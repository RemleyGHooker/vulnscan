#!/usr/bin/env python3
"""
Multi-turn vs fresh self-audit vs cross-model audit on the same synthetic vulnerable code.
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
import re
import sys
import time
from pathlib import Path
from typing import Any

from adversarial import TIERS, VULN_CLASSES, _normalize_vuln_type, intended_detected
from engine import scan_file
from llm_client import (
    DEFAULT_MODEL,
    LLMClientError,
    completion_text,
    get_client,
    parse_json_response,
)
from llm_groq import DEFAULT_GROQ_MODEL, analyze_chunk_groq, get_groq_client
from prompts import (
    ADV_SYNTH_SYSTEM,
    SELF_KNOWLEDGE_SCAN_FOLLOWUP,
    VULN_SCAN_SYSTEM,
    build_adversarial_generate_messages,
    build_scan_messages,
    format_numbered_code,
)
from reporter import normalize_finding
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from scanner import chunk_file_lines, language_from_path

PAPER_QUALITY_MIN_SAMPLES = 100


def _sanitize_id(raw: str, fallback: str) -> str:
    s = re.sub(r"[^\w.-]+", "_", raw.strip())[:48]
    return s or fallback


def _findings_from_dict(data: dict[str, Any]) -> list[dict[str, Any]]:
    f = data.get("findings")
    if not isinstance(f, list):
        return []
    out: list[dict[str, Any]] = []
    for item in f:
        if isinstance(item, dict):
            out.append(item)
    return out


def _normalize_findings(raw: list[dict[str, Any]], default_file: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for it in raw:
        n = normalize_finding(it, default_file)
        if n:
            out.append(n)
    return out


def scan_file_groq(
    groq_client: Any,
    path: Path,
    root: Path,
    *,
    model: str,
    max_lines: int,
) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    errors = 0
    rel = str(path.relative_to(root)).replace("\\", "/")
    lang = language_from_path(path)
    try:
        for chunk_text, _s, _e in chunk_file_lines(path, root, max_lines=max_lines):
            messages = build_scan_messages(rel, lang, chunk_text)
            user_content = messages[0]["content"]
            try:
                data = analyze_chunk_groq(
                    groq_client,
                    VULN_SCAN_SYSTEM,
                    user_content,
                    model=model,
                )
            except LLMClientError:
                errors += 1
                continue
            raw_list = data.get("findings")
            if not isinstance(raw_list, list):
                continue
            for item in raw_list:
                if not isinstance(item, dict):
                    continue
                norm = normalize_finding(item, rel)
                if norm:
                    findings.append(norm)
    except OSError:
        errors += 1
    return findings, errors


def _blind_spot_type(mt: bool, fs: bool, cm: bool) -> str:
    if mt and fs and cm:
        return "all_detected"
    if not mt and not fs and not cm:
        return "all_missed"
    if (not mt) and fs and cm:
        return "multi_turn_only_miss"
    if mt and (not fs) and cm:
        return "fresh_only_miss"
    if mt and fs and (not cm):
        return "cross_only_miss"
    return "mixed"


def _compute_summary(samples: list[dict[str, Any]], *, total_samples_requested: int) -> dict[str, Any]:
    gen_fail = sum(1 for s in samples if s.get("generation_error"))
    ok = [s for s in samples if not s.get("generation_error") and "multi_turn_detected" in s]
    n_ok = len(ok)
    mt_miss_fresh_catch = sum(
        1 for s in ok if (not s["multi_turn_detected"]) and s["fresh_self_detected"]
    )
    self_miss_cross_catch = sum(
        1
        for s in ok
        if (not (s["multi_turn_detected"] or s["fresh_self_detected"]))
        and s["cross_model_detected"]
    )
    fresh_miss_cross = sum(
        1 for s in ok if (not s["fresh_self_detected"]) and s["cross_model_detected"]
    )

    return {
        "samples_evaluated": n_ok,
        "generation_failures": gen_fail,
        "total_samples_requested": total_samples_requested,
        "multi_turn_miss_rate": round(mt_miss_fresh_catch / n_ok, 6) if n_ok else None,
        "self_vs_cross_gap": round(self_miss_cross_catch / n_ok, 6) if n_ok else None,
        "fresh_self_vs_cross_gap": round(fresh_miss_cross / n_ok, 6) if n_ok else None,
    }


def _atomic_write_manifest(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)


def run_multi_turn_audit(
    *,
    outdir: Path,
    samples: int,
    language: str,
    vulnerability_class: str | None,
    generator_model: str,
    scanner_model: str,
    max_lines: int,
    seed: int,
    verbose: bool,
) -> int:
    console = Console()
    rnd = random.Random(seed)
    outdir = outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    manifest_path = outdir / "multi_turn_manifest.json"

    research_question = (
        "Does a model audit code it just generated differently depending on conversational context, "
        "and does a different model catch what the generator misses?"
    )

    rows: list[dict[str, Any]] = []

    try:
        anthropic_client = get_client()
    except LLMClientError as e:
        console.print(f"[red]{e}[/red]")
        return 2

    try:
        groq_client = get_groq_client()
    except LLMClientError as e:
        console.print(f"[red]Cross-model audit needs Groq: {e}[/red]")
        return 2

    classes = [vulnerability_class] if vulnerability_class else list(VULN_CLASSES)
    class_cycle = itertools.cycle(classes)
    tier_cycle = itertools.cycle(list(TIERS))

    ext = ".py" if language.lower() == "python" else ".txt"

    tasks_n = samples
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("multi_turn_audit", total=tasks_n)
        for j in range(tasks_n):
            i = j
            vclass = next(class_cycle)
            tier = next(tier_cycle)
            _ = rnd  # reserved for future stratified sampling

            record: dict[str, Any] = {
                "sample_id": _sanitize_id(f"mta_{i}", f"mta_{i:04d}"),
                "intended_class": vclass,
                "generator_model": generator_model,
                "scanner_model": scanner_model,
            }

            gen_msgs = build_adversarial_generate_messages(language, vclass, tier)
            try:
                gen_raw = completion_text(
                    anthropic_client,
                    ADV_SYNTH_SYSTEM,
                    gen_msgs,
                    model=generator_model,
                    max_tokens=8192,
                )
                gen_data = parse_json_response(gen_raw)
            except (LLMClientError, json.JSONDecodeError, TypeError, KeyError) as e:
                record["generation_error"] = str(e)
                rows.append(record)
                _atomic_write_manifest(
                    manifest_path,
                    {
                        "version": 1,
                        "research_question": research_question,
                        "generator_model": generator_model,
                        "scanner_model": scanner_model,
                        "language": language,
                        "outdir": str(outdir),
                        "seed": seed,
                        "samples": rows,
                        "summary": _compute_summary(rows, total_samples_requested=tasks_n),
                    },
                )
                progress.advance(task_id)
                continue

            code = gen_data.get("code")
            if not isinstance(code, str) or not code.strip():
                record["generation_error"] = "missing code in generator JSON"
                rows.append(record)
                _atomic_write_manifest(
                    manifest_path,
                    {
                        "version": 1,
                        "research_question": research_question,
                        "generator_model": generator_model,
                        "scanner_model": scanner_model,
                        "language": language,
                        "outdir": str(outdir),
                        "seed": seed,
                        "samples": rows,
                        "summary": _compute_summary(rows, total_samples_requested=tasks_n),
                    },
                )
                progress.advance(task_id)
                continue

            intended = _normalize_vuln_type(str(gen_data.get("vulnerability_class", vclass)))
            record["intended_class"] = intended
            sid = record["sample_id"]
            path = outdir / f"{sid}{ext}"
            try:
                path.write_text(code, encoding="utf-8")
            except OSError as e:
                record["generation_error"] = f"write failed: {e}"
                rows.append(record)
                _atomic_write_manifest(
                    manifest_path,
                    {
                        "version": 1,
                        "research_question": research_question,
                        "generator_model": generator_model,
                        "scanner_model": scanner_model,
                        "language": language,
                        "outdir": str(outdir),
                        "seed": seed,
                        "samples": rows,
                        "summary": _compute_summary(rows, total_samples_requested=tasks_n),
                    },
                )
                progress.advance(task_id)
                continue

            mt = fs = cm = False
            mt_err: str | None = None
            fs_err: str | None = None
            cm_err: str | None = None

            numbered = format_numbered_code(code)
            follow = SELF_KNOWLEDGE_SCAN_FOLLOWUP.format(numbered_code=numbered)
            thread_messages = [
                gen_msgs[0],
                {"role": "assistant", "content": gen_raw},
                {"role": "user", "content": follow},
            ]
            try:
                scan_raw = completion_text(
                    anthropic_client,
                    VULN_SCAN_SYSTEM,
                    thread_messages,
                    model=generator_model,
                    max_tokens=4096,
                )
                thread_data = parse_json_response(scan_raw)
                thread_findings = _normalize_findings(
                    _findings_from_dict(thread_data), "synthetic.py"
                )
                mt = intended_detected(intended, thread_findings)
            except (LLMClientError, json.JSONDecodeError, TypeError) as e:
                mt_err = str(e)
                if verbose:
                    console.print(f"[yellow]multi-turn scan error sample {sid}: {e}[/yellow]")

            try:
                fresh_findings, _e = scan_file(
                    anthropic_client,
                    path,
                    outdir,
                    model=generator_model,
                    max_lines=max_lines,
                )
                fs = intended_detected(intended, fresh_findings)
            except Exception as e:
                fs_err = str(e)
                if verbose:
                    console.print(f"[yellow]fresh self scan error sample {sid}: {e}[/yellow]")

            try:
                cross_findings, _ce = scan_file_groq(
                    groq_client,
                    path,
                    outdir,
                    model=scanner_model,
                    max_lines=max_lines,
                )
                cm = intended_detected(intended, cross_findings)
            except Exception as e:
                cm_err = str(e)
                if verbose:
                    console.print(f"[yellow]cross-model scan error sample {sid}: {e}[/yellow]")

            record["multi_turn_detected"] = mt
            record["fresh_self_detected"] = fs
            record["cross_model_detected"] = cm
            record["blind_spot_type"] = _blind_spot_type(mt, fs, cm)
            if mt_err:
                record["multi_turn_error"] = mt_err
            if fs_err:
                record["fresh_self_error"] = fs_err
            if cm_err:
                record["cross_model_error"] = cm_err

            rows.append(record)
            _atomic_write_manifest(
                manifest_path,
                {
                    "version": 1,
                    "research_question": research_question,
                    "generator_model": generator_model,
                    "scanner_model": scanner_model,
                    "language": language,
                    "outdir": str(outdir),
                    "seed": seed,
                    "samples": rows,
                    "summary": _compute_summary(rows, total_samples_requested=tasks_n),
                },
            )
            if verbose:
                console.print(
                    f"[dim]{sid}[/dim] mt={mt} fresh={fs} cross={cm} [{record['blind_spot_type']}]"
                )
            progress.advance(task_id)

    summ = _compute_summary(rows, total_samples_requested=tasks_n)
    tbl = Table(title="Multi-turn audit summary", show_lines=True)
    tbl.add_column("Metric", style="cyan")
    tbl.add_column("Value", style="white")
    for k, v in summ.items():
        tbl.add_row(str(k), str(v))
    console.print(tbl)
    console.print(f"[dim]Wrote[/dim] {manifest_path.resolve()}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Multi-turn vs fresh vs cross-model audit experiment")
    ap.add_argument(
        "--samples",
        type=int,
        default=PAPER_QUALITY_MIN_SAMPLES,
        help=f"Number of samples (paper-quality default: {PAPER_QUALITY_MIN_SAMPLES})",
    )
    ap.add_argument("--language", default="python")
    ap.add_argument("--vulnerability-class", default=None)
    ap.add_argument("--generator-model", default=DEFAULT_MODEL)
    ap.add_argument("--scanner-model", default=DEFAULT_GROQ_MODEL, help="Cross-model auditor (Groq)")
    ap.add_argument("--max-lines", type=int, default=120)
    ap.add_argument("--outdir", type=Path, default=Path("multi_turn_audit_workspace"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    if args.samples < 50:
        Console().print(
            "[yellow]Warning:[/yellow] --samples < 50 is useful for debugging, "
            "but weak for paper-quality statistical claims."
        )

    return run_multi_turn_audit(
        outdir=args.outdir,
        samples=args.samples,
        language=args.language,
        vulnerability_class=args.vulnerability_class,
        generator_model=args.generator_model,
        scanner_model=args.scanner_model,
        max_lines=args.max_lines,
        seed=args.seed,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
