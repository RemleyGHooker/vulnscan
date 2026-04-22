#!/usr/bin/env python3
"""
Context isolation: full-file vs isolated-function vs summarized-context scanning.
"""

from __future__ import annotations

import argparse
import ast
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
from llm_client import DEFAULT_MODEL, LLMClientError, analyze_chunk, get_client
from prompts import ADV_SYNTH_SYSTEM, build_adversarial_generate_messages
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

PAPER_QUALITY_MIN_SAMPLES = 100
LLM_SUMMARY_SYSTEM = "You summarize source-code context for security analysis. Output JSON only."
LLM_SECURITY_SUMMARY_USER = """Summarize the following surrounding code for security analysis in under 100 words.
Include only facts visible in the code about: memory/buffer sizes, allocation/free behavior, pointer/index arithmetic,
input validation, global/shared state, and inter-function data flow. Do not infer protections that are not explicit.

Language: {language}
Code:
```{language}
{code}
```

Return ONLY JSON:
{{
  "summary": "string under 100 words"
}}
"""


def _sanitize_id(raw: str, fallback: str) -> str:
    s = re.sub(r"[^\w.-]+", "_", raw.strip())[:48]
    return s or fallback


def _risk_score(source: str, intended: str) -> int:
    low = source.lower()
    want = _normalize_vuln_type(intended)
    score = 0
    if want == "sql_injection":
        for k in ("execute(", "cursor", "select ", "raw", "query", "sql"):
            if k in low:
                score += 2
    elif want == "command_injection":
        for k in ("os.system", "subprocess", "popen", "shell=true", "eval(", "exec("):
            if k in low:
                score += 2
    elif want == "buffer_overflow":
        for k in ("strcpy", "strcat", "gets(", "memcpy", "sprintf"):
            if k in low:
                score += 2
    elif want == "path_traversal":
        for k in ("open(", "..", "path", "join"):
            if k in low:
                score += 1
    elif want == "hardcoded_secret":
        for k in ("api_key", "password", "secret", "token"):
            if k in low:
                score += 2
    elif want == "insecure_deserialization":
        for k in ("pickle", "yaml.load", "marshal", "loads("):
            if k in low:
                score += 2
    elif want == "prompt_injection":
        for k in ("system", "user_message", "prompt", "llm", "chat"):
            if k in low:
                score += 1
    elif want == "memory_leak":
        for k in ("malloc", "free", "open(", "close"):
            if k in low:
                score += 1
    else:
        score = len(low) // 80
    return score


def _pick_vulnerable_function(
    code: str, intended: str
) -> tuple[ast.FunctionDef | None, str | None]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None, None
    funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    if not funcs:
        return None, None
    best: ast.FunctionDef | None = None
    best_score = -1
    for fn in funcs:
        seg = ast.get_source_segment(code, fn)
        if not seg:
            continue
        sc = _risk_score(seg, intended)
        if sc > best_score:
            best_score = sc
            best = fn
    if best is None:
        return funcs[0], ast.get_source_segment(code, funcs[0])
    seg2 = ast.get_source_segment(code, best)
    return best, seg2 or None


def _template_summarize_surrounding(code: str, vuln_fn: ast.FunctionDef) -> str:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "Surrounding code could not be parsed; assume neutral helpers."
    names = [
        n.name
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n is not vuln_fn
    ]
    if not names:
        return "No other top-level functions in this snippet."
    return (
        f"Other top-level functions in this module ({', '.join(names)}) are benign helpers or glue code "
        "without the primary vulnerability pattern."
    )


def llm_summarize(client: Any, code: str, language: str, model: str) -> str:
    user = LLM_SECURITY_SUMMARY_USER.format(language=language, code=code)
    data = analyze_chunk(
        client,
        LLM_SUMMARY_SYSTEM,
        [{"role": "user", "content": user}],
        model=model,
        max_tokens=400,
    )
    summary = data.get("summary") if isinstance(data, dict) else None
    if not isinstance(summary, str) or not summary.strip():
        raise LLMClientError("LLM summarizer returned missing/empty summary")
    return summary.strip()


def _context_effect(full: bool, iso: bool, summ: bool) -> str:
    if full and iso and summ:
        return "all_detected"
    if not full and not iso and not summ:
        return "all_missed"
    if full and not iso and not summ:
        return "full_only"
    if not full and iso and not summ:
        return "isolated_only"
    if not full and not iso and summ:
        return "summarized_only"
    return "mixed"


def _compute_summary(samples: list[dict[str, Any]], *, total_samples_requested: int) -> dict[str, Any]:
    ok = [
        s
        for s in samples
        if not s.get("generation_error")
        and isinstance(s.get("full_file_detected"), bool)
        and isinstance(s.get("isolated_detected"), bool)
        and isinstance(s.get("summarized_context_detected"), bool)
    ]
    n = len(ok)
    if n == 0:
        return {
            "full_file_detection_rate": None,
            "isolated_detection_rate": None,
            "summarized_context_detection_rate": None,
            "context_helps_rate": None,
            "context_hurts_rate": None,
            "summarized_recovery_rate": None,
            "samples_evaluated": 0,
            "generation_failures": sum(1 for s in samples if s.get("generation_error")),
            "total_samples_requested": total_samples_requested,
        }

    def rate(key: str) -> float:
        return sum(1 for s in ok if s[key]) / n

    full_r = rate("full_file_detected")
    iso_r = rate("isolated_detected")
    sum_r = rate("summarized_context_detected")
    template_ok = [
        s for s in ok if isinstance(s.get("template_summarized_detected"), bool)
    ]
    template_r = (
        sum(1 for s in template_ok if s["template_summarized_detected"]) / len(template_ok)
        if template_ok
        else None
    )
    helps = sum(1 for s in ok if s["full_file_detected"] and not s["isolated_detected"]) / n
    hurts = sum(1 for s in ok if not s["full_file_detected"] and s["isolated_detected"]) / n
    recov = sum(
        1
        for s in ok
        if (not s["isolated_detected"]) and s["summarized_context_detected"]
    ) / n

    return {
        "full_file_detection_rate": round(full_r, 6),
        "isolated_detection_rate": round(iso_r, 6),
        "summarized_context_detection_rate": round(sum_r, 6),
        "template_summarized_detection_rate": round(template_r, 6) if template_r is not None else None,
        "context_helps_rate": round(helps, 6),
        "context_hurts_rate": round(hurts, 6),
        "summarized_recovery_rate": round(recov, 6),
        "samples_evaluated": n,
        "generation_failures": sum(1 for s in samples if s.get("generation_error")),
        "total_samples_requested": total_samples_requested,
    }


def _atomic_write(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    tmp.replace(path)


def run_context_isolation(
    *,
    outdir: Path,
    samples: int,
    language: str,
    vulnerability_class: str | None,
    model: str,
    max_lines: int,
    seed: int,
    verbose: bool,
    delay: float,
    dry_run: bool,
) -> int:
    console = Console()
    rnd = random.Random(seed)
    outdir = outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    manifest_path = outdir / "context_isolation_manifest.json"
    research_question = (
        "Does the amount of surrounding code context sent to an LLM scanner change "
        "what vulnerabilities it detects?"
    )

    rows: list[dict[str, Any]] = []
    try:
        client = get_client()
    except LLMClientError as e:
        console.print(f"[red]{e}[/red]")
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
        task_id = progress.add_task("context_isolation", total=tasks_n)
        for i in range(tasks_n):
            _ = rnd
            vclass = next(class_cycle)
            tier = next(tier_cycle)
            sid = _sanitize_id(f"ctx_{i}", f"ctx_{i:04d}")
            record: dict[str, Any] = {
                "sample_id": sid,
                "intended_class": vclass,
            }

            base_content = build_adversarial_generate_messages(language, vclass, tier)[0]["content"]
            extra = (
                "\n\nLayout requirement: define at least three top-level functions in one file. "
                "Put the primary vulnerability in exactly one function; the other two must be benign "
                "helpers, stubs, or configuration code without introducing unrelated critical flaws."
            )
            gen_msgs = [{"role": "user", "content": base_content + extra}]

            try:
                gen_data = analyze_chunk(
                    client,
                    ADV_SYNTH_SYSTEM,
                    gen_msgs,
                    model=model,
                    max_tokens=8192,
                )
            except (LLMClientError, json.JSONDecodeError, TypeError) as e:
                record["generation_error"] = str(e)
                rows.append(record)
                _atomic_write(
                    manifest_path,
                    {
                        "version": 1,
                        "research_question": research_question,
                        "model": model,
                        "language": language,
                        "outdir": str(outdir),
                        "seed": seed,
                        "dry_run": dry_run,
                        "samples": rows,
                        "summary": _compute_summary(rows, total_samples_requested=tasks_n),
                    },
                )
                progress.advance(task_id)
                time.sleep(delay)
                continue

            code = gen_data.get("code") if isinstance(gen_data, dict) else None
            if not isinstance(code, str) or not code.strip():
                record["generation_error"] = "missing code in generator JSON"
                rows.append(record)
                _atomic_write(
                    manifest_path,
                    {
                        "version": 1,
                        "research_question": research_question,
                        "model": model,
                        "language": language,
                        "outdir": str(outdir),
                        "seed": seed,
                        "dry_run": dry_run,
                        "samples": rows,
                        "summary": _compute_summary(rows, total_samples_requested=tasks_n),
                    },
                )
                progress.advance(task_id)
                time.sleep(delay)
                continue

            intended = _normalize_vuln_type(str(gen_data.get("vulnerability_class", vclass)))
            record["intended_class"] = intended

            full_path = outdir / f"{sid}_full{ext}"
            iso_path = outdir / f"{sid}_isolated{ext}"
            sum_path = outdir / f"{sid}_summarized{ext}"

            vuln_fn: ast.FunctionDef | None = None
            isolated_src: str | None = None
            if language.lower() == "python":
                vuln_fn, isolated_src = _pick_vulnerable_function(code, intended)
            if not isolated_src:
                isolated_src = code
                record["isolation_note"] = (
                    "Used full file as isolated chunk (non-Python or parse failed / single blob)."
                )

            summary_sentence = (
                _template_summarize_surrounding(code, vuln_fn)
                if vuln_fn and language.lower() == "python"
                else "Context: full module omitted; scanning isolated snippet only."
            )
            llm_summary = summary_sentence
            if language.lower() == "python":
                try:
                    llm_summary = llm_summarize(client, code, language, model)
                    time.sleep(delay)
                except (LLMClientError, json.JSONDecodeError, TypeError) as e:
                    record["llm_summary_error"] = str(e)
                    llm_summary = summary_sentence
            template_summarized_src = f"# {summary_sentence}\n\n{isolated_src}"
            summarized_src = f"# {llm_summary}\n\n{isolated_src}"

            try:
                full_path.write_text(code, encoding="utf-8")
                iso_path.write_text(isolated_src, encoding="utf-8")
                sum_path.write_text(summarized_src, encoding="utf-8")
                (outdir / f"{sid}_template_summarized{ext}").write_text(
                    template_summarized_src, encoding="utf-8"
                )
            except OSError as e:
                record["generation_error"] = f"write failed: {e}"
                rows.append(record)
                _atomic_write(
                    manifest_path,
                    {
                        "version": 1,
                        "research_question": research_question,
                        "model": model,
                        "language": language,
                        "outdir": str(outdir),
                        "seed": seed,
                        "dry_run": dry_run,
                        "samples": rows,
                        "summary": _compute_summary(rows, total_samples_requested=tasks_n),
                    },
                )
                progress.advance(task_id)
                time.sleep(delay)
                continue

            if dry_run:
                record["full_file_detected"] = None
                record["isolated_detected"] = None
                record["summarized_context_detected"] = None
                record["template_summarized_detected"] = None
                record["context_effect"] = None
                record["scan_skipped"] = True
                record["template_summary"] = summary_sentence
                record["llm_summary"] = llm_summary
                record["files"] = {
                    "full": full_path.name,
                    "isolated": iso_path.name,
                    "summarized": sum_path.name,
                    "template_summarized": f"{sid}_template_summarized{ext}",
                }
                rows.append(record)
                _atomic_write(
                    manifest_path,
                    {
                        "version": 1,
                        "research_question": research_question,
                        "model": model,
                        "language": language,
                        "outdir": str(outdir),
                        "seed": seed,
                        "dry_run": dry_run,
                        "samples": rows,
                        "summary": _compute_summary(rows, total_samples_requested=tasks_n),
                    },
                )
                if verbose:
                    console.print(f"[dim]{sid}[/dim] dry-run files written")
                progress.advance(task_id)
                time.sleep(delay)
                continue

            full_d = iso_d = sum_d = template_d = False
            try:
                ff, _ = scan_file(client, full_path, outdir, model=model, max_lines=max_lines)
                time.sleep(delay)
                full_d = intended_detected(intended, ff)
            except Exception as e:
                record["full_file_error"] = str(e)
                if verbose:
                    console.print(f"[yellow]full scan {sid}: {e}[/yellow]")

            try:
                fi, _ = scan_file(client, iso_path, outdir, model=model, max_lines=max_lines)
                time.sleep(delay)
                iso_d = intended_detected(intended, fi)
            except Exception as e:
                record["isolated_error"] = str(e)
                if verbose:
                    console.print(f"[yellow]isolated scan {sid}: {e}[/yellow]")

            try:
                fs, _ = scan_file(client, sum_path, outdir, model=model, max_lines=max_lines)
                time.sleep(delay)
                sum_d = intended_detected(intended, fs)
            except Exception as e:
                record["summarized_error"] = str(e)
                if verbose:
                    console.print(f"[yellow]summarized scan {sid}: {e}[/yellow]")

            template_sum_path = outdir / f"{sid}_template_summarized{ext}"
            try:
                ft, _ = scan_file(
                    client,
                    template_sum_path,
                    outdir,
                    model=model,
                    max_lines=max_lines,
                )
                time.sleep(delay)
                template_d = intended_detected(intended, ft)
            except Exception as e:
                record["template_summarized_error"] = str(e)
                if verbose:
                    console.print(f"[yellow]template summarized scan {sid}: {e}[/yellow]")

            record["full_file_detected"] = full_d
            record["isolated_detected"] = iso_d
            record["summarized_context_detected"] = sum_d
            record["template_summarized_detected"] = template_d
            record["context_effect"] = _context_effect(full_d, iso_d, sum_d)
            record["template_summary"] = summary_sentence
            record["llm_summary"] = llm_summary
            record["files"] = {
                "full": full_path.name,
                "isolated": iso_path.name,
                "summarized": sum_path.name,
                "template_summarized": template_sum_path.name,
            }

            rows.append(record)
            _atomic_write(
                manifest_path,
                {
                    "version": 1,
                    "research_question": research_question,
                    "model": model,
                    "language": language,
                    "outdir": str(outdir),
                    "seed": seed,
                    "dry_run": dry_run,
                    "samples": rows,
                    "summary": _compute_summary(rows, total_samples_requested=tasks_n),
                },
            )
            if verbose:
                console.print(
                    f"[dim]{sid}[/dim] full={full_d} iso={iso_d} sum={sum_d} [{record['context_effect']}]"
                )
            progress.advance(task_id)
            time.sleep(delay)

    summ = _compute_summary(rows, total_samples_requested=tasks_n)
    tbl = Table(title="Context isolation summary", show_lines=True)
    tbl.add_column("Metric", style="cyan")
    tbl.add_column("Value", style="white")
    for k, v in summ.items():
        tbl.add_row(str(k), str(v))
    console.print(tbl)
    console.print(f"[dim]Wrote[/dim] {manifest_path.resolve()}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Context isolation scanning experiment")
    ap.add_argument(
        "--samples",
        type=int,
        default=PAPER_QUALITY_MIN_SAMPLES,
        help=f"Number of samples (paper-quality default: {PAPER_QUALITY_MIN_SAMPLES})",
    )
    ap.add_argument("--language", default="python")
    ap.add_argument("--vulnerability-class", default=None)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--max-lines", type=int, default=120)
    ap.add_argument("--outdir", type=Path, default=Path("context_isolation_workspace"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--dry-run", action="store_true", help="Generate files only; skip scanning")
    args = ap.parse_args()
    if args.samples < 50:
        Console().print(
            "[yellow]Warning:[/yellow] --samples < 50 is useful for debugging, "
            "but weak for paper-quality statistical claims."
        )

    return run_context_isolation(
        outdir=args.outdir,
        samples=args.samples,
        language=args.language,
        vulnerability_class=args.vulnerability_class,
        model=args.model,
        max_lines=args.max_lines,
        seed=args.seed,
        verbose=args.verbose,
        delay=args.delay,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
