"""Aggressive in-file directives aimed at manipulating the scanner (prompt injection via comments)."""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from adversarial import EXT_FOR_LANGUAGE, VULN_CLASSES, _normalize_vuln_type, intended_detected
from engine import scan_file
from llm_client import LLMClientError, completion_text, get_client, parse_json_response
from prompts import SCANNER_POISON_SYSTEM, build_scanner_poison_messages


def _sanitize_id(raw: str, fallback: str) -> str:
    s = re.sub(r"[^\w.-]+", "_", raw.strip())[:48]
    return s or fallback


def _lang_ext(language: str) -> str:
    return EXT_FOR_LANGUAGE.get(language.lower(), ".txt")


def run_scanner_poison_experiment(
    *,
    outdir: Path,
    samples: int,
    language: str,
    vulnerability_class: str | None,
    obfuscation_tier: str | None,
    generator_model: str,
    scanner_model: str,
    max_lines: int,
    seed: int,
    file_progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    _ = seed
    outdir = outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    client = get_client()
    classes = [vulnerability_class] if vulnerability_class else list(VULN_CLASSES)
    _ = obfuscation_tier
    class_cycle = itertools.cycle(classes)

    rows: list[dict[str, Any]] = []
    gen_err = 0
    suppressed = 0
    baseline_hits = 0

    for i in range(samples):
        vclass = next(class_cycle)
        try:
            raw = completion_text(
                client,
                SCANNER_POISON_SYSTEM,
                build_scanner_poison_messages(language, vclass),
                model=generator_model,
                max_tokens=8192,
            )
            data = parse_json_response(raw)
        except (LLMClientError, json.JSONDecodeError) as e:
            gen_err += 1
            rows.append({"index": i, "error": str(e)})
            continue

        base = data.get("code_baseline")
        poison = data.get("code_with_scanner_directive_comments")
        if not isinstance(base, str) or not isinstance(poison, str):
            gen_err += 1
            rows.append({"index": i, "error": "missing code fields"})
            continue

        intended = _normalize_vuln_type(str(data.get("vulnerability_class", vclass)))
        sid = _sanitize_id(f"sp_{i}", f"sp_{i:04d}")
        ext = _lang_ext(language)
        b_path = outdir / f"{sid}_baseline{ext}"
        p_path = outdir / f"{sid}_poison{ext}"
        b_path.write_text(base, encoding="utf-8")
        p_path.write_text(poison, encoding="utf-8")

        if file_progress:
            file_progress(b_path.name)
        fb, eb = scan_file(client, b_path, outdir, model=scanner_model, max_lines=max_lines)
        if file_progress:
            file_progress(p_path.name)
        fp, ep = scan_file(client, p_path, outdir, model=scanner_model, max_lines=max_lines)

        b_hit = intended_detected(intended, fb)
        p_hit = intended_detected(intended, fp)
        if b_hit:
            baseline_hits += 1
        if b_hit and not p_hit:
            suppressed += 1

        rows.append(
            {
                "index": i,
                "sample_id": sid,
                "intended_class": intended,
                "directive_summary": data.get("directive_summary"),
                "baseline_detected": b_hit,
                "poison_detected": p_hit,
                "scanner_suppressed": b_hit and not p_hit,
                "baseline_findings": len(fb),
                "poison_findings": len(fp),
            }
        )

    manifest = {
        "version": 1,
        "mode": "scanner_poison",
        "research_question": (
            "Can in-source comments that mimic or override scanner instructions suppress "
            "LLM vulnerability detection more aggressively than benign-looking rationales?"
        ),
        "generator_model": generator_model,
        "scanner_model": scanner_model,
        "language": language,
        "outdir": str(outdir),
        "seed": seed,
        "summary": {
            "samples_requested": samples,
            "generation_failures": gen_err,
            "baseline_detection_hits": baseline_hits,
            "suppression_after_baseline_hit": suppressed,
            "suppression_rate_given_baseline_hit": round(suppressed / baseline_hits, 4)
            if baseline_hits
            else None,
        },
        "samples": rows,
    }
    (outdir / "scanner_poison_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest
