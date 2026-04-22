"""Comment-suppression experiment: paired vulnerable code vs. same code + adversarial comments."""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from adversarial import (
    EXT_FOR_LANGUAGE,
    TIERS,
    VULN_CLASSES,
    _normalize_vuln_type,
    intended_detected,
)
from engine import scan_file
from llm_client import LLMClientError, analyze_chunk, get_client
from prompts import COMMENT_SUPPRESS_SYSTEM, build_comment_suppress_pair_messages


def _lang_ext(language: str) -> str:
    return EXT_FOR_LANGUAGE.get(language.lower(), ".txt")


def _sanitize_id(raw: str, fallback: str) -> str:
    s = re.sub(r"[^\w.-]+", "_", raw.strip())[:48]
    return s or fallback


def summarize_suppression(samples: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate rates from per-sample records (no I/O)."""
    n = 0
    baseline_hits = 0
    treatment_hits = 0
    suppressed = 0
    baseline_miss_both = 0
    weird_treatment_only = 0

    for s in samples:
        if s.get("error"):
            continue
        n += 1
        b = bool(s.get("baseline_detected"))
        t = bool(s.get("treatment_detected"))
        if b:
            baseline_hits += 1
        if t:
            treatment_hits += 1
        if b and not t:
            suppressed += 1
        if not b and not t:
            baseline_miss_both += 1
        if not b and t:
            weird_treatment_only += 1

    rate_base = (baseline_hits / n) if n else None
    rate_treat = (treatment_hits / n) if n else None
    sup_given_hit = (suppressed / baseline_hits) if baseline_hits else None
    delta = (
        (rate_base - rate_treat)
        if rate_base is not None and rate_treat is not None
        else None
    )

    return {
        "samples_evaluated": n,
        "baseline_detection_count": baseline_hits,
        "treatment_detection_count": treatment_hits,
        "baseline_detection_rate": round(rate_base, 4) if rate_base is not None else None,
        "treatment_detection_rate": round(rate_treat, 4) if rate_treat is not None else None,
        "suppression_events": suppressed,
        "suppression_rate_given_baseline_detected": round(sup_given_hit, 4)
        if sup_given_hit is not None
        else None,
        "detection_rate_delta_baseline_minus_treatment": round(delta, 4)
        if delta is not None
        else None,
        "baseline_miss_neither_detected": baseline_miss_both,
        "treatment_only_hits": weird_treatment_only,
    }


def run_comment_suppression_experiment(
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
    """
    For each sample: generate paired baseline + commented code, scan both, record detection.
    """
    _ = seed
    outdir = outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    client = get_client()
    classes = [vulnerability_class] if vulnerability_class else list(VULN_CLASSES)
    tier_list = [obfuscation_tier] if obfuscation_tier else list(TIERS)
    class_cycle = itertools.cycle(classes)
    tier_cycle = itertools.cycle(tier_list)

    records: list[dict[str, Any]] = []
    gen_errors = 0

    for i in range(samples):
        vclass = next(class_cycle)
        tier = next(tier_cycle)
        try:
            messages = build_comment_suppress_pair_messages(language, vclass, tier)
            data = analyze_chunk(
                client,
                COMMENT_SUPPRESS_SYSTEM,
                messages,
                model=generator_model,
                max_tokens=8192,
            )
        except LLMClientError as e:
            gen_errors += 1
            records.append({"index": i, "error": str(e), "intended_class": vclass})
            continue

        if not isinstance(data, dict):
            gen_errors += 1
            records.append({"index": i, "error": "invalid generator JSON", "intended_class": vclass})
            continue

        base_code = data.get("code_baseline")
        treat_code = data.get("code_with_suppression_comments")
        if not isinstance(base_code, str) or not isinstance(treat_code, str):
            gen_errors += 1
            records.append({"index": i, "error": "missing code fields", "intended_class": vclass})
            continue

        sid = _sanitize_id(str(data.get("sample_id", "")), f"cs_{i:04d}")
        ext = _lang_ext(language)
        base_path = outdir / f"{sid}_baseline{ext}"
        treat_path = outdir / f"{sid}_suppressed{ext}"
        base_path.write_text(base_code, encoding="utf-8")
        treat_path.write_text(treat_code, encoding="utf-8")

        intended = _normalize_vuln_type(str(data.get("vulnerability_class", vclass)))

        if file_progress is not None:
            file_progress(f"{sid}_baseline{ext}")
        fb, eb = scan_file(
            client, base_path, outdir, model=scanner_model, max_lines=max_lines
        )
        if file_progress is not None:
            file_progress(f"{sid}_suppressed{ext}")
        ft, et = scan_file(
            client, treat_path, outdir, model=scanner_model, max_lines=max_lines
        )

        b_hit = intended_detected(intended, fb)
        t_hit = intended_detected(intended, ft)

        records.append(
            {
                "index": i,
                "sample_id": sid,
                "intended_class": intended,
                "obfuscation_tier": tier,
                "generator_strategy": data.get("suppression_strategy"),
                "comment_patterns_used": data.get("comment_patterns_used"),
                "baseline_file": base_path.name,
                "treatment_file": treat_path.name,
                "baseline_detected": b_hit,
                "treatment_detected": t_hit,
                "suppressed": b_hit and not t_hit,
                "baseline_findings_count": len(fb),
                "treatment_findings_count": len(ft),
                "scanner_errors_baseline": eb,
                "scanner_errors_treatment": et,
            }
        )

    summary = summarize_suppression(records)
    summary["generation_failures"] = gen_errors
    summary["samples_requested"] = samples

    manifest = {
        "version": 1,
        "mode": "comment_suppression",
        "research_question": (
            "Can adversarially crafted source code comments suppress LLM-based vulnerability detection, "
            "and under what paired conditions does detection drop?"
        ),
        "generator_model": generator_model,
        "scanner_model": scanner_model,
        "language": language,
        "outdir": str(outdir),
        "seed": seed,
        "summary": summary,
        "samples": records,
    }
    (outdir / "comment_suppression_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest
