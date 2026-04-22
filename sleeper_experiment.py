"""Sleeper / shallow-prefix: vuln after N lines; repeated full-file scan stability."""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from adversarial import VULN_CLASSES, _normalize_vuln_type, intended_detected
from engine import scan_file
from llm_client import LLMClientError, completion_text, get_client, parse_json_response
from prompts import SLEEPER_SYSTEM, build_sleeper_messages


def _sanitize_id(raw: str, fallback: str) -> str:
    s = re.sub(r"[^\w.-]+", "_", raw.strip())[:48]
    return s or fallback


def _variance(counts: list[int]) -> float | None:
    if len(counts) < 2:
        return None
    m = sum(counts) / len(counts)
    v = sum((x - m) ** 2 for x in counts) / (len(counts) - 1)
    return round(v, 4)


def run_sleeper_experiment(
    *,
    outdir: Path,
    samples: int,
    language: str,
    vulnerability_class: str | None,
    obfuscation_tier: str | None,
    surface_lines: int,
    repeat_scans: int,
    model: str,
    max_lines: int,
    seed: int,
    file_progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    _ = seed
    _ = obfuscation_tier  # reserved for generator hint expansion
    outdir = outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    client = get_client()
    classes = [vulnerability_class] if vulnerability_class else list(VULN_CLASSES)
    cycle = itertools.cycle(classes)

    rows: list[dict[str, Any]] = []
    gen_err = 0
    prefix_miss_full_hit = 0
    stability_variances: list[float] = []

    for i in range(samples):
        vclass = next(cycle)
        try:
            raw = completion_text(
                client,
                SLEEPER_SYSTEM,
                build_sleeper_messages(language, vclass, surface_lines),
                model=model,
                max_tokens=8192,
            )
            data = parse_json_response(raw)
        except (LLMClientError, json.JSONDecodeError) as e:
            gen_err += 1
            rows.append({"index": i, "error": str(e)})
            continue

        full = data.get("code_full")
        prefix = data.get("code_prefix")
        if not isinstance(full, str) or not isinstance(prefix, str):
            gen_err += 1
            rows.append({"index": i, "error": "missing code_full or code_prefix"})
            continue

        intended = _normalize_vuln_type(str(data.get("vulnerability_class", vclass)))
        sid = _sanitize_id(f"sl_{i}", f"sl_{i:04d}")
        ext = ".py" if language.lower() == "python" else ".txt"
        full_path = outdir / f"{sid}_full{ext}"
        pre_path = outdir / f"{sid}_prefix{ext}"
        full_path.write_text(full, encoding="utf-8")
        pre_path.write_text(prefix, encoding="utf-8")

        if file_progress:
            file_progress(pre_path.name)
        fpre, epre = scan_file(client, pre_path, outdir, model=model, max_lines=max_lines)
        if file_progress:
            file_progress(full_path.name)
        ffull, efull = scan_file(client, full_path, outdir, model=model, max_lines=max_lines)

        pre_hit = intended_detected(intended, fpre)
        full_hit = intended_detected(intended, ffull)
        if full_hit and not pre_hit:
            prefix_miss_full_hit += 1

        repeat_counts: list[int] = []
        for _r in range(max(1, repeat_scans)):
            fr, _ = scan_file(client, full_path, outdir, model=model, max_lines=max_lines)
            repeat_counts.append(len(fr))
        var = _variance(repeat_counts)
        if var is not None:
            stability_variances.append(var)

        rows.append(
            {
                "index": i,
                "sample_id": sid,
                "intended_class": intended,
                "trigger_explanation": data.get("trigger_explanation"),
                "prefix_detected": pre_hit,
                "full_detected": full_hit,
                "hidden_branch_effect": full_hit and not pre_hit,
                "prefix_findings_count": len(fpre),
                "full_findings_count": len(ffull),
                "repeat_scan_finding_counts": repeat_counts,
                "repeat_scan_count_variance": var,
            }
        )

    manifest = {
        "version": 1,
        "mode": "sleeper",
        "research_question": (
            "Do LLM scanners miss vulnerabilities that only appear after the first N lines or under rare "
            "conditions, and how stable are repeated scans of the same file?"
        ),
        "model": model,
        "language": language,
        "surface_lines": surface_lines,
        "repeat_scans_per_sample": repeat_scans,
        "outdir": str(outdir),
        "seed": seed,
        "summary": {
            "samples_requested": samples,
            "generation_failures": gen_err,
            "hidden_branch_events_full_yes_prefix_no": prefix_miss_full_hit,
            "mean_repeat_count_variance": round(sum(stability_variances) / len(stability_variances), 4)
            if stability_variances
            else None,
        },
        "samples": rows,
    }
    (outdir / "sleeper_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
