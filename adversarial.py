"""Generate synthetic vulnerable code and evaluate the scanner (ground-truth vs findings)."""

from __future__ import annotations

import json
import itertools
import re
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from engine import scan_file
from llm_client import LLMClientError, analyze_chunk, get_client
from prompts import ADV_SYNTH_SYSTEM, build_adversarial_generate_messages

VULN_CLASSES = (
    "buffer_overflow",
    "sql_injection",
    "command_injection",
    "path_traversal",
    "memory_leak",
    "hardcoded_secret",
    "insecure_deserialization",
    "prompt_injection",
    "other",
)
TIERS = ("obvious", "subtle", "disguised")

EXT_FOR_LANGUAGE = {
    "python": ".py",
    "cpp": ".cpp",
    "c": ".c",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "rust": ".rs",
    "java": ".java",
}


def _lang_ext(language: str) -> str:
    return EXT_FOR_LANGUAGE.get(language.lower(), ".txt")


def _normalize_vuln_type(t: str) -> str:
    t = t.lower().strip().replace("-", "_").replace(" ", "_")
    aliases = {
        "sqli": "sql_injection",
        "sql_injection": "sql_injection",
        "command_injection": "command_injection",
        "cmd_injection": "command_injection",
        "rce": "command_injection",
        "path_traversal": "path_traversal",
        "directory_traversal": "path_traversal",
        "deserialization": "insecure_deserialization",
        "xxe": "other",
    }
    return aliases.get(t, t)


def intended_detected(intended: str, findings: list[dict[str, Any]]) -> bool:
    want = _normalize_vuln_type(intended)
    for f in findings:
        got = _normalize_vuln_type(str(f.get("vulnerability_type", "other")))
        if got == want:
            return True
        if want == "sql_injection" and got == "other":
            desc = (f.get("description") or "").lower()
            if "sql" in desc and "inject" in desc:
                return True
        if want == "command_injection" and got == "other":
            desc = (f.get("description") or "").lower()
            if "command" in desc and "inject" in desc:
                return True
    return False


def _extra_findings(intended: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    want = _normalize_vuln_type(intended)
    out: list[dict[str, Any]] = []
    for f in findings:
        got = _normalize_vuln_type(str(f.get("vulnerability_type", "other")))
        if got != want:
            out.append(f)
    return out


def _sanitize_sample_id(raw: str, fallback: str) -> str:
    s = re.sub(r"[^\w.-]+", "_", raw.strip())[:64]
    return s or fallback


def generate_one_sample(
    client,
    *,
    language: str,
    vulnerability_class: str,
    obfuscation_tier: str,
    generator_model: str,
) -> dict[str, Any]:
    messages = build_adversarial_generate_messages(
        language, vulnerability_class, obfuscation_tier
    )
    data = analyze_chunk(
        client,
        ADV_SYNTH_SYSTEM,
        messages,
        model=generator_model,
        max_tokens=8192,
    )
    if not isinstance(data, dict):
        raise LLMClientError("Generator returned non-object JSON")
    code = data.get("code")
    if not isinstance(code, str) or not code.strip():
        raise LLMClientError("Generator JSON missing non-empty 'code' string")
    return data


def _tier_detection_rates(sample_records: list[dict[str, Any]]) -> dict[str, Any]:
    tier_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0})
    for s in sample_records:
        if "error" in s:
            continue
        t = str(s.get("obfuscation_tier", "unknown"))
        if s.get("detected_intended"):
            tier_stats[t]["tp"] += 1
        else:
            tier_stats[t]["fn"] += 1
    out: dict[str, Any] = {}
    for t, st in sorted(tier_stats.items()):
        tot = st["tp"] + st["fn"]
        out[t] = {
            "true_positives": st["tp"],
            "false_negatives": st["fn"],
            "detection_rate": round(st["tp"] / tot, 4) if tot else None,
        }
    return out


def run_adversarial_eval(
    *,
    outdir: Path,
    samples: int,
    per_tier: int | None,
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
    Generate synthetic files under outdir, scan each, return report dict.

    If ``per_tier`` is set, generates that many samples **per** obfuscation tier
    (tiers = single ``obfuscation_tier`` if set, else all of ``TIERS``). The
    ``samples`` argument is ignored when ``per_tier`` is set.
    """
    _ = seed  # reserved for future stratified sampling / reproducibility hooks
    outdir = outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    client = get_client()

    classes = [vulnerability_class] if vulnerability_class else list(VULN_CLASSES)
    tier_list = [obfuscation_tier] if obfuscation_tier else list(TIERS)

    cycle_classes = itertools.cycle(classes)

    sample_records: list[dict[str, Any]] = []
    tp = fn = 0
    gen_errors = 0
    i = 0

    if per_tier is not None:
        worklist = []
        for tier in tier_list:
            for _ in range(per_tier):
                worklist.append((next(cycle_classes), tier))
    else:
        worklist = []
        cycle_tiers = itertools.cycle(tier_list)
        for _ in range(samples):
            worklist.append((next(cycle_classes), next(cycle_tiers)))
    total_gens = len(worklist)

    for vclass, tier in worklist:
        try:
            gen = generate_one_sample(
                client,
                language=language,
                vulnerability_class=vclass,
                obfuscation_tier=tier,
                generator_model=generator_model,
            )
        except LLMClientError as e:
            gen_errors += 1
            sample_records.append(
                {
                    "index": i,
                    "error": str(e),
                    "intended_class": vclass,
                    "obfuscation_tier": tier,
                }
            )
            i += 1
            continue

        sid = _sanitize_sample_id(str(gen.get("sample_id", "")), f"adv_{i:04d}")
        ext = _lang_ext(language)
        rel_name = f"{sid}{ext}"
        file_path = outdir / rel_name
        code = str(gen.get("code", ""))
        file_path.write_text(code, encoding="utf-8")

        intended = _normalize_vuln_type(str(gen.get("vulnerability_class", vclass)))
        eff_tier = str(gen.get("obfuscation_tier", tier))

        if file_progress is not None:
            file_progress(rel_name)

        findings, scan_err = scan_file(
            client,
            file_path,
            outdir,
            model=scanner_model,
            max_lines=max_lines,
        )
        hit = intended_detected(intended, findings)
        if hit:
            tp += 1
        else:
            fn += 1

        extras = _extra_findings(intended, findings)
        sample_records.append(
            {
                "index": i,
                "sample_id": sid,
                "file_path": rel_name,
                "intended_class": intended,
                "obfuscation_tier": eff_tier,
                "language": language,
                "generator_rationale": gen.get("rationale"),
                "detected_intended": hit,
                "scanner_errors": scan_err,
                "findings_count": len(findings),
                "extra_findings": extras,
                "findings": findings,
            }
        )
        i += 1

    n_ok = tp + fn
    recall = (tp / n_ok) if n_ok else 0.0
    by_tier = _tier_detection_rates(sample_records)

    manifest = {
        "version": 1,
        "mode": "adversarial_eval",
        "generator_model": generator_model,
        "scanner_model": scanner_model,
        "language": language,
        "outdir": str(outdir),
        "seed": seed,
        "per_tier": per_tier,
        "summary": {
            "samples_requested": total_gens,
            "per_tier_mode": per_tier is not None,
            "generation_failures": gen_errors,
            "evaluated": n_ok,
            "true_positives": tp,
            "false_negatives": fn,
            "recall_on_intended_class": round(recall, 4),
            "detection_rate_by_tier": by_tier,
        },
        "samples": sample_records,
    }
    (outdir / "adversarial_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest
