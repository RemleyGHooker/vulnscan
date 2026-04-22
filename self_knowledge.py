"""Self-knowledge gap: same model generates vuln, then audits it in-thread vs fresh scan."""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from adversarial import TIERS, VULN_CLASSES, _normalize_vuln_type, intended_detected
from engine import scan_file
from llm_client import LLMClientError, completion_text, get_client, parse_json_response
from prompts import (
    SELF_KNOWLEDGE_GEN_SYSTEM,
    SELF_KNOWLEDGE_SCAN_FOLLOWUP,
    VULN_SCAN_SYSTEM,
    build_self_knowledge_gen_messages,
    format_numbered_code,
)
from reporter import normalize_finding


def _sanitize_id(raw: str, fallback: str) -> str:
    s = re.sub(r"[^\w.-]+", "_", raw.strip())[:48]
    return s or fallback


def _findings_from_dict(data: dict[str, Any]) -> list[dict[str, Any]]:
    f = data.get("findings")
    if not isinstance(f, list):
        return []
    out = []
    for item in f:
        if isinstance(item, dict):
            out.append(item)
    return out


def run_self_knowledge_experiment(
    *,
    outdir: Path,
    samples: int,
    language: str,
    vulnerability_class: str | None,
    obfuscation_tier: str | None,
    model: str,
    max_lines: int,
    seed: int,
    file_progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    _ = seed
    outdir = outdir.resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    client = get_client()

    classes = [vulnerability_class] if vulnerability_class else list(VULN_CLASSES)
    tiers = [obfuscation_tier] if obfuscation_tier else list(TIERS)
    class_cycle = itertools.cycle(classes)
    tier_cycle = itertools.cycle(tiers)

    rows: list[dict[str, Any]] = []
    gen_err = 0
    thread_scan_err = 0
    blindspot = 0  # fresh hit, thread miss
    both_hit = 0
    thread_only = 0
    neither = 0
    completed = 0

    for i in range(samples):
        vclass = next(class_cycle)
        tier = next(tier_cycle)
        gen_msgs = build_self_knowledge_gen_messages(language, vclass, tier)
        try:
            gen_raw = completion_text(
                client,
                SELF_KNOWLEDGE_GEN_SYSTEM,
                gen_msgs,
                model=model,
                max_tokens=4096,
            )
            gen_data = parse_json_response(gen_raw)
        except (LLMClientError, json.JSONDecodeError, KeyError, TypeError) as e:
            gen_err += 1
            rows.append({"index": i, "error": str(e), "intended_class": vclass})
            continue

        code = gen_data.get("code")
        if not isinstance(code, str) or not code.strip():
            gen_err += 1
            rows.append({"index": i, "error": "missing code", "intended_class": vclass})
            continue

        intended = _normalize_vuln_type(str(gen_data.get("vulnerability_class", vclass)))
        numbered = format_numbered_code(code)
        sid = _sanitize_id(f"sk_{i}", f"sk_{i:04d}")
        ext = ".py" if language.lower() == "python" else ".txt"
        path = outdir / f"{sid}{ext}"
        path.write_text(code, encoding="utf-8")

        follow = SELF_KNOWLEDGE_SCAN_FOLLOWUP.format(numbered_code=numbered)
        thread_messages = [
            gen_msgs[0],
            {"role": "assistant", "content": gen_raw},
            {"role": "user", "content": follow},
        ]
        try:
            scan_raw = completion_text(
                client,
                VULN_SCAN_SYSTEM,
                thread_messages,
                model=model,
                max_tokens=4096,
            )
            thread_data = parse_json_response(scan_raw)
        except (LLMClientError, json.JSONDecodeError) as e:
            thread_scan_err += 1
            rows.append({"index": i, "error": f"thread_scan:{e}", "intended_class": intended})
            continue

        thread_findings = _findings_from_dict(thread_data)
        thread_norm = []
        for it in thread_findings:
            n = normalize_finding(it, "synthetic.py")
            if n:
                thread_norm.append(n)

        if file_progress:
            file_progress(path.name)
        fresh_findings, _ = scan_file(client, path, outdir, model=model, max_lines=max_lines)

        t_hit = intended_detected(intended, thread_norm)
        f_hit = intended_detected(intended, fresh_findings)

        if f_hit and not t_hit:
            blindspot += 1
        elif f_hit and t_hit:
            both_hit += 1
        elif t_hit and not f_hit:
            thread_only += 1
        else:
            neither += 1

        rows.append(
            {
                "index": i,
                "sample_id": sid,
                "intended_class": intended,
                "multi_turn_detected": t_hit,
                "fresh_scan_detected": f_hit,
                "self_knowledge_blindspot": f_hit and not t_hit,
                "thread_findings_count": len(thread_norm),
                "fresh_findings_count": len(fresh_findings),
            }
        )
        completed += 1

    summary = {
        "samples_requested": samples,
        "generation_failures": gen_err,
        "thread_scan_failures": thread_scan_err,
        "evaluated": completed,
        "self_knowledge_blindspot_events": blindspot,
        "both_detected": both_hit,
        "thread_only_detected": thread_only,
        "neither_detected": neither,
        "blindspot_rate_given_fresh_hit": round(blindspot / (blindspot + both_hit), 4)
        if (blindspot + both_hit)
        else None,
    }

    manifest = {
        "version": 1,
        "mode": "self_knowledge",
        "research_question": (
            "When the same model first authors synthetic vulnerable code and then audits it in a "
            "multi-turn conversation, does it miss findings that a fresh isolated scan catches?"
        ),
        "model": model,
        "language": language,
        "outdir": str(outdir),
        "seed": seed,
        "summary": summary,
        "samples": rows,
    }
    (outdir / "self_knowledge_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return manifest
