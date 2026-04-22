"""Cross-language transplant: C snippet + Python port preserving flaw; scan both."""

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
from prompts import TRANSPLANT_SYSTEM, build_transplant_messages


def _sanitize_id(raw: str, fallback: str) -> str:
    s = re.sub(r"[^\w.-]+", "_", raw.strip())[:48]
    return s or fallback


def run_transplant_experiment(
    *,
    outdir: Path,
    samples: int,
    vulnerability_class: str | None,
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
    cycle = itertools.cycle(classes)

    rows: list[dict[str, Any]] = []
    gen_err = 0
    both = c_only = py_only = neither = 0

    for i in range(samples):
        vclass = next(cycle)
        try:
            raw = completion_text(
                client,
                TRANSPLANT_SYSTEM,
                build_transplant_messages(vclass),
                model=model,
                max_tokens=8192,
            )
            data = parse_json_response(raw)
        except (LLMClientError, json.JSONDecodeError, TypeError) as e:
            gen_err += 1
            rows.append({"index": i, "error": str(e), "intended_class": vclass})
            continue

        c_code = data.get("c_code")
        py_code = data.get("python_code")
        if not isinstance(c_code, str) or not isinstance(py_code, str):
            gen_err += 1
            rows.append({"index": i, "error": "missing c_code or python_code"})
            continue

        intended = _normalize_vuln_type(str(data.get("vulnerability_class", vclass)))
        sid = _sanitize_id(f"tp_{i}", f"tp_{i:04d}")
        c_path = outdir / f"{sid}.c"
        py_path = outdir / f"{sid}.py"
        c_path.write_text(c_code, encoding="utf-8")
        py_path.write_text(py_code, encoding="utf-8")

        if file_progress:
            file_progress(c_path.name)
        fc, ec = scan_file(client, c_path, outdir, model=model, max_lines=max_lines)
        if file_progress:
            file_progress(py_path.name)
        fp, ep = scan_file(client, py_path, outdir, model=model, max_lines=max_lines)

        c_hit = intended_detected(intended, fc)
        p_hit = intended_detected(intended, fp)
        if c_hit and p_hit:
            both += 1
        elif c_hit:
            c_only += 1
        elif p_hit:
            py_only += 1
        else:
            neither += 1

        rows.append(
            {
                "index": i,
                "sample_id": sid,
                "intended_class": intended,
                "c_detected": c_hit,
                "python_detected": p_hit,
                "port_notes": data.get("port_notes"),
                "c_findings": len(fc),
                "py_findings": len(fp),
                "scanner_errors_c": ec,
                "scanner_errors_py": ep,
            }
        )

    done = len(rows) - gen_err
    manifest = {
        "version": 1,
        "mode": "transplant",
        "research_question": (
            "When a vulnerability pattern is transplanted from C to Python while preserving the flaw class, "
            "does an LLM scanner detect it equally in both languages?"
        ),
        "model": model,
        "outdir": str(outdir),
        "seed": seed,
        "summary": {
            "samples_requested": samples,
            "generation_failures": gen_err,
            "evaluated": done,
            "both_detected": both,
            "c_only": c_only,
            "python_only": py_only,
            "neither": neither,
        },
        "samples": rows,
    }
    (outdir / "transplant_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
