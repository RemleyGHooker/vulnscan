"""Multi-model compare: same chunk → Claude vs Groq → structured diff."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import anthropic
from groq import Groq

from llm_client import LLMClientError, analyze_chunk
from llm_groq import analyze_chunk_groq
from prompts import VULN_SCAN_SYSTEM, build_scan_messages
from reporter import normalize_finding
from scanner import chunk_file_lines, language_from_path


def _norm_type(t: str) -> str:
    return str(t).lower().strip().replace("-", "_").replace(" ", "_")


def findings_equivalent(a: dict[str, Any], b: dict[str, Any], line_slack: int = 5) -> bool:
    if _norm_type(a.get("vulnerability_type", "")) != _norm_type(b.get("vulnerability_type", "")):
        return False
    try:
        la = int(a.get("line_number", 0))
        lb = int(b.get("line_number", 0))
    except (TypeError, ValueError):
        return False
    return abs(la - lb) <= line_slack


def diff_findings(
    claude_findings: list[dict[str, Any]],
    groq_findings: list[dict[str, Any]],
) -> tuple[list[dict], list[dict], list[tuple[dict, dict]]]:
    """
    Returns (claude_only, groq_only, matched_pairs).
    Greedy match: pair findings that are equivalent; each finding used at most once.
    """
    c_left = list(claude_findings)
    g_left = list(groq_findings)
    pairs: list[tuple[dict, dict]] = []
    for c in list(c_left):
        for g in list(g_left):
            if findings_equivalent(c, g):
                pairs.append((c, g))
                c_left.remove(c)
                g_left.remove(g)
                break
    return c_left, g_left, pairs


def compare_scan_file(
    anthropic_client: anthropic.Anthropic,
    groq_client: Groq,
    path: Path,
    root: Path,
    *,
    claude_model: str,
    groq_model: str,
    max_lines: int,
) -> tuple[dict[str, Any], int]:
    """
    Scan each chunk with Claude and Groq (parallel per chunk). Returns (report_dict, error_count).
    """
    rel = str(path.relative_to(root)).replace("\\", "/")
    lang = language_from_path(path)
    chunks_out: list[dict[str, Any]] = []
    errors = 0

    for chunk_text, start_ln, end_ln in chunk_file_lines(path, root, max_lines=max_lines):
        messages = build_scan_messages(rel, lang, chunk_text)
        user_content = messages[0]["content"]

        def run_claude() -> dict[str, Any]:
            return analyze_chunk(
                anthropic_client,
                VULN_SCAN_SYSTEM,
                messages,
                model=claude_model,
            )

        def run_groq() -> dict[str, Any]:
            return analyze_chunk_groq(
                groq_client,
                VULN_SCAN_SYSTEM,
                user_content,
                model=groq_model,
            )

        try:
            with ThreadPoolExecutor(max_workers=2) as ex:
                f_c = ex.submit(run_claude)
                f_g = ex.submit(run_groq)
                c_data = f_c.result()
                g_data = f_g.result()
        except LLMClientError:
            errors += 1
            chunks_out.append(
                {
                    "file_path": rel,
                    "start_line": start_ln,
                    "end_line": end_ln,
                    "error": "one or both models failed",
                }
            )
            continue
        except Exception:
            errors += 1
            continue

        def normalize_list(data: dict[str, Any]) -> list[dict[str, Any]]:
            out: list[dict[str, Any]] = []
            raw = data.get("findings")
            if not isinstance(raw, list):
                return out
            for item in raw:
                if isinstance(item, dict):
                    n = normalize_finding(item, rel)
                    if n:
                        out.append(n)
            return out

        c_find = normalize_list(c_data or {})
        g_find = normalize_list(g_data or {})
        c_only, g_only, both = diff_findings(c_find, g_find)

        chunks_out.append(
            {
                "file_path": rel,
                "start_line": start_ln,
                "end_line": end_ln,
                "claude_findings": c_find,
                "groq_findings": g_find,
                "claude_only": c_only,
                "groq_only": g_only,
                "agreed_pairs": [
                    {"claude": a, "groq": b} for a, b in both
                ],
                "counts": {
                    "claude": len(c_find),
                    "groq": len(g_find),
                    "agreed": len(both),
                    "claude_only": len(c_only),
                    "groq_only": len(g_only),
                },
            }
        )

    return (
        {
            "version": 1,
            "mode": "compare",
            "file_path": rel,
            "claude_model": claude_model,
            "groq_model": groq_model,
            "chunks": chunks_out,
        },
        errors,
    )


def compare_scan_files(
    anthropic_client: anthropic.Anthropic,
    groq_client: Groq,
    files: list[Path],
    root: Path,
    *,
    claude_model: str,
    groq_model: str,
    max_lines: int,
    max_workers: int = 2,
    file_progress: Any = None,
) -> tuple[dict[str, Any], int]:
    """Compare-scan many files (parallel across files when max_workers > 1)."""
    file_reports: list[dict[str, Any]] = []
    total_errors = 0

    def one_file(p: Path) -> tuple[dict[str, Any], int]:
        rep, err = compare_scan_file(
            anthropic_client,
            groq_client,
            p,
            root,
            claude_model=claude_model,
            groq_model=groq_model,
            max_lines=max_lines,
        )
        return rep, err

    if max_workers <= 1:
        for p in files:
            rel = str(p.relative_to(root)).replace("\\", "/")
            if file_progress:
                file_progress(rel)
            rep, err = one_file(p)
            file_reports.append(rep)
            total_errors += err
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {}
            for p in files:
                rel = str(p.relative_to(root)).replace("\\", "/")
                if file_progress:
                    file_progress(rel)
                futs[ex.submit(one_file, p)] = rel
            for fut in as_completed(futs):
                rep, err = fut.result()
                file_reports.append(rep)
                total_errors += err

    merged = {
        "version": 1,
        "mode": "compare",
        "claude_model": claude_model,
        "groq_model": groq_model,
        "files": file_reports,
    }
    return merged, total_errors
