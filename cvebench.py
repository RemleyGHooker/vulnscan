"""Run scanner against a manifest of public vulnerable/educational repos (CVE-style ground truth)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from engine import scan_files
from llm_client import LLMClientError, get_client
from scanner import cleanup_clone, clone_repo, discover_source_files, is_github_url

from adversarial import _normalize_vuln_type  # reuse label normalization


def finding_matches_expected(
    findings: list[dict[str, Any]],
    expected_families: list[str],
) -> bool:
    exp = {_normalize_vuln_type(x) for x in expected_families}
    for f in findings:
        t = _normalize_vuln_type(str(f.get("vulnerability_type", "other")))
        if t in exp:
            return True
        desc = (f.get("description") or "").lower()
        for e in exp:
            if e == "sql_injection" and "sql" in desc and "inject" in desc:
                return True
            if e == "command_injection" and "command" in desc and "inject" in desc:
                return True
    return False


def run_cvebench(
    manifest_path: Path,
    *,
    model: str,
    max_lines: int,
    max_files_per_repo: int,
    file_progress: Any = None,
) -> dict[str, Any]:
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = raw.get("cases")
    if not isinstance(cases, list):
        raise ValueError("Manifest must contain a 'cases' array")

    client = get_client()
    case_results: list[dict[str, Any]] = []
    hits = 0
    total = 0

    for case in cases:
        if not isinstance(case, dict):
            continue
        cid = str(case.get("id", "unknown"))
        url = case.get("repo_url")
        local_path = case.get("local_path")
        expected = case.get("expected_families") or []
        if not isinstance(expected, list):
            expected = []

        clone_dir: Path | None = None
        root: Path | None = None
        try:
            if local_path:
                root = Path(str(local_path)).expanduser().resolve()
                if not root.is_dir():
                    case_results.append({"id": cid, "error": f"local_path not a directory: {root}"})
                    continue
            elif url and is_github_url(str(url)):
                clone_dir = Path(tempfile.mkdtemp(prefix="vulnscan_cvebench_"))
                clone_repo(str(url), target=clone_dir)
                root = clone_dir
            else:
                case_results.append({"id": cid, "error": "case needs repo_url or local_path"})
                continue

            assert root is not None
            files = discover_source_files(root, include_secrets_candidates=True)
            if max_files_per_repo > 0:
                files = files[:max_files_per_repo]

            findings, errors = scan_files(
                client,
                files,
                root,
                model=model,
                max_lines=max_lines,
                file_progress=file_progress,
            )
            matched = finding_matches_expected(findings, [str(x) for x in expected])
            if expected:
                total += 1
                if matched:
                    hits += 1

            case_results.append(
                {
                    "id": cid,
                    "description": case.get("description"),
                    "repo_url": url,
                    "local_path": str(local_path) if local_path else None,
                    "expected_families": expected,
                    "matched_expected_family": matched if expected else None,
                    "files_scanned": len(files),
                    "findings_count": len(findings),
                    "scanner_errors": errors,
                    "sample_findings": findings[:15],
                }
            )
        except LLMClientError as e:
            case_results.append({"id": cid, "error": str(e)})
        finally:
            cleanup_clone(clone_dir)

    rate = (hits / total) if total else None
    return {
        "version": 1,
        "mode": "cvebench",
        "manifest": str(manifest_path.resolve()),
        "model": model,
        "summary": {
            "cases_with_expectations": total,
            "cases_matched": hits,
            "match_rate": round(rate, 4) if rate is not None else None,
            "disclaimer": "Heuristic match on vulnerability_type/description vs expected_families; not a formal CVE reproduction proof.",
        },
        "cases": case_results,
    }
