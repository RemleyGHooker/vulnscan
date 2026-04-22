"""Shared scan loop: chunk files, call LLM, collect normalized findings."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from llm_client import LLMClientError, analyze_chunk
from prompts import VULN_SCAN_SYSTEM, build_scan_messages
from reporter import normalize_finding
from scanner import chunk_file_lines, language_from_path


def scan_file(
    client,
    path: Path,
    root: Path,
    *,
    model: str,
    max_lines: int,
) -> tuple[list[dict], int]:
    """
    Scan one source file. Returns (findings, error_count).
    """
    findings: list[dict] = []
    errors = 0
    rel = str(path.relative_to(root)).replace("\\", "/")
    lang = language_from_path(path)
    try:
        for chunk_text, _s, _e in chunk_file_lines(path, root, max_lines=max_lines):
            messages = build_scan_messages(rel, lang, chunk_text)
            try:
                data = analyze_chunk(
                    client,
                    VULN_SCAN_SYSTEM,
                    messages,
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


def scan_files(
    client,
    files: list[Path],
    root: Path,
    *,
    model: str,
    max_lines: int,
    file_progress: Callable[[str], None] | None = None,
) -> tuple[list[dict], int]:
    """Scan many files; concatenate findings and sum errors.

    If ``file_progress`` is set, it is called with the repo-relative file path
    before each file is scanned (for ``--verbose`` CLI output).
    """
    all_findings: list[dict] = []
    total_errors = 0
    for path in files:
        rel = str(path.relative_to(root)).replace("\\", "/")
        if file_progress is not None:
            file_progress(rel)
        f, err = scan_file(client, path, root, model=model, max_lines=max_lines)
        all_findings.extend(f)
        total_errors += err
    return all_findings, total_errors


def scan_files_parallel(
    client,
    files: list[Path],
    root: Path,
    *,
    model: str,
    max_lines: int,
    max_workers: int = 4,
    file_progress: Callable[[str], None] | None = None,
) -> tuple[list[dict], int]:
    """Like ``scan_files`` but scan multiple files concurrently (I/O-bound API calls)."""
    if max_workers <= 1:
        return scan_files(
            client,
            files,
            root,
            model=model,
            max_lines=max_lines,
            file_progress=file_progress,
        )

    all_findings: list[dict] = []
    total_errors = 0

    def work(item: Path) -> tuple[list[dict], int]:
        return scan_file(client, item, root, model=model, max_lines=max_lines)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_map = {}
        for path in files:
            rel = str(path.relative_to(root)).replace("\\", "/")
            if file_progress is not None:
                file_progress(rel)
            future_map[ex.submit(work, path)] = rel

        for fut in as_completed(future_map):
            f, err = fut.result()
            all_findings.extend(f)
            total_errors += err

    return all_findings, total_errors
