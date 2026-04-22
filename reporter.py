"""CLI table (rich) and JSON report output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def severity_meets_filter(severity: str, min_severity: str) -> bool:
    s = severity.lower().strip()
    m = min_severity.lower().strip()
    return SEVERITY_ORDER.get(s, 0) >= SEVERITY_ORDER.get(m, 0)


def normalize_finding(raw: dict[str, Any], default_file: str) -> dict[str, Any] | None:
    try:
        fp = str(raw.get("file_path") or default_file)
        ln = int(raw.get("line_number", 0))
        vtype = str(raw.get("vulnerability_type", "other"))
        sev = str(raw.get("severity", "low")).lower()
        if sev not in SEVERITY_ORDER:
            sev = "low"
        desc = str(raw.get("description", ""))
        fix = str(raw.get("suggested_fix", ""))
        return {
            "file_path": fp,
            "line_number": ln,
            "vulnerability_type": vtype,
            "severity": sev,
            "description": desc,
            "suggested_fix": fix,
        }
    except (TypeError, ValueError):
        return None


def filter_findings(
    findings: list[dict[str, Any]],
    min_severity: str,
) -> list[dict[str, Any]]:
    return [f for f in findings if severity_meets_filter(f["severity"], min_severity)]


def print_table(findings: list[dict[str, Any]], console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title="Vulnerability Scan Results", show_lines=True)
    table.add_column("File", style="cyan", no_wrap=False, max_width=36)
    table.add_column("Line", justify="right")
    table.add_column("Type", style="magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Description", max_width=50)
    for f in findings:
        sev = f["severity"]
        style = {
            "critical": "red",
            "high": "bright_red",
            "medium": "yellow",
            "low": "green",
        }.get(sev, "white")
        table.add_row(
            f["file_path"],
            str(f["line_number"]),
            f["vulnerability_type"],
            f"[{style}]{sev}[/]",
            f["description"][:200] + ("…" if len(f["description"]) > 200 else ""),
        )
    console.print(table)


def write_json_report(findings: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "findings": findings,
        "summary": {
            "total": len(findings),
            "by_severity": _count_by_severity(findings),
        },
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def print_adversarial_summary(manifest: dict[str, Any], console: Console | None = None) -> None:
    console = console or Console()
    summ = manifest.get("summary", {})
    table = Table(title="Adversarial eval (intended class detection)", show_lines=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    for key in (
        "samples_requested",
        "generation_failures",
        "evaluated",
        "true_positives",
        "false_negatives",
        "recall_on_intended_class",
    ):
        table.add_row(key.replace("_", " ").title(), str(summ.get(key, "")))
    console.print(table)

    rows = Table(title="Per-sample", show_lines=True)
    rows.add_column("Sample", max_width=20)
    rows.add_column("Intended")
    rows.add_column("Tier", max_width=10)
    rows.add_column("Hit", justify="center")
    rows.add_column("#Find", justify="right")
    rows.add_column("Extras", justify="right")
    for s in manifest.get("samples", []):
        if "error" in s:
            rows.add_row(
                str(s.get("index", "")),
                str(s.get("intended_class", "")),
                str(s.get("obfuscation_tier", "")),
                "[red]ERR[/]",
                "-",
                "-",
            )
            continue
        hit = "yes" if s.get("detected_intended") else "no"
        style = "green" if s.get("detected_intended") else "yellow"
        extras = len(s.get("extra_findings") or [])
        rows.add_row(
            str(s.get("sample_id", "")),
            str(s.get("intended_class", "")),
            str(s.get("obfuscation_tier", "")),
            f"[{style}]{hit}[/]",
            str(s.get("findings_count", 0)),
            str(extras),
        )
    console.print(rows)


def print_compare_report(compare_root: dict[str, Any], console: Console | None = None) -> None:
    """Rich summary for multi-model compare JSON."""
    console = console or Console()
    files = compare_root.get("files") or []
    if not files:
        console.print("[yellow]No file entries in compare report.[/yellow]")
        return
    table = Table(
        title=f"Model compare (Claude: {compare_root.get('claude_model','')} vs Groq: {compare_root.get('groq_model','')})",
        show_lines=True,
    )
    table.add_column("File", style="cyan", max_width=32)
    table.add_column("Claude", justify="right")
    table.add_column("Groq", justify="right")
    table.add_column("Agreed", justify="right")
    table.add_column("C-only", justify="right", style="yellow")
    table.add_column("G-only", justify="right", style="magenta")
    for frep in files:
        fp = frep.get("file_path", "")
        tc = tg = ta = conly = gonly = 0
        for ch in frep.get("chunks") or []:
            if "error" in ch:
                continue
            cts = ch.get("counts") or {}
            tc += int(cts.get("claude", 0))
            tg += int(cts.get("groq", 0))
            ta += int(cts.get("agreed", 0))
            conly += int(cts.get("claude_only", 0))
            gonly += int(cts.get("groq_only", 0))
        table.add_row(fp, str(tc), str(tg), str(ta), str(conly), str(gonly))
    console.print(table)


def print_manifest_kv(title: str, manifest: dict[str, Any], console: Console | None = None) -> None:
    """Print summary dict + optional research_question from experiment manifests."""
    console = console or Console()
    table = Table(title=title, show_lines=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    for k, v in sorted((manifest.get("summary") or {}).items()):
        table.add_row(str(k), str(v))
    console.print(table)
    rq = manifest.get("research_question")
    if rq:
        console.print(f"\n[dim]{rq}[/dim]")


def print_comment_suppression_summary(
    manifest: dict[str, Any],
    console: Console | None = None,
) -> None:
    """Rich summary for comment-suppression experiment."""
    console = console or Console()
    s = manifest.get("summary", {})
    t = Table(title="Comment-suppression experiment", show_lines=False)
    t.add_column("Metric", style="cyan")
    t.add_column("Value", style="white")
    rows = [
        ("Samples evaluated", s.get("samples_evaluated")),
        ("Generation failures", s.get("generation_failures")),
        ("Baseline detection rate", s.get("baseline_detection_rate")),
        ("Treatment detection rate", s.get("treatment_detection_rate")),
        ("Δ (baseline − treatment)", s.get("detection_rate_delta_baseline_minus_treatment")),
        ("Suppression events (hit→miss)", s.get("suppression_events")),
        ("P(suppress | baseline hit)", s.get("suppression_rate_given_baseline_detected")),
        ("Neither detected", s.get("baseline_miss_neither_detected")),
        ("Treatment-only hits", s.get("treatment_only_hits")),
    ]
    for k, v in rows:
        t.add_row(k, str(v))
    console.print(t)
    rq = manifest.get("research_question")
    if rq:
        console.print(f"\n[dim]{rq}[/dim]")


def print_adversarial_tier_table(manifest: dict[str, Any], console: Console | None = None) -> None:
    """Print detection_rate_by_tier if present."""
    console = console or Console()
    by = manifest.get("summary", {}).get("detection_rate_by_tier")
    if not by:
        return
    t = Table(title="Detection rate by obfuscation tier", show_lines=False)
    t.add_column("Tier", style="cyan")
    t.add_column("TP", justify="right")
    t.add_column("FN", justify="right")
    t.add_column("Rate", justify="right")
    for tier_name, row in sorted(by.items()):
        t.add_row(
            str(tier_name),
            str(row.get("true_positives", 0)),
            str(row.get("false_negatives", 0)),
            str(row.get("detection_rate", "")),
        )
    console.print(t)


def write_compare_report(compare_root: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(compare_root, indent=2), encoding="utf-8")


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        s = f.get("severity", "low")
        if s in counts:
            counts[s] += 1
    return counts
