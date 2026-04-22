#!/usr/bin/env python3
"""
Aggregate research manifests into a paper-ready analysis bundle.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _norm_mode(root: dict[str, Any], path: Path) -> str:
    m = root.get("mode")
    if isinstance(m, str) and m.strip():
        return m.strip()
    name = path.name
    if "multi_turn" in name:
        return "multi_turn_audit"
    if "context_isolation" in name:
        return "context_isolation"
    if "comment_suppression" in name:
        return "comment_suppression"
    if "scanner_poison" in name:
        return "scanner_poison"
    return "unknown"


def _experiment_version(root: dict[str, Any]) -> str:
    ev = root.get("experiment_version")
    if isinstance(ev, str) and ev.strip():
        return ev.strip()
    v = root.get("version")
    return f"manifest_v{v}" if v is not None else "unknown"


def _wilson_95(k: int, n: int) -> dict[str, Any]:
    if n <= 0:
        return {"rate": None, "ci95_low": None, "ci95_high": None, "k": k, "n": n}
    z = 1.959963984540054
    p = k / n
    den = 1.0 + (z * z) / n
    center = (p + (z * z) / (2.0 * n)) / den
    margin = z * math.sqrt((p * (1 - p) + (z * z) / (4.0 * n)) / n) / den
    lo = max(0.0, center - margin)
    hi = min(1.0, center + margin)
    return {
        "rate": round(p, 6),
        "ci95_low": round(lo, 6),
        "ci95_high": round(hi, 6),
        "k": int(k),
        "n": int(n),
    }


def _mcnemar_exact(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    low = sum(math.comb(n, i) for i in range(0, k + 1)) / (2**n)
    high = sum(math.comb(n, i) for i in range(max(b, c), n + 1)) / (2**n)
    return min(1.0, 2.0 * min(low, high))


def _paired_delta(a: list[int], b: list[int]) -> dict[str, Any]:
    n = min(len(a), len(b))
    if n == 0:
        return {
            "n": 0,
            "rate_a": None,
            "rate_b": None,
            "delta_a_minus_b": None,
            "mcnemar_p_value": None,
            "discordant_a1_b0": None,
            "discordant_a0_b1": None,
            "odds_ratio_discordant": None,
        }
    aa = a[:n]
    bb = b[:n]
    a1b0 = sum(1 for x, y in zip(aa, bb) if x == 1 and y == 0)
    a0b1 = sum(1 for x, y in zip(aa, bb) if x == 0 and y == 1)
    ra = sum(aa) / n
    rb = sum(bb) / n
    p = _mcnemar_exact(a1b0, a0b1)
    # Haldane-Anscombe correction to avoid divide by zero.
    odds_ratio = (a1b0 + 0.5) / (a0b1 + 0.5)
    return {
        "n": n,
        "rate_a": round(ra, 6),
        "rate_b": round(rb, 6),
        "delta_a_minus_b": round(ra - rb, 6),
        "mcnemar_p_value": round(p, 6),
        "discordant_a1_b0": a1b0,
        "discordant_a0_b1": a0b1,
        "odds_ratio_discordant": round(odds_ratio, 6),
    }


def _row_base(
    root: dict[str, Any],
    path: Path,
    sample: dict[str, Any],
) -> dict[str, Any]:
    return {
        "source_manifest": str(path.resolve()),
        "experiment": _norm_mode(root, path),
        "experiment_version": _experiment_version(root),
        "sample_id": str(sample.get("sample_id", sample.get("index", ""))),
        "intended_class": sample.get("intended_class"),
        "generator_model": sample.get("generator_model", root.get("generator_model", root.get("model"))),
        "scanner_model": sample.get("scanner_model", root.get("scanner_model", root.get("model"))),
    }


def _confounds_for_row(experiment: str, sample: dict[str, Any], condition: str) -> list[str]:
    flags: list[str] = []
    if experiment == "context_isolation":
        if sample.get("isolation_note"):
            flags.append("risk_score_fallback")
    if experiment == "multi_turn_audit" and condition == "cross_model_detected":
        flags.append("groq_format_path")
    if sample.get("scan_skipped"):
        flags.append("scan_skipped")
    return flags


def _flatten_rows(root: dict[str, Any], path: Path) -> tuple[list[dict[str, Any]], int]:
    samples = root.get("samples")
    if not isinstance(samples, list):
        return [], 0
    exp = _norm_mode(root, path)
    out: list[dict[str, Any]] = []
    err_count = 0
    for s in samples:
        if not isinstance(s, dict):
            continue
        base = _row_base(root, path, s)
        row_err = bool(
            s.get("error")
            or s.get("generation_error")
            or s.get("multi_turn_error")
            or s.get("fresh_self_error")
            or s.get("cross_model_error")
            or s.get("full_file_error")
            or s.get("isolated_error")
            or s.get("summarized_error")
        )
        if row_err:
            err_count += 1
        conditions: list[str] = []
        if exp == "multi_turn_audit":
            conditions = ["multi_turn_detected", "fresh_self_detected", "cross_model_detected"]
        elif exp == "context_isolation":
            conditions = [
                "full_file_detected",
                "isolated_detected",
                "summarized_context_detected",
                "template_summarized_detected",
            ]
        elif exp == "comment_suppression":
            conditions = ["baseline_detected", "treatment_detected"]
        elif exp == "scanner_poison":
            conditions = ["baseline_detected", "poison_detected"]
        for cond in conditions:
            val = s.get(cond)
            if not isinstance(val, bool):
                continue
            row = dict(base)
            row["condition"] = cond
            row["detected"] = val
            row["row_has_error"] = row_err
            row["confound_flags"] = _confounds_for_row(exp, s, cond)
            out.append(row)
    return out, err_count


def _apply_model_filters(
    rows: list[dict[str, Any]],
    generator_model: str | None,
    scanner_model: str | None,
) -> list[dict[str, Any]]:
    out = rows
    if generator_model:
        out = [r for r in out if str(r.get("generator_model", "")) == generator_model]
    if scanner_model:
        out = [r for r in out if str(r.get("scanner_model", "")) == scanner_model]
    return out


def _group_rates(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in rows:
        key = (str(r["experiment"]), str(r["condition"]))
        buckets.setdefault(key, []).append(r)
    out: list[dict[str, Any]] = []
    for (exp, cond), group in sorted(buckets.items()):
        n = len(group)
        k = sum(1 for g in group if g["detected"])
        ci = _wilson_95(k, n)
        out.append(
            {
                "experiment": exp,
                "condition": cond,
                **ci,
                "generator_models": sorted({str(g.get("generator_model", "")) for g in group}),
                "scanner_models": sorted({str(g.get("scanner_model", "")) for g in group}),
            }
        )
    return out


def _experiment_deltas(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Paired within sample_id for each experiment.
    by_exp_sample: dict[str, dict[str, dict[str, int]]] = {}
    for r in rows:
        exp = str(r["experiment"])
        sid = str(r["sample_id"])
        by_exp_sample.setdefault(exp, {}).setdefault(sid, {})[str(r["condition"])] = int(r["detected"])
    specs = {
        "multi_turn_audit": [
            ("fresh_self_detected", "multi_turn_detected", "fresh_vs_multi_turn"),
            ("cross_model_detected", "fresh_self_detected", "cross_vs_fresh_self"),
        ],
        "context_isolation": [
            ("full_file_detected", "isolated_detected", "full_vs_isolated"),
            ("summarized_context_detected", "isolated_detected", "summarized_vs_isolated"),
            ("summarized_context_detected", "template_summarized_detected", "llm_summary_vs_template_summary"),
        ],
        "comment_suppression": [
            ("baseline_detected", "treatment_detected", "baseline_vs_treatment"),
        ],
        "scanner_poison": [
            ("baseline_detected", "poison_detected", "baseline_vs_poison"),
        ],
    }
    out: list[dict[str, Any]] = []
    for exp, pairs in specs.items():
        sample_map = by_exp_sample.get(exp, {})
        for a_name, b_name, label in pairs:
            a_vals: list[int] = []
            b_vals: list[int] = []
            for cond_map in sample_map.values():
                if a_name in cond_map and b_name in cond_map:
                    a_vals.append(cond_map[a_name])
                    b_vals.append(cond_map[b_name])
            d = _paired_delta(a_vals, b_vals)
            out.append({"experiment": exp, "comparison": label, "a_condition": a_name, "b_condition": b_name, **d})
    return out


def _paper_block(
    rows: list[dict[str, Any]],
    raw_rows_total: int,
    raw_error_rows: int,
    excluded_for_errors: int,
    excluded_for_confounds: int,
    manifest_versions: list[str],
) -> dict[str, Any]:
    rates = _group_rates(rows)
    deltas = _experiment_deltas(rows)
    by_exp_n: dict[str, dict[str, int]] = {}
    for r in rows:
        e = str(r["experiment"])
        c = str(r["condition"])
        by_exp_n.setdefault(e, {}).setdefault(c, 0)
        by_exp_n[e][c] += 1
    return {
        "per_experiment_detection_rates_with_95ci": rates,
        "cross_experiment_deltas_with_significance_and_effect_size": deltas,
        "sample_sizes_per_condition": by_exp_n,
        "error_rates_and_exclusions": {
            "raw_condition_rows": raw_rows_total,
            "raw_error_rows": raw_error_rows,
            "raw_error_row_rate": round(raw_error_rows / raw_rows_total, 6) if raw_rows_total else None,
            "excluded_for_errors": excluded_for_errors,
            "excluded_for_confound_flags": excluded_for_confounds,
            "final_condition_rows_analyzed": len(rows),
        },
        "model_versions_used": sorted(set(manifest_versions)),
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    cols = [
        "source_manifest",
        "experiment",
        "experiment_version",
        "sample_id",
        "intended_class",
        "generator_model",
        "scanner_model",
        "condition",
        "detected",
        "row_has_error",
        "confound_flags",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            row = dict(r)
            row["confound_flags"] = ";".join(row.get("confound_flags", []))
            w.writerow({k: row.get(k) for k in cols})


def main() -> int:
    ap = argparse.ArgumentParser(description="Aggregate research manifests for paper-ready metrics.")
    ap.add_argument("--manifests", nargs="+", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("aggregate_research_results.json"))
    ap.add_argument("--export-csv", type=Path, default=None, help="Optional normalized condition-row CSV")
    ap.add_argument("--exclude-errors", action="store_true", help="Exclude condition rows from samples with errors")
    ap.add_argument(
        "--exclude-confounds",
        action="store_true",
        help="Exclude condition rows with any confound_flags for sensitivity analysis",
    )
    ap.add_argument("--filter-generator-model", default=None)
    ap.add_argument("--filter-scanner-model", default=None)
    args = ap.parse_args()

    console = Console()
    all_rows: list[dict[str, Any]] = []
    manifest_meta: list[dict[str, Any]] = []
    raw_error_rows = 0

    for mp in args.manifests:
        try:
            root = _load_json(mp)
        except (OSError, json.JSONDecodeError) as e:
            console.print(f"[yellow]Skipping {mp}: {e}[/yellow]")
            continue
        rows, errs = _flatten_rows(root, mp)
        raw_error_rows += errs
        all_rows.extend(rows)
        manifest_meta.append(
            {
                "path": str(mp.resolve()),
                "mode": _norm_mode(root, mp),
                "version": root.get("version"),
                "experiment_version": _experiment_version(root),
                "generator_model": root.get("generator_model", root.get("model")),
                "scanner_model": root.get("scanner_model", root.get("model")),
                "sample_count": len(root.get("samples", [])) if isinstance(root.get("samples"), list) else 0,
            }
        )

    raw_rows_total = len(all_rows)
    filtered = _apply_model_filters(
        all_rows,
        generator_model=args.filter_generator_model,
        scanner_model=args.filter_scanner_model,
    )
    excluded_for_errors = 0
    if args.exclude_errors:
        pre = len(filtered)
        filtered = [r for r in filtered if not r.get("row_has_error")]
        excluded_for_errors = pre - len(filtered)
    excluded_for_confounds = 0
    if args.exclude_confounds:
        pre = len(filtered)
        filtered = [r for r in filtered if not r.get("confound_flags")]
        excluded_for_confounds = pre - len(filtered)

    rates = _group_rates(filtered)
    deltas = _experiment_deltas(filtered)
    versions = [str(m.get("experiment_version")) for m in manifest_meta if m.get("experiment_version")]
    paper = _paper_block(
        filtered,
        raw_rows_total=raw_rows_total,
        raw_error_rows=raw_error_rows,
        excluded_for_errors=excluded_for_errors,
        excluded_for_confounds=excluded_for_confounds,
        manifest_versions=versions,
    )
    output = {
        "version": 1,
        "research_question": (
            "How do detection outcomes vary across context/audit/suppression experiments, "
            "including uncertainty, error sensitivity, and confound-aware exclusions?"
        ),
        "inputs": manifest_meta,
        "flags": {
            "exclude_errors": args.exclude_errors,
            "exclude_confounds": args.exclude_confounds,
            "filter_generator_model": args.filter_generator_model,
            "filter_scanner_model": args.filter_scanner_model,
        },
        "normalized_condition_rows": filtered,
        "per_condition_rates_with_95ci": rates,
        "paired_deltas_significance_effect_sizes": deltas,
        "paper_ready_metrics": paper,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(output, indent=2), encoding="utf-8")
    if args.export_csv:
        _write_csv(args.export_csv, filtered)

    tbl = Table(title="Aggregate research results", show_lines=True)
    tbl.add_column("Experiment", style="cyan")
    tbl.add_column("Condition")
    tbl.add_column("N", justify="right")
    tbl.add_column("Rate")
    tbl.add_column("95% CI")
    for row in rates:
        ci = (
            f"[{row['ci95_low']}, {row['ci95_high']}]"
            if row["ci95_low"] is not None
            else ""
        )
        tbl.add_row(
            str(row["experiment"]),
            str(row["condition"]),
            str(row["n"]),
            "" if row["rate"] is None else str(row["rate"]),
            ci,
        )
    console.print(tbl)
    console.print(f"\n[green]Wrote JSON[/green] {args.out.resolve()}")
    if args.export_csv:
        console.print(f"[green]Wrote CSV[/green] {args.export_csv.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
