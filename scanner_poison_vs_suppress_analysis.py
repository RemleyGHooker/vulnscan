#!/usr/bin/env python3
"""
Offline analysis: compare comment-suppression (social engineering) vs scanner-poison (directive) manifests.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table


def _load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _valid_row(s: dict[str, Any]) -> bool:
    return not s.get("error") and "baseline_detected" in s


def _row_metrics(samples: list[dict[str, Any]], baseline_key: str, treatment_key: str) -> dict[str, Any]:
    rows = [s for s in samples if _valid_row(s) and baseline_key in s and treatment_key in s]
    n = len(rows)
    if n == 0:
        return {
            "n": 0,
            "baseline_detection_rate": None,
            "treatment_detection_rate": None,
            "suppression_rate_given_baseline_detected": None,
            "suppression_rate_overall_sample_fraction": None,
            "mcnemar_b": None,
            "mcnemar_c": None,
            "mcnemar_p_value": None,
        }
    b_hits = sum(1 for s in rows if s[baseline_key])
    t_hits = sum(1 for s in rows if s[treatment_key])
    suppressed = sum(1 for s in rows if s[baseline_key] and not s[treatment_key])
    sup_given_base = (suppressed / b_hits) if b_hits else None
    b_only = sum(1 for s in rows if s[baseline_key] and not s[treatment_key])
    c_rev = sum(1 for s in rows if not s[baseline_key] and s[treatment_key])
    p_mcn = mcnemar_exact_p_value(b_only, c_rev)
    return {
        "n": n,
        "baseline_detection_rate": round(b_hits / n, 6),
        "treatment_detection_rate": round(t_hits / n, 6),
        "suppression_rate_given_baseline_detected": round(sup_given_base, 6)
        if sup_given_base is not None
        else None,
        "suppression_rate_overall_sample_fraction": round(suppressed / n, 6) if n else None,
        "mcnemar_b": b_only,
        "mcnemar_c": c_rev,
        "mcnemar_p_value": p_mcn,
        "contingency_baseline_yes_treatment_no": b_only,
        "contingency_baseline_no_treatment_yes": c_rev,
    }


def mcnemar_exact_p_value(b: int, c: int) -> float:
    """Two-sided exact McNemar for discordant pairs (binomial n=b+c, p=0.5)."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    # P(X <= k) under Binomial(n, 0.5)
    tail_low = sum(math.comb(n, i) for i in range(0, k + 1)) / (2**n)
    tail_high = sum(math.comb(n, i) for i in range(max(b, c), n + 1)) / (2**n)
    return min(1.0, 2 * min(tail_low, tail_high))


def cohens_kappa_binary(a: list[int], b: list[int]) -> float | None:
    if len(a) != len(b) or not a:
        return None
    n = len(a)
    p_o = sum(1 for x, y in zip(a, b) if x == y) / n
    p_yes_a = sum(a) / n
    p_yes_b = sum(b) / n
    p_e = p_yes_a * p_yes_b + (1 - p_yes_a) * (1 - p_yes_b)
    if abs(1 - p_e) < 1e-12:
        return 0.0
    return (p_o - p_e) / (1 - p_e)


def _paired_suppression_flags(
    poison_samples: list[dict[str, Any]],
    suppress_samples: list[dict[str, Any]],
) -> tuple[list[int], list[int]]:
    """Align by index; 1 = suppression occurred (baseline detected, treatment not)."""
    m = min(len(poison_samples), len(suppress_samples))
    a: list[int] = []
    b: list[int] = []
    for i in range(m):
        p = poison_samples[i]
        s = suppress_samples[i]
        if p.get("error") or s.get("error"):
            continue
        if not all(k in p for k in ("baseline_detected", "poison_detected")):
            continue
        if not all(k in s for k in ("baseline_detected", "treatment_detected")):
            continue
        a.append(1 if (p["baseline_detected"] and not p["poison_detected"]) else 0)
        b.append(1 if (s["baseline_detected"] and not s["treatment_detected"]) else 0)
    return a, b


def _contingency_2x2(
    poison_suppressed: list[int],
    social_suppressed: list[int],
) -> dict[str, int]:
    """Rows: scanner directive suppressed? Cols: social engineering suppressed? (paired)."""
    both = se_only = dir_only = neither = 0
    for d, se in zip(poison_suppressed, social_suppressed):
        if d and se:
            both += 1
        elif se and not d:
            se_only += 1
        elif d and not se:
            dir_only += 1
        else:
            neither += 1
    return {
        "directive_yes_social_yes": both,
        "directive_no_social_yes": se_only,
        "directive_yes_social_no": dir_only,
        "directive_no_social_no": neither,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compare scanner_poison vs comment_suppression manifest outcomes (no API calls)."
    )
    ap.add_argument("--poison-manifest", type=Path, required=True)
    ap.add_argument("--suppress-manifest", type=Path, required=True)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("poison_vs_suppress_comparison.json"),
        help="Output JSON path",
    )
    args = ap.parse_args()
    console = Console()

    try:
        poison_root = _load_manifest(args.poison_manifest)
        supp_root = _load_manifest(args.suppress_manifest)
    except (OSError, json.JSONDecodeError) as e:
        console.print(f"[red]Failed to load manifest: {e}[/red]")
        return 2

    poison_samples = poison_root.get("samples") if isinstance(poison_root, dict) else []
    suppress_samples = supp_root.get("samples") if isinstance(supp_root, dict) else []
    if not isinstance(poison_samples, list) or not isinstance(suppress_samples, list):
        console.print("[red]Each manifest must contain a 'samples' list.[/red]")
        return 2

    social = _row_metrics(suppress_samples, "baseline_detected", "treatment_detected")
    directive = _row_metrics(poison_samples, "baseline_detected", "poison_detected")

    dir_flags, soc_flags = _paired_suppression_flags(poison_samples, suppress_samples)
    kappa = cohens_kappa_binary(dir_flags, soc_flags)
    cont = _contingency_2x2(dir_flags, soc_flags)

    interpretation = (
        "McNemar's test uses each manifest's *paired* baseline vs. treatment detections on the same synthetic "
        "samples from that run. A small p-value means baseline and treatment detection rates differ "
        "systematically more than chance would suggest under the null of equal marginal detection. "
        "It does **not** by itself prove one attack type is stronger than the other across manifests—"
        "those rows come from independent experiments unless you deliberately matched generation seeds."
    )

    out_payload: dict[str, Any] = {
        "version": 1,
        "research_question": (
            "Are explicit scanner directive comments more effective at suppressing LLM vulnerability "
            "detection than subtle social engineering comments?"
        ),
        "poison_manifest": str(args.poison_manifest.resolve()),
        "suppress_manifest": str(args.suppress_manifest.resolve()),
        "social_engineering_metrics": social,
        "scanner_directive_metrics": directive,
        "cohens_kappa_suppression_agreement_index_paired": kappa,
        "paired_sample_count_for_kappa": len(dir_flags),
        "contingency_suppression_paired_by_index": cont,
        "interpretation_note": interpretation,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out_payload, indent=2), encoding="utf-8")

    tbl = Table(title="Poison vs suppression (offline)", show_lines=True)
    tbl.add_column("Attack type", style="cyan")
    tbl.add_column("N", justify="right")
    tbl.add_column("Baseline det. rate", max_width=14)
    tbl.add_column("Treatment det. rate", max_width=14)
    tbl.add_column("Suppr. | given baseline hit", max_width=22)
    tbl.add_column("McNemar p", max_width=12)

    def fmt_rate(x: Any) -> str:
        return "" if x is None else str(x)

    tbl.add_row(
        "Social engineering",
        str(social["n"]),
        fmt_rate(social["baseline_detection_rate"]),
        fmt_rate(social["treatment_detection_rate"]),
        fmt_rate(social["suppression_rate_given_baseline_detected"]),
        fmt_rate(social["mcnemar_p_value"]),
    )
    tbl.add_row(
        "Scanner directive",
        str(directive["n"]),
        fmt_rate(directive["baseline_detection_rate"]),
        fmt_rate(directive["treatment_detection_rate"]),
        fmt_rate(directive["suppression_rate_given_baseline_detected"]),
        fmt_rate(directive["mcnemar_p_value"]),
    )
    console.print(tbl)
    console.print(f"\n[bold]Cohen's kappa[/bold] (paired-by-index suppression occurred): {kappa}")
    console.print("\n[bold]2×2 (paired suppression):[/bold]", json.dumps(cont, indent=2))
    console.print(f"\n[dim]{interpretation}[/dim]")
    console.print(f"\n[green]Wrote[/green] {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
