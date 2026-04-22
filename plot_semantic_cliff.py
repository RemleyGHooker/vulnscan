#!/usr/bin/env python3
"""Plot Full vs Summarized detection for key classes."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


def rates_by_class(manifest_path: Path) -> dict[str, dict[str, float]]:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = data.get("samples", [])
    by = defaultdict(lambda: {"n": 0, "full": 0, "summarized": 0})
    for r in rows:
        if not isinstance(r, dict):
            continue
        c = str(r.get("intended_class", "unknown"))
        f = r.get("full_file_detected")
        s = r.get("summarized_context_detected")
        if not isinstance(f, bool) or not isinstance(s, bool):
            continue
        by[c]["n"] += 1
        by[c]["full"] += int(f)
        by[c]["summarized"] += int(s)
    out: dict[str, dict[str, float]] = {}
    for c, m in by.items():
        n = m["n"]
        if n == 0:
            continue
        out[c] = {
            "full": m["full"] / n,
            "summarized": m["summarized"] / n,
        }
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate semantic-cliff grouped bar chart.")
    ap.add_argument(
        "--manifest",
        type=Path,
        default=Path("runs/ctx_50/context_isolation_manifest.json"),
    )
    ap.add_argument("--out", type=Path, default=Path("results.png"))
    ap.add_argument(
        "--classes",
        nargs="+",
        default=["buffer_overflow", "sql_injection"],
        help="Class names to plot (default: buffer_overflow sql_injection)",
    )
    args = ap.parse_args()

    rates = rates_by_class(args.manifest)
    classes = [c for c in args.classes if c in rates]
    if not classes:
        raise SystemExit("No requested classes found in manifest.")

    full_vals = [rates[c]["full"] for c in classes]
    sum_vals = [rates[c]["summarized"] for c in classes]

    x = list(range(len(classes)))
    w = 0.36
    plt.figure(figsize=(7, 4))
    plt.bar([i - w / 2 for i in x], full_vals, width=w, label="Full")
    plt.bar([i + w / 2 for i in x], sum_vals, width=w, label="Summarized")
    plt.xticks(x, classes, rotation=15)
    plt.ylim(0, 1.05)
    plt.ylabel("Detection Rate")
    plt.title("Semantic Cliff: Full vs Summarized Context")
    plt.legend()
    plt.tight_layout()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(args.out, dpi=180)
    print(f"Wrote {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
