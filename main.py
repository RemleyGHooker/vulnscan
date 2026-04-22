#!/usr/bin/env python3
"""vulnscan: LLM-assisted scanning, multi-model compare, adversarial eval, CVE bench."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from rich.console import Console

from adversarial import VULN_CLASSES, run_adversarial_eval
from comment_suppress import run_comment_suppression_experiment
from scanner_poison import run_scanner_poison_experiment
from self_knowledge import run_self_knowledge_experiment
from sleeper_experiment import run_sleeper_experiment
from transplant import run_transplant_experiment
from compare import compare_scan_files
from cvebench import run_cvebench
from engine import scan_files, scan_files_parallel
from git_paths import git_toplevel, paths_in_last_commit
from llm_client import DEFAULT_MODEL, LLMClientError, get_client
from llm_groq import DEFAULT_GROQ_MODEL, get_groq_client
from reporter import (
    filter_findings,
    print_adversarial_summary,
    print_adversarial_tier_table,
    print_comment_suppression_summary,
    print_compare_report,
    print_manifest_kv,
    print_table,
    write_compare_report,
    write_json_report,
)
from scanner import cleanup_clone, clone_repo, discover_source_files, is_github_url


def _print_usage(console: Console) -> None:
    console.print(
        "[bold]vulnscan[/bold] — LLM scanning, [cyan]--compare[/cyan] (Claude+Groq), adversarial eval, CVE bench.\n"
        "\n[dim]Scan:[/dim]  python main.py scan <path_or_url> [options]\n"
        "[dim]Compare:[/dim]  python main.py scan <path> --compare ...\n"
        "[dim]Adversarial:[/dim]  python main.py adversarial [--per-tier N] ...\n"
        "[dim]CVE bench:[/dim]  python main.py cvebench --manifest data/cve_ground_truth.json\n"
        "[dim]Comment suppression:[/dim]  python main.py comment-suppress --samples 20 -o suppress.json\n"
        "[dim]Self-knowledge:[/dim]  python main.py self-knowledge --samples 30 -o sk.json\n"
        "[dim]Transplant:[/dim]  python main.py transplant --samples 20 -o tp.json\n"
        "[dim]Scanner poison:[/dim]  python main.py scanner-poison --samples 20 -o poison.json\n"
        "[dim]Sleeper / prefix:[/dim]  python main.py sleeper --samples 20 --surface-lines 45 -o sl.json\n"
    )


def parse_scan_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="vulnscan scan",
        description="Scan a repository with Claude (optional Groq --compare).",
    )
    p.add_argument("target", help="GitHub URL or local directory")
    p.add_argument("-o", "--output", type=Path, default=Path("vulnscan_report.json"))
    p.add_argument(
        "--severity-filter",
        choices=("critical", "high", "medium", "low"),
        default="low",
    )
    p.add_argument("--max-files", type=int, default=0, help="0 = no limit")
    p.add_argument("--max-lines", type=int, default=120)
    p.add_argument("--model", default=DEFAULT_MODEL, help="Anthropic model id")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument(
        "--compare",
        action="store_true",
        help="Run each chunk through Claude and Groq; write side-by-side diff JSON",
    )
    p.add_argument(
        "--groq-model",
        default=DEFAULT_GROQ_MODEL,
        help=f"Groq model when using --compare (default: {DEFAULT_GROQ_MODEL})",
    )
    p.add_argument(
        "--parallel-workers",
        type=int,
        default=4,
        help="Concurrent files to scan (1 = sequential). Ignored with --compare.",
    )
    p.add_argument(
        "--no-secrets-files",
        action="store_true",
        help="Do not include .env / small config files in discovery",
    )
    p.add_argument(
        "--diff",
        action="store_true",
        help="Only scan files touched in the last git commit (requires git repo)",
    )
    return p.parse_args(argv)


def parse_adversarial_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="vulnscan adversarial")
    p.add_argument("--samples", type=int, default=5)
    p.add_argument(
        "--per-tier",
        type=int,
        default=None,
        metavar="N",
        help="Generate N samples per obfuscation tier (ignores --samples). E.g. 50 × 3 tiers = 150 API calls.",
    )
    p.add_argument("--language", default="python")
    p.add_argument("--vulnerability-class", choices=VULN_CLASSES, default=None)
    p.add_argument("--tier", choices=("obvious", "subtle", "disguised"), default=None)
    p.add_argument("--outdir", type=Path, default=Path("vulnscan_adv_workspace"))
    p.add_argument("-o", "--output", type=Path, default=Path("adversarial_report.json"))
    p.add_argument("--generator-model", default=DEFAULT_MODEL)
    p.add_argument("--scanner-model", default=DEFAULT_MODEL)
    p.add_argument("--max-lines", type=int, default=120)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def parse_comment_suppress_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="vulnscan comment-suppress",
        description=(
            "Paired vulnerable code vs. same logic with adversarial comments; "
            "measure scanner detection drop (prompt-injection via source comments)."
        ),
    )
    p.add_argument(
        "--samples",
        type=int,
        default=20,
        help="Number of paired generations (each = 1 gen + 2 scans)",
    )
    p.add_argument("--language", default="python")
    p.add_argument("--vulnerability-class", choices=VULN_CLASSES, default=None)
    p.add_argument("--tier", choices=("obvious", "subtle", "disguised"), default=None)
    p.add_argument(
        "--outdir",
        type=Path,
        default=Path("vulnscan_comment_suppress_workspace"),
    )
    p.add_argument("-o", "--output", type=Path, default=Path("comment_suppression_report.json"))
    p.add_argument("--generator-model", default=DEFAULT_MODEL)
    p.add_argument("--scanner-model", default=DEFAULT_MODEL)
    p.add_argument("--max-lines", type=int, default=120)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def parse_self_knowledge_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="vulnscan self-knowledge")
    p.add_argument("--samples", type=int, default=20)
    p.add_argument("--language", default="python")
    p.add_argument("--vulnerability-class", choices=VULN_CLASSES, default=None)
    p.add_argument("--tier", choices=("obvious", "subtle", "disguised"), default=None)
    p.add_argument("--outdir", type=Path, default=Path("vulnscan_self_knowledge_workspace"))
    p.add_argument("-o", "--output", type=Path, default=Path("self_knowledge_report.json"))
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--max-lines", type=int, default=120)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def parse_transplant_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="vulnscan transplant")
    p.add_argument("--samples", type=int, default=15)
    p.add_argument("--vulnerability-class", choices=VULN_CLASSES, default=None)
    p.add_argument("--outdir", type=Path, default=Path("vulnscan_transplant_workspace"))
    p.add_argument("-o", "--output", type=Path, default=Path("transplant_report.json"))
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--max-lines", type=int, default=120)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def parse_scanner_poison_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="vulnscan scanner-poison")
    p.add_argument("--samples", type=int, default=15)
    p.add_argument("--language", default="python")
    p.add_argument("--vulnerability-class", choices=VULN_CLASSES, default=None)
    p.add_argument("--outdir", type=Path, default=Path("vulnscan_scanner_poison_workspace"))
    p.add_argument("-o", "--output", type=Path, default=Path("scanner_poison_report.json"))
    p.add_argument("--generator-model", default=DEFAULT_MODEL)
    p.add_argument("--scanner-model", default=DEFAULT_MODEL)
    p.add_argument("--max-lines", type=int, default=120)
    p.add_argument("--obfuscation-tier", choices=("obvious", "subtle", "disguised"), default=None)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def parse_sleeper_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="vulnscan sleeper")
    p.add_argument("--samples", type=int, default=15)
    p.add_argument("--language", default="python")
    p.add_argument("--vulnerability-class", choices=VULN_CLASSES, default=None)
    p.add_argument("--tier", choices=("obvious", "subtle", "disguised"), default=None)
    p.add_argument("--surface-lines", type=int, default=45, help="Prefix length; vuln must appear after this")
    p.add_argument(
        "--repeat-scans",
        type=int,
        default=5,
        help="Repeated identical scans of full file (variance diagnostic)",
    )
    p.add_argument("--outdir", type=Path, default=Path("vulnscan_sleeper_workspace"))
    p.add_argument("-o", "--output", type=Path, default=Path("sleeper_report.json"))
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--max-lines", type=int, default=120)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def parse_cvebench_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="vulnscan cvebench")
    p.add_argument(
        "--manifest",
        type=Path,
        default=Path("data/cve_ground_truth.json"),
        help="JSON manifest with cases[]",
    )
    p.add_argument("-o", "--output", type=Path, default=Path("cvebench_report.json"))
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--max-lines", type=int, default=120)
    p.add_argument(
        "--max-files-per-repo",
        type=int,
        default=40,
        help="Cap files per case (0 = no limit; lower for smoke tests)",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def run_scan(args: argparse.Namespace) -> int:
    console = Console(stderr=True)
    clone_dir: Path | None = None
    target = args.target.strip()
    if is_github_url(target):
        console.print(f"[dim]Cloning {target}…[/dim]")
        try:
            clone_dir = clone_repo(target)
        except Exception as e:
            console.print(f"[red]Clone failed:[/red] {e}")
            return 2
        root = clone_dir
    else:
        root = Path(target).expanduser().resolve()
        if not root.is_dir():
            console.print(f"[red]Not a directory:[/red] {root}")
            return 2

    try:
        aclient = get_client()
    except LLMClientError as e:
        console.print(f"[red]{e}[/red]")
        cleanup_clone(clone_dir)
        return 2

    if args.diff:
        top = git_toplevel(root)
        if top is None:
            console.print("[red]--diff requires a git repository.[/red]")
            cleanup_clone(clone_dir)
            return 2
        if top.resolve() != root.resolve():
            console.print(f"[dim]--diff: using repo root {top}[/dim]")
        root = top

    files = discover_source_files(
        root,
        include_secrets_candidates=not args.no_secrets_files,
    )
    if args.diff:
        changed = set(paths_in_last_commit(root))
        if not changed:
            console.print("[yellow]No files in last commit.[/yellow]")
            cleanup_clone(clone_dir)
            return 0
        files = [
            f
            for f in files
            if str(f.relative_to(root)).replace("\\", "/") in changed
        ]
        if not files:
            console.print("[yellow]No scannable files overlap last commit.[/yellow]")
            cleanup_clone(clone_dir)
            return 0

    if args.max_files > 0:
        files = files[: args.max_files]

    if not files:
        console.print("[yellow]No source files matched.[/yellow]")
        cleanup_clone(clone_dir)
        return 0

    progress = (lambda rel: console.print(f"[dim]Scanning[/dim] {rel}")) if args.verbose else None

    if args.compare:
        try:
            gclient = get_groq_client()
        except LLMClientError as e:
            console.print(f"[red]{e}[/red]")
            cleanup_clone(clone_dir)
            return 2
        report, errors = compare_scan_files(
            aclient,
            gclient,
            files,
            root,
            claude_model=args.model,
            groq_model=args.groq_model,
            max_lines=args.max_lines,
            max_workers=max(1, min(args.parallel_workers, 3)),
            file_progress=progress,
        )
        write_compare_report(report, args.output)
        print_compare_report(report, Console())
        console.print(f"\n[dim]Compare JSON:[/dim] {args.output.resolve()}  [dim]Errors:[/dim] {errors}")
        cleanup_clone(clone_dir)
        return 0 if errors == 0 else 1

    workers = max(1, args.parallel_workers)
    if workers <= 1:
        all_findings, errors = scan_files(
            aclient,
            files,
            root,
            model=args.model,
            max_lines=args.max_lines,
            file_progress=progress,
        )
    else:
        all_findings, errors = scan_files_parallel(
            aclient,
            files,
            root,
            model=args.model,
            max_lines=args.max_lines,
            max_workers=workers,
            file_progress=progress,
        )

    filtered = filter_findings(all_findings, args.severity_filter)
    write_json_report(filtered, args.output)
    print_table(filtered, Console())
    console.print(f"\n[dim]JSON report:[/dim] {args.output.resolve()}")
    console.print(
        f"[dim]Files scanned:[/dim] {len(files)}  [dim]Findings:[/dim] {len(filtered)}  [dim]Errors:[/dim] {errors}"
    )
    cleanup_clone(clone_dir)
    return 0 if errors == 0 else 1


def run_adversarial(args: argparse.Namespace) -> int:
    console = Console(stderr=True)
    try:
        progress = (
            (lambda rel: console.print(f"[dim]Scanning[/dim] {rel}"))
            if args.verbose
            else None
        )
        manifest = run_adversarial_eval(
            outdir=args.outdir,
            samples=args.samples,
            per_tier=args.per_tier,
            language=args.language,
            vulnerability_class=args.vulnerability_class,
            obfuscation_tier=args.tier,
            generator_model=args.generator_model,
            scanner_model=args.scanner_model,
            max_lines=args.max_lines,
            seed=args.seed,
            file_progress=progress,
        )
    except LLMClientError as e:
        console.print(f"[red]{e}[/red]")
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print_adversarial_summary(manifest, Console())
    print_adversarial_tier_table(manifest, Console())
    console.print(f"\n[dim]Full report:[/dim] {args.output.resolve()}")
    console.print(
        f"[dim]Workspace:[/dim] {Path(manifest['outdir']).resolve() / 'adversarial_manifest.json'}"
    )
    return 0


def run_self_knowledge_cmd(args: argparse.Namespace) -> int:
    console = Console(stderr=True)
    try:
        progress = (
            (lambda rel: console.print(f"[dim]Scanning[/dim] {rel}"))
            if args.verbose
            else None
        )
        manifest = run_self_knowledge_experiment(
            outdir=args.outdir,
            samples=args.samples,
            language=args.language,
            vulnerability_class=args.vulnerability_class,
            obfuscation_tier=args.tier,
            model=args.model,
            max_lines=args.max_lines,
            seed=args.seed,
            file_progress=progress,
        )
    except LLMClientError as e:
        console.print(f"[red]{e}[/red]")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print_manifest_kv("Self-knowledge (multi-turn vs fresh)", manifest, Console())
    console.print(f"\n[dim]Report:[/dim] {args.output.resolve()}")
    return 0


def run_transplant_cmd(args: argparse.Namespace) -> int:
    console = Console(stderr=True)
    try:
        progress = (
            (lambda rel: console.print(f"[dim]Scanning[/dim] {rel}"))
            if args.verbose
            else None
        )
        manifest = run_transplant_experiment(
            outdir=args.outdir,
            samples=args.samples,
            vulnerability_class=args.vulnerability_class,
            model=args.model,
            max_lines=args.max_lines,
            seed=args.seed,
            file_progress=progress,
        )
    except LLMClientError as e:
        console.print(f"[red]{e}[/red]")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print_manifest_kv("Cross-language transplant (C vs Python)", manifest, Console())
    console.print(f"\n[dim]Report:[/dim] {args.output.resolve()}")
    return 0


def run_scanner_poison_cmd(args: argparse.Namespace) -> int:
    console = Console(stderr=True)
    try:
        progress = (
            (lambda rel: console.print(f"[dim]Scanning[/dim] {rel}"))
            if args.verbose
            else None
        )
        manifest = run_scanner_poison_experiment(
            outdir=args.outdir,
            samples=args.samples,
            language=args.language,
            vulnerability_class=args.vulnerability_class,
            obfuscation_tier=args.obfuscation_tier,
            generator_model=args.generator_model,
            scanner_model=args.scanner_model,
            max_lines=args.max_lines,
            seed=args.seed,
            file_progress=progress,
        )
    except LLMClientError as e:
        console.print(f"[red]{e}[/red]")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print_manifest_kv("Scanner-poison (directive comments)", manifest, Console())
    console.print(f"\n[dim]Report:[/dim] {args.output.resolve()}")
    return 0


def run_sleeper_cmd(args: argparse.Namespace) -> int:
    console = Console(stderr=True)
    try:
        progress = (
            (lambda rel: console.print(f"[dim]Scanning[/dim] {rel}"))
            if args.verbose
            else None
        )
        manifest = run_sleeper_experiment(
            outdir=args.outdir,
            samples=args.samples,
            language=args.language,
            vulnerability_class=args.vulnerability_class,
            obfuscation_tier=args.tier,
            surface_lines=args.surface_lines,
            repeat_scans=args.repeat_scans,
            model=args.model,
            max_lines=args.max_lines,
            seed=args.seed,
            file_progress=progress,
        )
    except LLMClientError as e:
        console.print(f"[red]{e}[/red]")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print_manifest_kv("Sleeper / prefix + repeat-scan stability", manifest, Console())
    console.print(f"\n[dim]Report:[/dim] {args.output.resolve()}")
    return 0


def run_comment_suppress_cmd(args: argparse.Namespace) -> int:
    console = Console(stderr=True)
    try:
        progress = (
            (lambda rel: console.print(f"[dim]Scanning[/dim] {rel}"))
            if args.verbose
            else None
        )
        manifest = run_comment_suppression_experiment(
            outdir=args.outdir,
            samples=args.samples,
            language=args.language,
            vulnerability_class=args.vulnerability_class,
            obfuscation_tier=args.tier,
            generator_model=args.generator_model,
            scanner_model=args.scanner_model,
            max_lines=args.max_lines,
            seed=args.seed,
            file_progress=progress,
        )
    except LLMClientError as e:
        console.print(f"[red]{e}[/red]")
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print_comment_suppression_summary(manifest, Console())
    console.print(f"\n[dim]Full report:[/dim] {args.output.resolve()}")
    console.print(
        f"[dim]Workspace:[/dim] {Path(manifest['outdir']).resolve() / 'comment_suppression_manifest.json'}"
    )
    return 0


def run_cvebench_cmd(args: argparse.Namespace) -> int:
    console = Console(stderr=True)
    man = args.manifest
    if not man.is_file():
        console.print(f"[red]Manifest not found:[/red] {man}")
        return 2
    progress = (lambda rel: console.print(f"[dim]Scanning[/dim] {rel}")) if args.verbose else None
    try:
        report = run_cvebench(
            man,
            model=args.model,
            max_lines=args.max_lines,
            max_files_per_repo=args.max_files_per_repo,
            file_progress=progress,
        )
    except LLMClientError as e:
        console.print(f"[red]{e}[/red]")
        return 2
    except (json.JSONDecodeError, ValueError) as e:
        console.print(f"[red]{e}[/red]")
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    summ = report.get("summary", {})
    console.print(
        f"[bold]CVE bench[/bold] matched {summ.get('cases_matched')}/{summ.get('cases_with_expectations')} "
        f"(rate={summ.get('match_rate')}) → {args.output.resolve()}"
    )
    return 0


def main() -> int:
    argv = sys.argv[1:]
    console = Console(stderr=True)

    if not argv or argv[0] in ("-h", "--help"):
        _print_usage(console)
        if argv and argv[0] in ("-h", "--help"):
            parse_scan_args(["--help"])
        return 0

    if argv[0] == "adversarial":
        return run_adversarial(parse_adversarial_args(argv[1:]))
    if argv[0] == "comment-suppress":
        return run_comment_suppress_cmd(parse_comment_suppress_args(argv[1:]))
    if argv[0] == "self-knowledge":
        return run_self_knowledge_cmd(parse_self_knowledge_args(argv[1:]))
    if argv[0] == "transplant":
        return run_transplant_cmd(parse_transplant_args(argv[1:]))
    if argv[0] == "scanner-poison":
        return run_scanner_poison_cmd(parse_scanner_poison_args(argv[1:]))
    if argv[0] == "sleeper":
        return run_sleeper_cmd(parse_sleeper_args(argv[1:]))
    if argv[0] == "cvebench":
        return run_cvebench_cmd(parse_cvebench_args(argv[1:]))
    if argv[0] == "scan":
        return run_scan(parse_scan_args(argv[1:]))
    return run_scan(parse_scan_args(argv))


if __name__ == "__main__":
    sys.exit(main())
