# vulnscan

LLM-assisted vulnerability scanning and adversarial evaluation framework for studying robustness, failure modes, and class-dependent fragility in LLM security analysis.

## The problem

Modern codebases are too large and fast-moving for purely manual security review, so teams increasingly use LLMs to help find vulnerabilities. The core problem is reliability: an LLM can appear strong on one prompt or code view, then miss the same bug when context is reduced, summarized, or adversarially framed.

## How this work solves it

`vulnscan` turns that reliability question into a measurable research workflow. Instead of only asking "did the model find bugs?", it runs controlled experiments across context conditions and attack-style perturbations, logs machine-readable artifacts, and compares detection behavior class-by-class.

## Foundation and expansion

This repository builds on the April 9 arXiv preprint, *Vulnerability Detection with Interprocedural Context in Multiple Languages: Assessing Effectiveness and Cost of Modern LLMs* (Kevin Lira et al., 2026), and extends that line of inquiry into a broader adversarial evaluation suite. The April 9 study established strong evidence that context design materially affects LLM vulnerability detection quality and cost; this codebase expands that direction with context-isolation stress tests, adversarial suppression trials, scanner-poison experiments, multi-turn self-audit checks, cross-language transplants, and reproducible aggregation/plotting tooling.

## Core research contributions

- A unified scan/eval pipeline that supports both practical repo scanning and controlled adversarial experiments.
- A class-conditional context-isolation protocol comparing full-file, isolated-window, template summary, and LLM security-summary conditions.
- Paired suppression/poison experiments that isolate whether prompt-injection-like comments measurably change detection.
- Structured artifacts for reproducibility (`manifest` JSONs, aggregate CSV/JSON outputs, and figure-generation scripts).

## Findings snapshot

- **Semantic cliff:** Buffer overflow drops **100% -> 17%** with isolated/template context, then recovers to **100%** with LLM security-summary context.
- **Class-conditional robustness:** SQL injection remains **100%** across full, isolated, template, and LLM-summary conditions in the same run.
- **Memory leak pattern:** Memory leak shifts **100% -> 67% -> 100%** across full -> isolated/template -> LLM-summary.
- **Comment attacks in this setup:** Comment suppression is flat (**0.96 -> 0.96**), and scanner-poison is also flat (**0.36 -> 0.36**).

## Continued progress

- Scaling from exploratory runs toward larger-sample evaluations (`N >= 200`) for tighter confidence intervals.
- Expanding cross-model and cross-language comparisons while keeping manifests and prompts reproducible.
- Hardening evaluation quality with clearer labeling criteria and stronger human-adjudication workflows.
- Converting paper artifacts into release-ready figures and tables for public dissemination.

---

## Demo

**Rich table output** (what you see in the terminal after a scan):

<p align="center">
  <img src="assets/demo-terminal.png" alt="vulnscan CLI: Rich vulnerability table" width="720">
</p>

*Stylized screenshot of the CLI. For a **real** recording, run against intentionally vulnerable apps such as **[vulnado](https://github.com/ScaleSec/vulnado)** (Java) or **[DVWA](https://github.com/digininja/DVWA)** (PHP), then capture the terminal.*

---

## Research visuals

### Study design at a glance

```mermaid
flowchart TD
  RQ[Research questions] --> E1[Context isolation]
  RQ --> E2[Comment suppression]
  RQ --> E3[Scanner poison]
  RQ --> E4[Self-knowledge / transplant / sleeper]
  E1 --> M[Unified metrics + manifests]
  E2 --> M
  E3 --> M
  E4 --> M
  M --> A[Aggregate JSON + CSV]
  A --> P[Paper tables + figures]
```

### Semantic cliff intuition

```mermaid
flowchart LR
  F[Full context] -->|Summarize/trim context| I[Isolated or template context]
  I -->|Class-dependent drop| C[Detection cliff]
  C -->|Add LLM security summary| R[Recovery for fragile classes]
```

> Tip: add your paper figure export (for example `assets/semantic-cliff.png`) and embed it here once finalized.

---

## Paper (preprint)

**The Semantic Cliff: Class-Dependent Fragility of LLM Vulnerability Detection under Context Summarization**

- **LaTeX source:** [`paper.tex`](paper.tex)
- **PDF:** add [`paper.pdf`](paper.pdf) at the repo root when you publish a build (GitHub Release, arXiv, OpenReview Archive, etc.); until then run `pdflatex paper.tex` locally (requires a TeX distribution).

---

## Key research findings

This repo contains the pipeline used to produce the results summarized in [`paper.tex`](paper.tex). Primary quantitative runs used **\(N = 50\)** samples per experiment suite (aggregate Wilson CIs in `runs/aggregate_50_all_llm.json`); scaling to **\(N \geq 200\)** per suite tightens intervals for venue submission.

### Novel empirical findings

- **Semantic cliff (class-dependent collapse):** In context isolation, **buffer overflow** detection drops from **100% -> 17%** under isolated/template summarization, then **recovers to 100%** with an LLM security-focused summary prefix.
- **Class-conditional robustness:** **SQL injection** remains at **100%** across full, isolated, template, and LLM-summary conditions in the same run.
- **Partial fragility with recovery:** **Memory leak** shifts **100% -> 67%** (isolated/template) -> **100%** (LLM summary).
- **Compression quality matters more than compression itself:** Aggregate context rates are full-file **0.96**, isolated **0.84**, template **0.84**, and LLM summary **0.98**, indicating semantically informed summaries can outperform raw full-context baselines.
- **Prompt-style comment attacks were ineffective in this setup:** Comment suppression is flat (**0.96 -> 0.96**) and scanner-poison paired condition is also flat (**0.36 -> 0.36**) in the reported aggregate run.

Artifacts: `runs/ctx_50_llm/context_isolation_manifest.json`, `runs/aggregate_50_all_llm.json`, `runs/aggregate_50_all_llm.csv`, figure `runs/results_semantic_cliff_llm.png`.

---

## Architecture

```mermaid
flowchart LR
  subgraph scan["Scan mode"]
    A[GitHub URL or local repo] --> B[Discover .py .js .ts .c …]
    B --> C[Chunk files + line prefixes]
    C --> D[Claude: JSON findings]
    D --> E[Normalize + filter by severity]
    E --> F[Rich table + vulnscan_report.json]
  end
```

```mermaid
flowchart LR
  subgraph research["Research mode"]
    G[Generator prompt + tier] --> H[Synthetic vulnerable file]
    H --> I[Same chunk → LLM scan pipeline]
    I --> J[Match vs intended class + extras]
    J --> K[adversarial_report.json + manifest]
  end
```

Prompts live in **`prompts.py`** (`VULN_SCAN_*` for scanning, **`ADV_SYNTH_*`** for adversarial samples).

---

## Sample JSON (`vulnscan_report.json`)

```json
{
  "version": 1,
  "findings": [
    {
      "file_path": "src/LoginServlet.java",
      "line_number": 42,
      "vulnerability_type": "sql_injection",
      "severity": "high",
      "description": "User-controlled input concatenated into a SQL string before execution.",
      "suggested_fix": "Use parameterized queries / PreparedStatement exclusively."
    }
  ],
  "summary": {
    "total": 1,
    "by_severity": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0
    }
  }
}
```

**Adversarial run** (`-o adversarial_report.json`): each entry includes `intended_class`, `obfuscation_tier`, `detected_intended`, `findings`, `extra_findings`, and aggregate `summary.recall_on_intended_class`.

---

## Research mode: adversarial sample generation

This repo is not only a “linter with an API.” The **adversarial** path uses a structured prompt (see `ADV_SYNTH_SYSTEM` / `ADV_SYNTH_USER_TEMPLATE` in **`prompts.py`**) so an LLM emits **synthetic vulnerable code** with:

- a declared **vulnerability class** (e.g. `sql_injection`, `prompt_injection`),
- an **obfuscation tier** (`obvious` → `subtle` → `disguised`),

then **`vulnscan` scans that file with the same pipeline** used on real repos. You get machine-readable labels plus **whether the scanner reported the intended class**—useful for recall curves, multi-model comparisons, and human adjudication of false positives. *Recall here is heuristic (label match); treat published numbers seriously only with a frozen rubric and human labels.*

```bash
python3 main.py adversarial --samples 8 --language python -v -o adversarial_report.json
```

Flags: `--vulnerability-class`, `--tier`, `--generator-model` / `--scanner-model` (split models for disagreement studies). See **`python3 main.py adversarial --help`**.

**Paper-style tier table:** generate *N samples per obfuscation tier* (e.g. 50 × obvious / subtle / disguised = 150 generations). The report includes `summary.detection_rate_by_tier` for a ready-made results table.

```bash
python3 main.py adversarial --per-tier 50 --language python -o tier_eval.json -v
```

---

## Multi-model compare (Claude + Groq)

Same chunk is sent to **Anthropic** and **Groq** in parallel; JSON records `claude_findings`, `groq_findings`, `claude_only`, `groq_only`, and greedy `agreed_pairs` (type + nearby line). Requires **`GROQ_API_KEY`**.

```bash
export GROQ_API_KEY="…"
python3 main.py scan ./vulnado --compare -v -o compare.json
```

`--parallel-workers` applies to **per-file** concurrency in normal scan mode; compare mode caps file-level workers lower (each file already runs two models per chunk).

---

## Novel / high-impact research modes

| Command | What it tests |
|---------|----------------|
| `self-knowledge` | Same model: **multi-turn** (it wrote the code, then audits that conversation) vs **fresh isolated scan** of the same file — *self-knowledge blind spot*. |
| `transplant` | **C + Python pair** preserving a flaw class; scanner hits on each — *cross-language generalization*. |
| `scanner-poison` | Baseline vuln vs. same vuln plus **comments that explicitly instruct the reviewer** (empty findings / pre-audit) — *aggressive prompt injection in source*. |
| `sleeper` | Vuln **after line N** + scan of **prefix only** vs **full file**; **repeat identical scans** on full file for count variance — *hidden branch + stochastic stability*. |

Examples:

```bash
python3 main.py self-knowledge --samples 40 -v -o sk.json
python3 main.py transplant --samples 25 -v -o tp.json
python3 main.py scanner-poison --samples 30 --language python -v -o poison.json
python3 main.py sleeper --samples 20 --surface-lines 45 --repeat-scans 8 -o sleeper.json
```

Each mode writes a JSON report, a workspace manifest, and prints a summary table (`print_manifest_kv`). **Costs scale with samples** (API calls per design).

---

## Comment-suppression experiment (prompt injection in source)

**Research question:** *Can adversarially crafted source comments suppress LLM-based vulnerability detection?*

The `comment-suppress` command asks the generator for a **paired** program: (A) vulnerable baseline without misleading comments, and (B) the **same vulnerability** with comments crafted to persuade a reviewer the sink is safe. The **same** scanner model then analyzes both files; the report includes baseline vs. treatment detection rates, **suppression events** (baseline hit → treatment miss), and **P(suppress | baseline hit)**.

```bash
python3 main.py comment-suppress --samples 100 --language python -v -o suppression_report.json
```

Outputs: `-o` JSON, `comment_suppression_manifest.json` under `--outdir`, and paired sources (`*_baseline.py`, `*_suppressed.py`). This is an empirical probe—use large **N**, log model IDs and dates, and add human adjudication before claiming publication-ready effect sizes.

---

## CVE-style ground truth bench

`data/cve_ground_truth.json` lists public **intentionally vulnerable** repos and coarse `expected_families`. The command clones each (shallow), scans up to `--max-files-per-repo`, and reports whether any finding matched expectations (**heuristic**; tighten labels before claiming CVE reproduction).

```bash
python3 main.py cvebench --manifest data/cve_ground_truth.json -o cvebench.json --max-files-per-repo 25
```

---

## Other scan flags

| Flag | Behavior |
|------|----------|
| `--parallel-workers 8` | Scan multiple files concurrently (default 4) |
| `--diff` | Resolve git repo root, only files touched in **last commit** |
| `--no-secrets-files` | Skip `.env` / small `config.yaml`-style candidates |
| `-v` / `--verbose` | Log each file (or synthetic file) as it is scanned |

---

## Install & run

```bash
cd vulnscan
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt   # or: pip install -e .
export ANTHROPIC_API_KEY="…"
```

**Scan a repo** (verbose: print each file as it is scanned):

```bash
python3 main.py scan /path/to/vulnado -v -o report.json
# legacy: python3 main.py /path/to/repo -o report.json
```

**Install CLI entry point:** `pip install -e .` then run **`vulnscan scan …`** from any directory.

**Pre-commit:** see `contrib/pre-commit-config.example.yaml`.

**Tests** (no API):

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

### Batch eval (`eval_pipeline.py`)

Full-grid adversarial generation + scanning + four comment variants (writes **`eval_results_raw.json`** after **each** sample, then **`eval_results_summary.json`**). The module is listed in **`pyproject.toml`** (`eval_pipeline`) so `pip install -e .` includes it.

**Cost / model:** The eval pipeline defaults to **`claude-haiku-4-5-20251001`** (override with `--model`). For synthetic vulnerable code plus scanning, Haiku is usually sufficient and is dramatically cheaper than Sonnet-class models at similar token volumes. Default grid is `8×3×3×samples_per_combo` with **`--samples-per-combo` defaulting to 1** → **72** samples for a full run (use `2` if you want paired repetitions). Each sample does **phase2 + 4 phase3** scans; **`scan_file` calls the API once per chunk**, not once per file — so “samples × 5” is only a **lower** bound. **`--dry-run`** generates code and writes **`dry_run_chunk_counts`** / **`dry_run_estimated_scanner_api_calls`** per record plus an aggregate hint at the end.

**Smoke grid (18 samples):** `data/eval_manifest_smoke_18.json` limits classes to **sql_injection** and **command_injection** across all tiers and languages — run this (optionally with `--dry-run`) before the full 72-sample grid.

**Resume:** **`--resume`** skips combo keys already present in **`eval_results_raw.json`**, so you can interrupt and continue without redoing finished samples.

**Limitation:** `misleading_name` uses a fragile first-`def foo(` → `def safe_query(` heuristic (no class methods, lambdas, etc.); treat as exploratory.

```bash
# 18-sample wiring check (chunk estimate only)
python3 eval_pipeline.py --manifest data/eval_manifest_smoke_18.json --dry-run

# Full default grid (72 samples), real scans
python3 eval_pipeline.py --delay 1.5

# Resume after interrupt
python3 eval_pipeline.py --resume --delay 1.5
```

`--manifest` accepts `{"combinations":[{"vulnerability_class":"sql_injection","obfuscation_tier":"obvious","language":"python"}]}` or a JSON array of those objects.

---

## Citation

If you use **vulnscan**, please cite this repository. If you discuss the April 9 **Semantic Cliff** foundation, cite Kevin Lira's preprint separately.

```bibtex
@software{hooker2026vulnscan,
  title  = {vulnscan: LLM-assisted vulnerability scanning and adversarial evaluation},
  author = {Hooker, Remley},
  year   = {2026},
  month  = apr,
  note   = {Software and research artifact.},
  url    = {https://github.com/remleyhooker/vulnscan}
}
```

**APA-style (plain text):** Hooker, R. (2026). *vulnscan: LLM-assisted vulnerability scanning and adversarial evaluation* [Software]. https://github.com/remleyhooker/vulnscan

---

## Ethics

Synthetic vulnerable code is for **evaluation and education** only. Only scan systems you are authorized to test. LLM output is not a substitute for professional security review.
