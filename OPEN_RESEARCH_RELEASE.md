# Open Research Release Checklist

This checklist packages the project for OpenReview Archive, arXiv-style artifact links, or public repo release.

## 1) Final Artifacts To Include

- `paper.tex`
- `runs/aggregate_50_all_llm.json`
- `runs/aggregate_50_all_llm.csv`
- `runs/results_semantic_cliff_llm.png`
- `runs/mta_50/multi_turn_manifest.json`
- `runs/ctx_50_llm/context_isolation_manifest.json`
- `runs/comment_suppress_50/comment_suppression_manifest.json`
- `runs/scanner_poison_50/scanner_poison_manifest.json`

## 2) Reproducibility Metadata

Include in paper or README:

- Model names and versions:
  - Anthropic: `claude-haiku-4-5-20251001`
  - Groq baseline in cross-model arm as used in your runs
- Sample counts per experiment (`N=50`)
- Prompt families used (scanner + summarizer)
- Aggregation flags (`--exclude-errors --exclude-confounds`)

## 3) Compile the Paper

From `vulnscan/`:

```bash
pdflatex paper.tex
pdflatex paper.tex
```

If bibliography tooling is added later:

```bash
pdflatex paper.tex
bibtex paper
pdflatex paper.tex
pdflatex paper.tex
```

## 4) Sanity Checks Before Upload

```bash
python3 -m py_compile context_isolation.py aggregate_research_results.py plot_semantic_cliff.py
python3 aggregate_research_results.py --manifests runs/mta_50/multi_turn_manifest.json runs/ctx_50_llm/context_isolation_manifest.json runs/comment_suppress_50/comment_suppression_manifest.json runs/scanner_poison_50/scanner_poison_manifest.json --exclude-errors --exclude-confounds --out runs/quick_release_check.json
```

Confirm:

- Paper references the same numbers as aggregate JSON.
- Figure file path in LaTeX exists.
- No API keys in any tracked files.

## 5) OpenReview Archive Upload (Fast Path)

1. Export `paper.pdf`.
2. Create a zip with:
   - source (`paper.tex`)
   - figure(s)
   - aggregated JSON/CSV
   - manifests
3. Upload PDF + artifact link (repo or storage).
4. In abstract/notes, disclose:
   - synthetic-code setting
   - class-level sample counts
   - model/version constraints

## 6) Suggested Release Note Text

> We release the full manifest-level outputs, aggregation scripts, and LaTeX source for reproducibility. The study evaluates context compression effects on LLM vulnerability detection with class-level stratification and paired comment-manipulation controls.

