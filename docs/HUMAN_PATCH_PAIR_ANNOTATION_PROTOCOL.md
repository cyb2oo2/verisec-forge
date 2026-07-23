# Human Patch-Pair Annotation Protocol

## Goal

Create a small, clean evidence-grounded **audit** set of vulnerable/fixed patch pairs for evidence-coupled analysis.

**Active default study:** single-author stratified **50** pairs (`primevul_pair_study_author50_v1`, seed `20260720`).

A larger dual-independent design (up to 150 pairs, two annotators, Cohen’s κ) remains implementable via `--mode dual_independent` but is **not** the active paper-facing protocol.

AI-filled labels must not be copied into the annotation sheet. AI may only support post-hoc prioritization, never gold.

## Status checklist

| Gate | Meaning |
| --- | --- |
| **Engineering scaffold** | Stratified sample, blinded packet, empty answers CSV, private mapping, status tools |
| **Author-complete** | Required fields filled for a case |
| **Study complete (active)** | 50/50 author-complete rows |
| **Not claimed** | Inter-annotator κ; dual-rater consensus gold; prevalence; AI pilot as human gold |

## Annotation fields

- `vulnerable_side`: `A`, `B`, `neither`, or `unclear`
- `root_cause`: concise security-mechanism description
- `minimal_evidence_lines`: smallest side-prefixed span (e.g. `A:12-15;B:8`)
- `context_sufficient`: `yes`, `no`, or `unclear`
- `confidence`: `1-5`
- `notes`: optional

Packet presentation: randomized case order, randomized A/B assignment, Project/CVE/CWE scrubbed from diff text. Private mapping is staff-only (and should not be consulted during labeling).

## Sampling

Five strata (same rules as before):

- model pair errors  
- low-margin pairs  
- high-confidence pairs  
- large patches  
- ordinary controls  

Target ≈ equal stratum quotas then fill to exact `sample_size`. This is a **high-value audit set**, not a prevalence estimate.

## Single-author vs dual-independent

| | Single-author (active) | Dual-independent (optional) |
| --- | --- | --- |
| n (default) | 50 | 150 |
| Files | `annotator_packet.jsonl`, `annotator_answers.csv` | `annotator_{1,2}_*` |
| Reliability | No second rater; **no κ** | Exact agreement + Cohen’s κ; adjudicate disagreements |
| Paper use | Qualitative audit / error analysis | Stronger human-gold claim if completed |

## Claim boundary (paper)

Use this statement (also embedded in status JSON as `paper_claim_boundary_statement`):

> The human pair audit is a stratified 50-pair single-author annotation under blinded packet presentation (metadata scrubbed; sides randomized). It supports qualitative evidence-coupled error analysis and author-facing case review. It is not independent dual-rater gold, does not report inter-annotator Cohen's κ, is not a prevalence estimate for PrimeVul, is not AI pilot labeling, and must not be promoted as a model-quality benchmark or replacement for the pair-coupled decoding mainline metrics.

**Human gold ≠ AI pilot.** Author labels ≠ dual independent gold.

## Commands

```powershell
# Build active study (50 pairs, seed 20260720, single author)
.\.venv\Scripts\python.exe scripts\build_pair_annotation_study.py `
  --sample-size 50 --seed 20260720 --mode single_author

# Annotator tools — Streamlit UI (recommended)
.\.venv\Scripts\python.exe -m pip install streamlit
.\.venv\Scripts\python.exe -m streamlit run scripts\annotation_tool.py

# Annotator tools — CLI helpers
.\.venv\Scripts\python.exe scripts\export_pair_annotation_review_sheets.py
.\.venv\Scripts\python.exe scripts\validate_pair_annotation_answers.py
.\.venv\Scripts\python.exe scripts\check_pair_annotation_study_status.py
```

Annotator guide: `docs/PAIR_ANNOTATION_ANNOTATOR_GUIDE.md`.

Packets live under `data/annotation/` and are not published until licensing/privacy review.
