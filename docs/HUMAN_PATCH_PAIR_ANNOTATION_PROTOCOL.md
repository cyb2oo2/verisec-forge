# Human Patch-Pair Annotation Protocol

## Goal

Create a small, clean evidence-grounded evaluation set of `100-200` vulnerable/fixed patch pairs. The default study samples `150` unique pairs and assigns every pair independently to two annotators.

AI-filled labels must not be copied into the annotation sheets. They may only be used after annotation for error analysis and adjudication prioritization.

## Independent Annotation Fields

Each annotator records:

- `vulnerable_side`: `A`, `B`, `neither`, or `unclear`
- `root_cause`: one concise security-mechanism description
- `minimal_evidence_lines`: the smallest side-prefixed line span that supports the decision
- `context_sufficient`: `yes`, `no`, or `unclear`
- `confidence`: `1-5`
- `notes`: optional ambiguity or dependency information

Annotators receive randomized case order and randomized A/B side assignment. Project, CVE, CWE, benchmark label, model probability, and model decision are excluded from the review packet.

## Sampling

The default sampler draws from five strata:

- model pair errors
- low-margin pairs
- high-confidence pairs
- large patches
- ordinary controls

This is a high-value audit set, not a prevalence estimate for the full benchmark.

## Agreement And Adjudication

Report:

- exact vulnerable-side agreement
- Cohen's kappa for vulnerable-side choice
- exact context-sufficiency agreement
- Cohen's kappa for context sufficiency
- disagreement count and disagreement taxonomy

All side or context disagreements must be adjudicated by a third reviewer or a documented consensus meeting. Root-cause and minimal-line agreement should additionally be reviewed qualitatively because free-text spans are not well summarized by kappa alone.

## Commands

```powershell
.\.venv\Scripts\python.exe scripts\build_pair_annotation_study.py --sample-size 150
.\.venv\Scripts\python.exe scripts\analyze_pair_annotation_agreement.py
```

The annotation packets are written under `data/annotation/`, which is intentionally not published until licensing and privacy checks are complete.
