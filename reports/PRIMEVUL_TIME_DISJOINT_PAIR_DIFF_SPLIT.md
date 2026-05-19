# PrimeVul Time-Disjoint Pair-Diff Split

This report constructs a true time-disjoint paired-diff dataset from the full PrimeVul paired metadata.
It is a dataset-construction artifact: no model is trained or evaluated here yet.

## Protocol

- Train: `cve_year <= 2020`
- Eval: `cve_year >= 2021`
- Text mode: `diff_only`
- Seed: `20260519`

## Selected Split

| Split | Rows | Safe | Vulnerable | Pair Keys | Projects | CVEs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| train | `6000` | `3000` | `3000` | `3472` | `554` | `3179` |
| eval | `1562` | `781` | `781` | `761` | `187` | `713` |

## Overlap Checks

- CVE year overlap: `[]`
- CVE overlap: `0`
- Pair-key overlap: `0`
- Project overlap: `100`

## Interpretation

This split is stricter than filtering the old eval slice because it rebuilds train/eval by CVE year from the full paired metadata. It still allows project overlap, so it is a time-disjoint stress target rather than a fully project-disjoint external dataset.
