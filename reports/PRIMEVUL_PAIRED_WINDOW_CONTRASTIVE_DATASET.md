# PrimeVul Paired-Window Contrastive Dataset

This artifact converts pair-coupled predictions plus hunk/window candidates into model-ready pair-level contrastive examples. It is a dataset-building step for the next side-correction model, not a performance claim.

## Summary

- Pair groups seen: `614`
- Contrastive rows: `592`
- Label A / B rows: `509` / `83`
- Current high-probability-side orientation accuracy: `0.8598`
- High-gap orientation inversion pairs (`gap >= 0.5`): `44`
- Average probability gap: `0.6884`
- Average prompt chars: `2102.1402`
- Missing window sides: `0`

## Why This Exists

The previous shallow pair-side gates were flat across multiple pair-key splits. This dataset moves the next step from manual aggregate features to an explicit paired-window comparison task: given the high-probability side and low-probability side, learn whether the current orientation should be trusted or inverted.

## Important Boundary

Rows are derived from pseudo-label hunk/window candidates and current pair-coupled predictions. They should be used for calibration, hard-negative mining, or a held-out pair-key split experiment, not reported as independent human evidence-span supervision.

## Top Buckets

| changed_line_bucket | pairs |
| --- | ---: |
| 03-05 | 157 |
| 00-02 | 156 |
| 06-10 | 133 |
| 11-25 | 92 |
| 26+ | 54 |

## Top Vulnerability Types

| type | pairs |
| --- | ---: |
