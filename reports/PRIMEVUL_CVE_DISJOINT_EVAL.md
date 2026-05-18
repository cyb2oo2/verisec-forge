# PrimeVul CVE-Disjoint Evaluation

This stress evaluation removes every eval row whose CVE appears in the paired-diff training metadata.
It is an external-generalization check over unseen CVE identifiers, not a newly trained model.

## Split

- Train unique CVEs: `2141`
- Eval rows before filter: `1792`
- Eval rows after filter: `1703`
- Removed overlap rows: `89`
- CVE overlap after filter: `0`

## Results

| System | Balanced Accuracy | Recall | Specificity | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `diff_only` | `0.8168` | `0.8298` | `0.8038` | `0.8192` | `0.6976` | `0.848` |
| `pair_coupled` | `0.8491` | `0.8357` | `0.8625` | `0.8471` | `0.8205` | `0.848` |

## Delta

- Pair-coupled minus diff-only balanced accuracy: `0.0323`
- Pair-coupled minus diff-only group all-correct: `0.1229`
- Pair-coupled minus diff-only orientation accuracy: `0.0`

## Interpretation

If this remains close to the normal paired-diff result, the mainline is less likely to depend on repeated CVE identifiers. If it drops sharply, CVE-level generalization becomes the next bottleneck.
