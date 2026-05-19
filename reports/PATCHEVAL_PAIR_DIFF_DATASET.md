# PatchEval Pair-Diff Dataset

This report materializes a third paired vulnerable/fixed patch source for cross-dataset validation.

## Source

- Hugging Face dataset: `ByteDance/PatchEval`
- License: `Apache-2.0`
- Selected pairs: `1344`
- Pair rows: `2688`

## Split

| Split | Rows | Safe | Vulnerable | Pair Keys |
| --- | ---: | ---: | ---: | ---: |
| train | `2150` | `1075` | `1075` | `1075` |
| eval | `538` | `269` | `269` | `269` |

## Languages

```json
{
  "Go": 874,
  "JavaScript": 730,
  "Python": 1084
}
```

## Interpretation

PatchEval is a stronger third-source stress target because it covers Python, JavaScript, and Go repair examples rather than the C/C++-heavy setting used by DeltaSecommits.
