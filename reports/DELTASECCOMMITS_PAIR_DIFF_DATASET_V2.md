# DeltaSecommits Pair-Diff Dataset

This report materializes a second paired vulnerable/fixed patch source for cross-dataset validation.
Rows are converted into the same candidate-vs-counterpart diff contract used by the PrimeVul paired-diff line.

## Source

- Hugging Face dataset: `rufimelo/DeltaSecommits`
- License: `MIT`
- Selected extensions: `c, cc, cpp`
- Selected pairs: `1634`
- Pair rows: `3268`
- Unique projects: `280`
- Unique vulnerabilities: `1560`

## Split

| Split | Rows | Safe | Vulnerable | Pair Keys |
| --- | ---: | ---: | ---: | ---: |
| train | `2614` | `1307` | `1307` | `1307` |
| eval | `654` | `327` | `327` | `327` |

## Prompt Length

- p50: `862` characters
- p90: `2560` characters
- max: `22052` characters

## Changed-Line Buckets

```json
{
  "00-02": 994,
  "03-05": 858,
  "06-10": 655,
  "11-25": 509,
  "26+": 252
}
```

## Interpretation

DeltaSecommits is a good second-source stress target because it is much shorter than PrimeVul, uses paired pre/post-fix snapshots, and comes from a different curation pipeline. The first use should be zero-shot transfer from the PrimeVul paired-diff detector before training a Delta-specific model.
