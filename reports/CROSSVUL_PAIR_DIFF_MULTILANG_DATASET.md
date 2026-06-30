# CrossVul Multi-Language Pair-Diff Dataset

This report materializes the PHP/JavaScript/Python/Java subset of CrossVul (see
`reports/CROSSVUL_PAIR_DIFF_DATASET.md` for the C/C++ subset) for the language-shift stress
test in `reports/CROSSVUL_LANGUAGE_SHIFT_COMPARISON.md`. CrossVul rows already ship as direct
vulnerable/fixed code pairs, so no func-list stitching is needed.

This dataset is eval-only. It is not used for training; existing C/C++-only-trained
paired-diff checkpoints are evaluated zero-shot against it.

## Source

- Raw file: `data/raw/crossvul_train_raw.jsonl`
- Languages: `java, javascript, php, python`
- Input examples scanned: `3780`
- Selected pairs: `3780`
- Pair rows: `7560`

## Labels

- Safe: `3780`
- Vulnerable: `3780`
- Pair keys: `3780`

## Languages

```json
{
  "java": 978,
  "javascript": 1320,
  "php": 4278,
  "python": 984
}
```

## Changed-Line Buckets

```json
{
  "00-02": 2148,
  "03-05": 1496,
  "06-10": 1347,
  "11-25": 1398,
  "26+": 1171
}
```

## Interpretation

This subset isolates language shift from the source shift already tested in
`reports/CROSSVUL_ZERO_SHOT_PRIMEVUL_CHECKPOINT.md` and
`reports/CROSSVUL_ZERO_SHOT_MATCHED_MIXED_CHECKPOINT.md`: it is the same CrossVul source,
restricted to four languages neither existing checkpoint was trained on, rather than
C/C++. See `reports/CROSSVUL_LANGUAGE_SHIFT_COMPARISON.md` for results and interpretation.
