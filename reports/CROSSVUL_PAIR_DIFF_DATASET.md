# CrossVul Pair-Diff Dataset

This report materializes a fourth paired vulnerable/fixed patch source, never previously
used in this repository, for a genuine open-set source-shift stress test. CrossVul rows already
ship as direct vulnerable/fixed code pairs, so no func-list stitching is needed.

This dataset is eval-only. It is not used for training; the existing PrimeVul-trained
paired-diff detector is evaluated zero-shot against it.

## Source

- Raw file: `data/raw/crossvul_train_raw.jsonl`
- Languages: `c, cpp`
- Input examples scanned: `4371`
- Selected pairs: `4371`
- Pair rows: `8742`

## Labels

- Safe: `4371`
- Vulnerable: `4371`
- Pair keys: `4371`

## Languages

```json
{
  "c": 7944,
  "cpp": 798
}
```

## Changed-Line Buckets

```json
{
  "00-02": 2263,
  "03-05": 1893,
  "06-10": 1758,
  "11-25": 1637,
  "26+": 1191
}
```

## Interpretation

CrossVul is a source the existing PrimeVul/DeltaSecommits/PatchEval-trained detector has
never seen in training or development. It is restricted to C/C++ here to isolate a genuine
open-set *source* shift from a confounded language shift; CrossVul also covers many other
languages (PHP, JavaScript, Python, Java, ...) not used here, which remains a separate,
not-yet-run language-shift stress test for future work.
