# PrimeVul Main Results

This table is generated from run artifacts by `scripts/build_primevul_main_results.py`.

## Summary

![PrimeVul paired benchmark results](assets/primevul_main_results.svg)

- Headline: PrimeVul paired diff reasoning is the strongest current formulation.
- Diff-only dedup multi-seed balanced accuracy mean: `0.8287`
- Diff-only dedup multi-seed range: `0.8158-0.8382`
- Edge-focus multi-seed balanced accuracy mean: `0.8246`
- Edge-focus multi-seed range: `0.8164-0.8348`
- Strongest negative-control balanced accuracy: `0.5156`

## Main Table

| System | Threshold | Accuracy | Recall | Specificity | Precision | F1 | Balanced Accuracy | Note |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| same-source detector | 0.5000 | 0.9524 | 0.9709 | 0.9339 | 0.9363 | 0.9533 | 0.9524 | artifact-sensitive same-source holdout |
| same-source detector on paired eval | 0.9999 | 0.4961 | 0.1922 | 0.8000 | 0.4901 | 0.2761 | 0.4961 | fails paired specificity |
| paired-trained snippet detector | 0.6000 | 0.5072 | 0.3989 | 0.6156 | 0.5092 | 0.4474 | 0.5072 | near chance on paired snippets |
| metadata-only control | 0.5000 | 0.5022 | 0.6644 | 0.3400 | 0.5017 | 0.5717 | 0.5022 | negative control |
| candidate-only control | 0.2000 | 0.5078 | 0.8989 | 0.1167 | 0.5044 | 0.6462 | 0.5078 | negative control |
| counterpart-only control | 0.7000 | 0.5156 | 0.2011 | 0.8300 | 0.5419 | 0.2934 | 0.5156 | negative control |
| pair-context detector | 0.4000 | 0.6061 | 0.6589 | 0.5533 | 0.5960 | 0.6259 | 0.6061 | explicit comparison helps |
| candidate+diff detector | 0.5000 | 0.6728 | 0.7178 | 0.6278 | 0.6585 | 0.6869 | 0.6728 | extra context dilutes patch signal |
| diff-only detector | 0.6000 | 0.8156 | 0.8022 | 0.8289 | 0.8242 | 0.8131 | 0.8156 | best original paired formulation |
| diff-only detector, dedup eval | 0.6000 | 0.8158 | 0.8022 | 0.8294 | 0.8243 | 0.8131 | 0.8158 | removes 8 exact/near-duplicate eval rows |
| diff-only detector, no metadata | 0.8000 | 0.8244 | 0.7533 | 0.8956 | 0.8782 | 0.8110 | 0.8244 | removes Project/CVE/CWE prompt metadata |
| diff-only checkpoint on localized eval | 0.9000 | 0.7980 | 0.8693 | 0.7269 | 0.7605 | 0.8113 | 0.7981 | input-compression transfer check |
| localized-diff detector | 0.6000 | 0.8298 | 0.8056 | 0.8540 | 0.8462 | 0.8254 | 0.8298 | hunk-localized diff training |
| contrastive-window detector | 0.4000 | 0.8270 | 0.8525 | 0.8016 | 0.8108 | 0.8312 | 0.8270 | counterpart-vs-candidate changed windows |
| direction-aware window detector | 0.5000 | 0.8225 | 0.8268 | 0.8183 | 0.8195 | 0.8231 | 0.8225 | same-template operation-direction windows |
| direction-aware recall-recovery detector | 0.5000 | 0.8181 | 0.7732 | 0.8629 | 0.8491 | 0.8094 | 0.8180 | 26+ vulnerable oversampling with safe anchors |
| direction-aware bucket router | 0.8000 | 0.8231 | 0.8291 | 0.8172 | 0.8190 | 0.8240 | 0.8231 | routes 26+ rows to recall-recovery v1 |
| diff-only detector, edge-focus | 0.5000 | 0.8348 | 0.7966 | 0.8729 | 0.8622 | 0.8281 | 0.8348 | targets 00-02 and 26+ changed-line buckets; single seed |
| diff-only detector, edge-focus seed7 | 0.5000 | 0.8164 | 0.8179 | 0.8149 | 0.8151 | 0.8165 | 0.8164 | edge-focus multi-seed check |
| diff-only detector, edge-focus seed99 | 0.4000 | 0.8225 | 0.8492 | 0.7960 | 0.8059 | 0.8270 | 0.8226 | edge-focus multi-seed check |
| diff-only detector, seed7 dedup | 0.5000 | 0.8382 | 0.8291 | 0.8473 | 0.8441 | 0.8365 | 0.8382 | multi-seed stability |
| diff-only detector, seed99 dedup | 0.5000 | 0.8320 | 0.8503 | 0.8138 | 0.8200 | 0.8349 | 0.8321 | multi-seed stability |
