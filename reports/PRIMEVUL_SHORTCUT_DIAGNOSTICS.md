# PrimeVul Shortcut Diagnostics

The current `PrimeVul` detector-only result is numerically correct, but it should be treated as an artifact-sensitive same-source result until harder splits are built.

## Current Detector Result

Measured on `secure_code_primevul_holdout_eval_balanced_2000_metadata.jsonl` with the existing detector probabilities:

| System | Accuracy | Recall | Specificity | Precision | F1 | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| detector-only | 0.9524 | 0.9709 | 0.9339 | 0.9363 | 0.9533 | 867 | 834 | 59 | 26 |

The metric arithmetic is correct, but the benchmark distribution contains strong shortcut signals.

## Shortcut Baselines

These baselines are fit on `secure_code_primevul_train_balanced_presence_3000_metadata.jsonl` and evaluated on the holdout.

| Baseline | Accuracy | Recall | Specificity | Precision | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| length threshold | 0.6859 | 0.8320 | 0.5398 | 0.6438 | 0.7259 |
| project majority | 0.8096 | 0.9765 | 0.6428 | 0.7322 | 0.8369 |
| CWE majority | 0.5274 | 0.7906 | 0.2643 | 0.5180 | 0.6259 |
| CVE majority | 0.5728 | 0.9888 | 0.1568 | 0.5397 | 0.6983 |
| file-name majority | 0.5918 | 0.9899 | 0.1937 | 0.5511 | 0.7080 |

## Length Distribution

| Split | Label | Count | Median Code Chars | P90 Code Chars |
| --- | --- | ---: | ---: | ---: |
| train | vulnerable | 1500 | 1844 | 11179 |
| train | safe | 1500 | 325 | 1722 |
| holdout | vulnerable | 893 | 1677 | 9346 |
| holdout | safe | 893 | 504 | 2449 |

## Harder Split Progress

The repository now includes a reusable split builder:

```powershell
python scripts\build_primevul_harder_splits.py --help
```

It currently supports:

- `project_disjoint`: filters out evaluation rows whose `project` was seen in the training reference.
- `paired_eval`: builds a balanced evaluation subset from official `primevul_*_paired.jsonl` files.

### Project-Disjoint Feasibility Check

Using the current 6k normalized PrimeVul pool, strict project-disjoint balanced evaluation is not feasible yet:

| Candidate Set | Vulnerable | Safe | Total |
| --- | ---: | ---: | ---: |
| eval candidates | 122 | 878 | 1000 |
| project-known candidates | 122 | 878 | 1000 |
| project-disjoint candidates | 97 | 0 | 97 |
| selected balanced eval | 0 | 0 | 0 |

Interpretation: under this sampled pool, every safe evaluation example belongs to a project already observed in the training reference. This makes a strict balanced project-disjoint split impossible without rebuilding from a broader raw PrimeVul pool or changing the sampling policy.

### Paired Evaluation Shortcut Check

The official paired data gives a much cleaner sanity check because vulnerable and fixed examples are naturally matched. We normalized `primevul_train_paired`, `primevul_valid_paired`, and `primevul_test_paired`, then sampled a balanced 1800-row paired eval set.

| Split | Label | Count | Median Code Chars | P90 Code Chars |
| --- | --- | ---: | ---: | ---: |
| paired train | vulnerable | 4704 | 2088.5 | 11372 |
| paired train | safe | 4704 | 2252.0 | 11586 |
| paired eval | vulnerable | 900 | 2209.0 | 10242 |
| paired eval | safe | 900 | 2309.0 | 10462 |

Shortcut baselines fit on paired train and evaluated on paired eval:

| Baseline | Accuracy | Recall | Specificity | Precision | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| length threshold | 0.5200 | 0.3211 | 0.7189 | 0.5332 | 0.4008 |
| project majority | 0.5000 | 0.8589 | 0.1411 | 0.5000 | 0.6321 |
| CWE majority | 0.4989 | 0.7244 | 0.2733 | 0.4992 | 0.5911 |
| CVE majority | 0.5011 | 1.0000 | 0.0022 | 0.5006 | 0.6672 |
| file-name majority | 0.5122 | 0.8022 | 0.2222 | 0.5077 | 0.6219 |

Existing detector checkpoint evaluated with the eval-only classifier entry point:

| Eval Split | Accuracy | Recall | Specificity | Precision | F1 | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| same-source holdout2000 | 0.9524 | 0.9709 | 0.9339 | 0.9363 | 0.9533 | 867 | 834 | 59 | 26 |
| paired eval1800 | 0.4933 | 0.9756 | 0.0111 | 0.4966 | 0.6579 | 878 | 10 | 890 | 22 |

Threshold sweep over the paired predictions confirms that this is not a simple calibration issue:

| Selection | Threshold | Accuracy | Recall | Specificity | Precision | F1 | Balanced Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| default | 0.5000 | 0.4933 | 0.9756 | 0.0111 | 0.4966 | 0.6582 | 0.4933 |
| best balanced accuracy | 0.9999 | 0.4961 | 0.1922 | 0.8000 | 0.4901 | 0.2761 | 0.4961 |

Probability distribution by gold label on paired eval:

| Gold Label | Count | Min | P10 | P50 | P90 | P99 | Max | Mean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vulnerable | 900 | 0.0084 | 0.9247 | 0.9982 | 1.0000 | 1.0000 | 1.0000 | 0.9585 |
| safe/fixed | 900 | 0.0362 | 0.9392 | 0.9985 | 1.0000 | 1.0000 | 1.0000 | 0.9701 |

Interpretation: paired evaluation largely removes the most suspicious length shortcut. Project and metadata majority baselines collapse to chance accuracy, although recall-heavy metadata shortcuts can still inflate F1. The detector itself does not survive this shift: it keeps high vulnerable recall but loses nearly all safe specificity. The probability distribution is nearly saturated for both labels, so threshold tuning cannot repair it. This is strong evidence that the 0.95 same-source result was dominated by dataset artifacts or split-specific cues rather than robust semantic vulnerability detection.

## Interpretation

- The detector result is not a simple evaluation arithmetic bug.
- Exact ID matching and basic overlap checks are not enough to validate it.
- Project identity alone is highly predictive, reaching `F1 = 0.8369`.
- Code length is also predictive, reaching `F1 = 0.7259`.
- Therefore the safe claim is that the result is a `PrimeVul same-source / artifact-sensitive presence detector` result, not yet a robust semantic vulnerability-detection result.

## Required Next Splits

- Rebuild `project-disjoint` evaluation from a broader raw PrimeVul pool; the current 6k sampled pool has no project-disjoint safe examples.
- Build `CVE-disjoint` evaluation.
- Build `commit-disjoint` evaluation.
- Train or calibrate a detector directly against paired/hard-negative data and report both same-source and paired results.
- Require every headline detector report to include shortcut baselines.

The detector may still be learning useful security signal, but this benchmark is currently too shortcut-rich to support a strong external claim by itself.

## Pending Negative Controls

Two additional paired controls are now materialized as first-class run inputs:

| Control | Train Dataset | Eval Dataset | Config |
| --- | --- | --- | --- |
| metadata-only | `data/processed/secure_code_primevul_pair_metadata_only_train_balanced_3000_metadata.jsonl` | `data/processed/secure_code_primevul_pair_metadata_only_eval_balanced_1800_metadata.jsonl` | `configs/cls_secure_code_primevul_qwen15bcoder_lora_pair_metadata_only_3000_v1.json` |
| counterpart-only | `data/processed/secure_code_primevul_pair_counterpart_only_train_balanced_3000_metadata.jsonl` | `data/processed/secure_code_primevul_pair_counterpart_only_eval_balanced_1800_metadata.jsonl` | `configs/cls_secure_code_primevul_qwen15bcoder_lora_pair_counterpart_only_3000_v1.json` |

Both controls use `text_field = "pair_text"`. The JSONL rows intentionally preserve raw `code` and `prompt` fields for traceability, but the classifier training script reads only `pair_text`; therefore the metadata-only control exposes no code text to the model, and the counterpart-only control exposes only the paired counterpart body plus metadata.

After training, both controls stayed near chance:

| Control | Threshold | Accuracy | Recall | Specificity | Precision | F1 | Balanced Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| metadata-only control | 0.5000 | 0.5022 | 0.6644 | 0.3400 | 0.5017 | 0.5717 | 0.5022 |
| metadata-only control, best balanced | 0.5000 | 0.5022 | 0.6644 | 0.3400 | 0.5017 | 0.5717 | 0.5022 |
| counterpart-only control | 0.5000 | 0.5028 | 0.3911 | 0.6144 | 0.5036 | 0.4403 | 0.5028 |
| counterpart-only control, best balanced | 0.7000 | 0.5156 | 0.2011 | 0.8300 | 0.5419 | 0.2934 | 0.5156 |

Interpretation: these controls make the diff-only result much harder to dismiss as an obvious shortcut. Metadata alone cannot predict the paired label, and the paired counterpart alone is also almost uninformative. The strong diff-only result therefore appears to come from the candidate-vs-counterpart edit signal rather than from CVE/CWE/project metadata or one side of the pair in isolation.

## Train/Eval Diff Overlap Check

We added a dedicated paired-overlap diagnostic:

```powershell
python scripts\check_primevul_pair_overlap.py --help
```

On the diff-only train/eval split, the script found:

| Check | Result |
| --- | ---: |
| train rows | 3000 |
| eval rows | 1800 |
| exact ID overlap | 0 |
| pair counterpart ID overlap | 0 |
| function hash overlap | 0 |
| shared pair keys | 1 |
| exact pair-text overlaps | 2 |
| exact normalized-diff overlaps | 7 |
| shared-pair-key near-duplicate diff matches at `0.95` | 1 |
| risky eval rows removed by dedup filter | 8 |

The filtered eval set is `data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl`.

Diff-only remains stable after removing the flagged rows:

| Eval Set | Threshold | Accuracy | Recall | Specificity | Precision | F1 | Balanced Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| original eval1800 | 0.6000 | 0.8156 | 0.8022 | 0.8289 | 0.8242 | 0.8131 | 0.8156 |
| dedup eval1792 | 0.6000 | 0.8158 | 0.8022 | 0.8294 | 0.8243 | 0.8131 | 0.8158 |

Interpretation: the overlap check found a small number of suspicious duplicated or near-duplicated diff rows, so the original split was not perfectly clean. However, removing those rows does not reduce the diff-only result. This strongly suggests that the `0.8156` result is not driven by the detected exact/near-duplicate leakage.

## Diff-Only Multi-Seed Stability

After adding explicit seed support to the classifier training entry point, we repeated diff-only training on the same 3000-row training set and evaluated each run on the deduplicated 1792-row eval set.

| Run | Seed | Best Threshold | Accuracy | Recall | Specificity | Precision | F1 | Balanced Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| diff-only original, dedup eval | 42 | 0.6000 | 0.8158 | 0.8022 | 0.8294 | 0.8243 | 0.8131 | 0.8158 |
| diff-only seed7, dedup eval | 7 | 0.5000 | 0.8382 | 0.8291 | 0.8473 | 0.8441 | 0.8365 | 0.8382 |
| diff-only seed99, dedup eval | 99 | 0.5000 | 0.8320 | 0.8503 | 0.8138 | 0.8200 | 0.8349 | 0.8321 |

Summary:

| Metric | Value |
| --- | ---: |
| balanced accuracy mean | 0.8287 |
| balanced accuracy min | 0.8158 |
| balanced accuracy max | 0.8382 |
| balanced accuracy range | 0.0224 |

Interpretation: the diff-only result is stable across the tested seeds. The strongest safe claim is no longer a single `0.8156` checkpoint, but a reproducible `0.82-0.84` balanced-accuracy operating band on the deduplicated paired eval split.

## Paired-Training Follow-Up

We trained a first paired-only detector on `secure_code_primevul_paired_train_balanced_3000_metadata.jsonl` and evaluated it on `secure_code_primevul_paired_eval_balanced_1800_metadata.jsonl`.

The compact generated version of this result family is available in `reports/PRIMEVUL_MAIN_RESULTS.md` and `reports/PRIMEVUL_MAIN_RESULTS.json`.

| Model | Threshold | Accuracy | Recall | Specificity | Precision | F1 | Balanced Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| same-source detector on paired eval | 0.5000 | 0.4933 | 0.9756 | 0.0111 | 0.4966 | 0.6582 | 0.4933 |
| paired-trained detector | 0.5000 | 0.4978 | 0.5522 | 0.4433 | 0.4980 | 0.5237 | 0.4978 |
| paired-trained detector, best balanced | 0.6000 | 0.5072 | 0.3989 | 0.6156 | 0.5092 | 0.4474 | 0.5072 |
| metadata-only control | 0.5000 | 0.5022 | 0.6644 | 0.3400 | 0.5017 | 0.5717 | 0.5022 |
| metadata-only control, best balanced | 0.5000 | 0.5022 | 0.6644 | 0.3400 | 0.5017 | 0.5717 | 0.5022 |
| candidate-only control | 0.5000 | 0.5044 | 0.4778 | 0.5311 | 0.5047 | 0.4909 | 0.5044 |
| candidate-only control, best balanced | 0.2000 | 0.5078 | 0.8989 | 0.1167 | 0.5044 | 0.6462 | 0.5078 |
| counterpart-only control | 0.5000 | 0.5028 | 0.3911 | 0.6144 | 0.5036 | 0.4403 | 0.5028 |
| counterpart-only control, best balanced | 0.7000 | 0.5156 | 0.2011 | 0.8300 | 0.5419 | 0.2934 | 0.5156 |
| pair-context detector | 0.5000 | 0.5983 | 0.5833 | 0.6133 | 0.6014 | 0.5922 | 0.5983 |
| pair-context detector, best balanced | 0.4000 | 0.6061 | 0.6589 | 0.5533 | 0.5960 | 0.6259 | 0.6061 |
| pair-context detector, best F1 | 0.1000 | 0.5978 | 0.8378 | 0.3578 | 0.5661 | 0.6756 | 0.5978 |
| candidate+diff detector | 0.5000 | 0.6733 | 0.7178 | 0.6289 | 0.6592 | 0.6872 | 0.6733 |
| candidate+diff detector, best balanced | 0.5000 | 0.6728 | 0.7178 | 0.6278 | 0.6585 | 0.6869 | 0.6728 |
| candidate+diff detector, best F1 | 0.1000 | 0.6494 | 0.9000 | 0.3989 | 0.5996 | 0.7197 | 0.6494 |
| diff-only detector | 0.5000 | 0.8156 | 0.8311 | 0.8000 | 0.8060 | 0.8184 | 0.8156 |
| diff-only detector, best balanced | 0.6000 | 0.8156 | 0.8022 | 0.8289 | 0.8242 | 0.8131 | 0.8156 |
| diff-only detector, best F1 | 0.5000 | 0.8133 | 0.8311 | 0.7956 | 0.8026 | 0.8166 | 0.8133 |
| diff-only detector, dedup best balanced | 0.6000 | 0.8158 | 0.8022 | 0.8294 | 0.8243 | 0.8131 | 0.8158 |
| diff-only detector, dedup seed7 best balanced | 0.5000 | 0.8382 | 0.8291 | 0.8473 | 0.8441 | 0.8365 | 0.8382 |
| diff-only detector, dedup seed99 best balanced | 0.5000 | 0.8320 | 0.8503 | 0.8138 | 0.8200 | 0.8349 | 0.8321 |

Interpretation: paired training fixed the most obvious collapse mode, because safe specificity increased from `0.0111` to `0.4433` at the default threshold. However, independent paired-snippet training still did not learn a useful ordering. The metadata-only, candidate-only, and counterpart-only controls all stay near chance after threshold tuning, which protects the diff-only result from the simplest leakage explanations. The pair-context detector showed that explicit comparison helps, raising balanced accuracy to `0.6061`. Candidate-plus-diff improves over candidate-only and pair-context variants, but still trails diff-only by a large margin. The diff-only detector is the decisive result: representing the task as a patch-style difference raises balanced accuracy above `0.81` with both vulnerable recall and safe specificity above `0.80`, remains stable after removing detected exact/near-duplicate eval rows, and reproduces across additional seeds. This supports the first-principles diagnosis that PrimeVul paired data should be modeled as secure patch/diff reasoning, and that the cleanest patch signal is currently better for the 1.5B model than adding full candidate code.
