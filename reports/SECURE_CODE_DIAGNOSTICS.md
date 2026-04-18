# Secure Code Diagnostics

This report focuses on the two most important diagnostic layers in the current `PrimeVul` experiments:

- failure taxonomy shape
- confidence and calibration behavior

The goal is to show not just whether `SFT` beats `Base`, but *how* the error distribution changes across a small benchmark (`eval244`) and a larger held-out benchmark (`holdout1000`).

## Failure Taxonomy Comparison

### eval244

| Model | Correct | Label Failure | Format Failure | High-Confidence Error | Evidence Failure |
| --- | ---: | ---: | ---: | ---: | ---: |
| Base 0.5B | 0.4016 | 0.1393 | 0.3074 | 0.1434 | 0.0082 |
| SFT 0.5B | 0.4795 | 0.3238 | 0.1721 | 0.0246 | 0.0000 |

### eval244 Label Error Shape

| Model | False Negative | False Positive | CWE Mismatch | Null Prediction |
| --- | ---: | ---: | ---: | ---: |
| Base 0.5B | 0.9706 | 0.0294 | 0.0000 | 0.0000 |
| SFT 0.5B | 1.0000 | 0.0000 | 0.0000 | 0.0000 |

### holdout1000

| Model | Correct | Label Failure | Format Failure | High-Confidence Error | Evidence Failure |
| --- | ---: | ---: | ---: | ---: | ---: |
| Base 0.5B | 0.2800 | 0.3460 | 0.2080 | 0.1570 | 0.0090 |
| SFT 0.5B | 0.4140 | 0.3460 | 0.2180 | 0.0210 | 0.0010 |

### holdout1000 Label Error Shape

| Model | False Negative | False Positive | CWE Mismatch | Null Prediction |
| --- | ---: | ---: | ---: | ---: |
| Base 0.5B | 0.3902 | 0.3931 | 0.2168 | 0.0000 |
| SFT 0.5B | 0.9769 | 0.0145 | 0.0087 | 0.0000 |

## Calibration Diagnostics

### eval244

### Base 0.5B

| Confidence Bucket | Count | Accuracy | High-Confidence Error Rate |
| --- | ---: | ---: | ---: |
| 0.9-1.0 | 67 | 0.4179 | 0.5821 |
| 0.75-0.89 | 1 | 0.0000 | 1.0000 |
| 0.5-0.74 | 1 | 0.0000 | 0.0000 |
| 0.0-0.49 | 2 | 0.0000 | 0.0000 |
| missing | 173 | 0.4162 | 0.0000 |

### SFT 0.5B

| Confidence Bucket | Count | Accuracy | High-Confidence Error Rate |
| --- | ---: | ---: | ---: |
| 0.9-1.0 | 10 | 0.3000 | 0.7000 |
| 0.75-0.89 | 192 | 0.5781 | 0.0000 |
| 0.5-0.74 | 3 | 1.0000 | 0.0000 |
| missing | 39 | 0.0000 | 0.0000 |

### holdout1000

### Base 0.5B

| Confidence Bucket | Count | Accuracy | High-Confidence Error Rate |
| --- | ---: | ---: | ---: |
| 0.9-1.0 | 242 | 0.3099 | 0.6901 |
| 0.75-0.89 | 6 | 0.5000 | 0.5000 |
| 0.0-0.49 | 24 | 0.1667 | 0.0000 |
| missing | 728 | 0.2885 | 0.0000 |

### SFT 0.5B

| Confidence Bucket | Count | Accuracy | High-Confidence Error Rate |
| --- | ---: | ---: | ---: |
| 0.9-1.0 | 25 | 0.1600 | 0.8400 |
| 0.75-0.89 | 688 | 0.5218 | 0.0015 |
| 0.5-0.74 | 36 | 0.9722 | 0.0000 |
| missing | 251 | 0.0876 | 0.0000 |

## Diagnostic Takeaways

- On both benchmarks, the dominant semantic failure of the best current model (`SFT 0.5B`) is still `false_negative`. This shows the main remaining problem is missed vulnerabilities, not uncontrolled over-detection.
- The larger held-out benchmark exposes a more mixed base-model error shape: `Base 0.5B` shows substantial `false_negative` and `false_positive` mass, while `SFT 0.5B` collapses that pattern back toward mostly missed vulnerabilities.
- Calibration is where SFT is most clearly better: on the larger held-out benchmark, the SFT checkpoint keeps most predictions in the `0.75-0.89` bucket with near-zero high-confidence error, while the base model's `0.9-1.0` bucket remains badly unreliable.
- The small `eval244` slice is still useful for fast iteration, but `holdout1000` should now be treated as the stronger generalization check for claims about secure-code reliability.
- Concrete error counts reinforce that story: `SFT 0.5B` has `79` false negatives on `eval244` and `338` false negatives on `holdout1000`, while `Base 0.5B` already accumulates `136` false positives on the harder held-out benchmark.
