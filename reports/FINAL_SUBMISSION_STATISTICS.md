# Final Submission Statistics

This table compresses the reviewer-facing evidence into one submission-oriented view. It favors claim boundaries over raw score maximization: high same-source scores are treated as shortcut diagnostics, while paired diff reasoning, pair-coupled decoding, external validation, source-aware routing, and evidence triage are separated.

## Main Table

| Claim area | Setting | Primary result | Uncertainty / control | Reviewer-safe interpretation | Artifact |
| --- | --- | --- | --- | --- | --- |
| Shortcut diagnosis | PrimeVul same-source detector | BA `0.9524` | Recall `0.9709`, specificity `0.9339`; treated as artifact-sensitive. | High standard-split score motivates stricter paired evaluation; it is not the headline breakthrough. | `reports/secure_code_primevul_cls_qwen15bcoder_lora_presence_3000_v1_holdout2000_report.json` |
| Shortcut diagnosis | Same detector on vulnerable/fixed paired stress | BA `0.4961` | Best threshold `0.9999`; near chance. | The easy same-source result does not survive paired patch structure. | `reports/secure_code_primevul_cls_qwen15bcoder_lora_presence_3000_v1_paired1800_threshold_sweep.json` |
| Negative controls | Metadata/candidate/counterpart-only controls | best control BA `0.5156` | Metadata-only `0.5022`, candidate-only `0.5078`, counterpart-only `0.5156` BA. | Controls stay near chance, protecting the paired-diff formulation. | `reports/PRIMEVUL_MAIN_RESULTS.json` |
| Paired diff reasoning | PrimeVul diff-only paired detector | mean BA `0.8287` | 3 seeds, range `0.8158-0.8382`. | Diff-only paired reasoning is the credible base formulation after shortcut diagnosis. | `reports/PRIMEVUL_MAIN_RESULTS.json` |
| Metadata removal | PrimeVul diff-only without Project/CVE/CWE prompt metadata | BA `0.8244` | Threshold `0.8`. | The paired-diff signal does not depend on obvious prompt metadata. | `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_no_metadata_3000_v1_eval1800_threshold_sweep.json` |
| Task-structured decoding | Pair-coupled decoding over held-out pair-key splits | mean BA `0.8572` | 5 splits, CI `[0.8523, 0.8616]`; strict pair-minus-bucket BA delta `0.0348` CI `[0.0329, 0.0368]`. | This is the main method-like contribution because it uses paired task structure. | `reports/secure_code_primevul_pair_coupled_significance_v1.json` |
| External validation | PrimeVul true time-disjoint direct train <=2020, eval >=2021 | BA `0.8835` | `1562` rows, `761` pair groups. | Temporal split keeps paired-diff signal strong under later-CVE evaluation. | `reports/secure_code_primevul_time_disjoint_direct_train_v1.json` |
| External validation | DeltaSecommits C/C++ source-specific adapter | BA `0.8563` | `654` balanced rows, `327` pair groups. | Second-source C/C++ paired patches support the paired-diff formulation outside PrimeVul. | `reports/secure_code_deltasecommits_delta_only_pair_diff_eval_v1.json` |
| External validation | PatchEval zero-shot matched-mixed checkpoint | BA `0.8086` | `538` rows across Go/JavaScript/Python-oriented repairs. | Third-source cross-language transfer is harder but remains above chance. | `reports/secure_code_patcheval_zero_shot_matched_mixed_primevul_short_delta_v1.json` |
| External adaptation | PatchEval source-specific adapter, 3 seeds | mean BA `0.8172` | Range `0.803-0.829`. | PatchEval adaptation helps but is seed-sensitive, so report mean/range rather than best seed. | `reports/secure_code_patcheval_adapter_multiseed_v1.json` |
| Source-aware routing | Three-source source-routed adapter mixture | BA `0.8664` | Single matched-mixed BA `0.8591`; delta `0.0073`. | Source-specific experts provide a small aggregate gain over one mixed checkpoint. | `reports/secure_code_three_source_adapter_mixture_v1.json` |
| Learned router boundary | Learned diff-body-only source/expert router | routed BA `0.8664` | BA delta `0.0073`, CI `[0, 0.0145]`; leave-one-source routed-minus-oracle range `[-0.025, -0.0077]`. | Closed-world expert selection is supported; open-set source discovery is not claimed. | `reports/secure_code_learned_router_claim_boundary_v1.json` |
| Evidence-coupled audit loop | Predicted-side hunk/window localization | top-1 `0.6555` | Side-correct top-1 `0.7610`; side-wrong top-1 `0.0632`. | Evidence quality depends on upstream side decisions; current evidence labels remain pseudo-label/triage. | `reports/secure_code_primevul_predicted_side_hunk_scorer_v1.json` |
| Safe correction protocol | Evidence-conditioned project-holdout safe flip gate | accept precision `1.0` | Accepted `9`, introduced `0`; small queue and stress-invalidated earlier strict gate. | Useful precision-first review protocol, not a deployable large-scale automatic flipper. | `reports/secure_code_primevul_side_inversion_gate_summary_v1.json` |

## Reading Notes

- The same-source PrimeVul `0.9524` result is included as a cautionary artifact diagnosis, not as the headline.
- The strict pair-coupled claim is pair-coupled decoding versus bucket routing on the same held-out pair-key splits.
- External validation currently supports paired patch/diff reasoning across PrimeVul time-disjoint, DeltaSecommits, and PatchEval, but broader open-set source shift remains future work.
- Learned source routing should be described as closed-world source-aware expert selection. Leave-one-source stress prevents claiming unseen-source expert discovery.
- Evidence localization and safe flip gates are audit-loop diagnostics until non-AI adjudication confirms evidence spans.
