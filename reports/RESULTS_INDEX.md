# Results Index

This index collects the most important reports, diagnostics, and benchmark summaries in the repository.

## Project Entry Points

Start here for the main narrative and current system-level conclusions.

- `README`: `README.md`
- `Technical Report`: `reports/TECHNICAL_REPORT.md`
- `Research Summary`: `reports/SECURE_CODE_RESEARCH_SUMMARY.md`
- `Visual Diagnostics`: `reports/SECURE_CODE_VISUAL_DIAGNOSTICS.md`

## CodeXGLUE Mainline

Primary detector-auditor benchmark line and operating-point analysis.

- `Classifier Calibration`: `reports/CODEXGLUE_CLASSIFIER_CALIBRATION.md`
- `Hybrid Operating Points`: `reports/CODEXGLUE_HYBRID_OPERATING_POINTS.md`
- `Detector + Scorer Operating Points`: `reports/CODEXGLUE_DETECTOR_SCORER_OPERATING_POINTS.md`
- `Detector + Scorer Failure Breakdown`: `reports/secure_code_codexglue_detector_scorer_full_v1_best_accuracy_failure_breakdown.json`
- `Classifier Threshold Sweep (eval1000)`: `reports/secure_code_codexglue_cls_qwen15bcoder_lora_6000_v1_threshold_sweep_eval1000.json`
- `Classifier Threshold Sweep (holdout2000)`: `reports/secure_code_codexglue_cls_qwen15bcoder_lora_6000_v1_threshold_sweep_holdout2000.json`
- `Hybrid Summary (eval1000)`: `reports/codexglue_hybrid_thresholds/secure_code_codexglue_hybrid_threshold_summary.json`
- `Hybrid Summary (holdout2000)`: `reports/codexglue_hybrid_thresholds_holdout2000/secure_code_codexglue_hybrid_threshold_summary.json`

## PrimeVul Mainline

Original secure-code structured-auditor branch and its larger held-out evaluation.

- `PrimeVul Comparison`: `reports/training_comparison.md`
- `Best SFT holdout1000 report`: `reports/secure_code_primevul_sft_qwen05b_balanced_safe_none_only_v1_holdout1000_report.json`
- `Best SFT holdout2000 report`: `reports/secure_code_primevul_sft_qwen05b_balanced_safe_none_only_v1_holdout2000_report.json`
- `Detector + Confirmer Operating Points`: `reports/PRIMEVUL_DETECTOR_CONFIRMER_OPERATING_POINTS.md`
- `Detector + Scorer Operating Points`: `reports/PRIMEVUL_DETECTOR_SCORER_OPERATING_POINTS.md`
- `Support Scorer Ablations`: `reports/PRIMEVUL_SUPPORT_SCORER_ABLATIONS.md`
- `Shortcut Diagnostics`: `reports/PRIMEVUL_SHORTCUT_DIAGNOSTICS.md`
- `Generated Main Results`: `reports/PRIMEVUL_MAIN_RESULTS.md`
- `Generated Main Results JSON`: `reports/PRIMEVUL_MAIN_RESULTS.json`
- `Generated Main Results Chart`: `reports/assets/primevul_main_results.svg`
- `Paired Eval Shortcut Report`: `reports/secure_code_primevul_paired_eval_balanced_1800_shortcut_diagnostics.json`
- `Paired Eval Detector Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_presence_3000_v1_paired1800_report.json`
- `Paired Eval Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_presence_3000_v1_paired1800_threshold_sweep.json`
- `Paired-Trained Detector Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_paired_presence_3000_v1_paired1800_report.json`
- `Paired-Trained Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_paired_presence_3000_v1_paired1800_threshold_sweep.json`
- `Pair-Context Detector Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_context_3000_v1_eval1800_report.json`
- `Pair-Context Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_context_3000_v1_eval1800_threshold_sweep.json`
- `Diff-Only Detector Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval1800_report.json`
- `Diff-Only Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval1800_threshold_sweep.json`
- `Diff-Only Train/Eval Overlap Report`: `reports/secure_code_primevul_pair_diff_only_train_eval_overlap_report.json`
- `Diff-Only Dedup Eval Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval1800_dedup_report.json`
- `Diff-Only Dedup Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval1800_dedup_threshold_sweep.json`
- `Diff-Only Seed7 Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_seed7_v1_eval1792_report.json`
- `Diff-Only Seed7 Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_seed7_v1_eval1792_threshold_sweep.json`
- `Diff-Only Seed99 Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_seed99_v1_eval1792_report.json`
- `Diff-Only Seed99 Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_seed99_v1_eval1792_threshold_sweep.json`
- `Candidate-Only Control Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_candidate_only_3000_v1_eval1800_report.json`
- `Candidate-Only Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_candidate_only_3000_v1_eval1800_threshold_sweep.json`
- `Candidate+Diff Detector Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_candidate_plus_diff_3000_v1_eval1800_report.json`
- `Candidate+Diff Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_candidate_plus_diff_3000_v1_eval1800_threshold_sweep.json`
- `Metadata-Only Control Train Summary`: `reports/secure_code_primevul_pair_metadata_only_train_balanced_3000_summary.json`
- `Metadata-Only Control Eval Summary`: `reports/secure_code_primevul_pair_metadata_only_eval_balanced_1800_summary.json`
- `Metadata-Only Control Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_metadata_only_3000_v1_eval1800_report.json`
- `Metadata-Only Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_metadata_only_3000_v1_eval1800_threshold_sweep.json`
- `Counterpart-Only Control Train Summary`: `reports/secure_code_primevul_pair_counterpart_only_train_balanced_3000_summary.json`
- `Counterpart-Only Control Eval Summary`: `reports/secure_code_primevul_pair_counterpart_only_eval_balanced_1800_summary.json`
- `Counterpart-Only Control Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_counterpart_only_3000_v1_eval1800_report.json`
- `Counterpart-Only Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_counterpart_only_3000_v1_eval1800_threshold_sweep.json`
- `Project-Disjoint Feasibility Summary`: `reports/secure_code_primevul_project_disjoint_eval_balanced_1000_summary.json`
- `PrimeVul Diagnostics`: `reports/SECURE_CODE_DIAGNOSTICS.md`
