# Results Index

This index collects the most important reports, diagnostics, and benchmark summaries in the repository.

## Project Entry Points

Start here for the main narrative and current system-level conclusions.

- `README`: `README.md`
- `Technical Report`: `reports/TECHNICAL_REPORT.md`
- `Research Summary`: `reports/SECURE_CODE_RESEARCH_SUMMARY.md`
- `Visual Diagnostics`: `reports/SECURE_CODE_VISUAL_DIAGNOSTICS.md`
- `Reproducibility Guide`: `REPRODUCIBILITY.md`
- `Data Lineage`: `reports/DATA_LINEAGE.md`

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

PrimeVul secure-code experiments, including the artifact-sensitive same-source detector, paired split diagnostics, and the current paired diff reasoning mainline.

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
- `Paired Diff Failure Analysis`: `reports/PRIMEVUL_PAIR_DIFF_FAILURE_ANALYSIS.md`
- `Paired Diff Failure Analysis JSON`: `reports/secure_code_primevul_pair_diff_only_failure_analysis.json`
- `Paired Diff Edge-Focus Plan`: `reports/PRIMEVUL_DIFF_EDGE_FOCUS_PLAN.md`
- `Paired Diff Bucket Slice Summary`: `reports/secure_code_primevul_pair_diff_bucket_slices_summary.json`
- `Paired Diff Edge-Focus Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_edge_focus_3000_v1_eval1800_dedup_report.json`
- `Paired Diff Edge-Focus Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_edge_focus_3000_v1_eval1800_dedup_threshold_sweep.json`
- `Paired Diff Edge-Focus Seed7 Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_edge_focus_3000_seed7_v1_eval1800_dedup_report.json`
- `Paired Diff Edge-Focus Seed7 Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_edge_focus_3000_seed7_v1_eval1800_dedup_threshold_sweep.json`
- `Paired Diff Edge-Focus Seed99 Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_edge_focus_3000_seed99_v1_eval1800_dedup_report.json`
- `Paired Diff Edge-Focus Seed99 Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_edge_focus_3000_seed99_v1_eval1800_dedup_threshold_sweep.json`
- `Paired Diff Edge-Focus Failure Analysis`: `reports/PRIMEVUL_PAIR_DIFF_EDGE_FOCUS_FAILURE_ANALYSIS.md`
- `Paired Diff Edge-Focus Small-Diff Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_edge_focus_3000_v1_eval_bucket_00_02_threshold_sweep.json`
- `Paired Diff Edge-Focus Large-Diff Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_edge_focus_3000_v1_eval_bucket_26plus_threshold_sweep.json`
- `Paired Diff No-Metadata Train Summary`: `reports/secure_code_primevul_pair_diff_no_metadata_train_balanced_3000_summary.json`
- `Paired Diff No-Metadata Eval Summary`: `reports/secure_code_primevul_pair_diff_no_metadata_eval_balanced_1800_summary.json`
- `Paired Diff No-Metadata Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_no_metadata_3000_v1_eval1800_report.json`
- `Paired Diff No-Metadata Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_no_metadata_3000_v1_eval1800_threshold_sweep.json`
- `Paired Diff No-Metadata Failure Analysis`: `reports/PRIMEVUL_PAIR_DIFF_NO_METADATA_FAILURE_ANALYSIS.md`
- `Paired Diff Localization Plan`: `reports/PRIMEVUL_DIFF_LOCALIZATION_PLAN.md`
- `Paired Diff Localized Train Summary`: `reports/secure_code_primevul_pair_diff_localized_train_balanced_3000_summary.json`
- `Paired Diff Localized Eval Summary`: `reports/secure_code_primevul_pair_diff_localized_eval_balanced_1792_dedup_summary.json`
- `Paired Diff 26+ Localized Bucket Summary`: `reports/secure_code_primevul_pair_diff_bucket_26plus_localized_h3_c1800_summary.json`
- `Paired Diff Contrastive Train Summary`: `reports/secure_code_primevul_pair_diff_contrastive_train_balanced_3000_summary.json`
- `Paired Diff Contrastive Eval Summary`: `reports/secure_code_primevul_pair_diff_contrastive_eval_balanced_1792_dedup_summary.json`
- `Paired Diff 26+ Contrastive Bucket Summary`: `reports/secure_code_primevul_pair_diff_bucket_26plus_contrastive_h3_c2200_summary.json`
- `Paired Diff 26+ Error Window Analysis`: `reports/PRIMEVUL_26PLUS_ERROR_WINDOWS.md`
- `Paired Diff 26+ Error Window Analysis JSON`: `reports/secure_code_primevul_pair_diff_edge_focus_26plus_error_windows.json`
- `Paired Diff Direction-Aware Window Experiment`: `reports/PRIMEVUL_DIRECTION_AWARE_WINDOWS.md`
- `Paired Diff Direction-Aware Train Summary`: `reports/secure_code_primevul_pair_diff_directional_train_balanced_3000_summary.json`
- `Paired Diff Direction-Aware Eval Summary`: `reports/secure_code_primevul_pair_diff_directional_eval_balanced_1792_dedup_summary.json`
- `Paired Diff 26+ Direction-Aware Bucket Summary`: `reports/secure_code_primevul_pair_diff_bucket_26plus_directional_h3_c2400_summary.json`
- `Paired Diff Edge-Focus 26+ Direction-Aware Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_edge_focus_3000_v1_eval_bucket_26plus_directional_h3_c2400_threshold_sweep.json`
- `Paired Diff Direction-Aware Detector Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval1792_dedup_report.json`
- `Paired Diff Direction-Aware Detector Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval1792_dedup_threshold_sweep.json`
- `Paired Diff Direction-Aware 26+ Bucket Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval_bucket_26plus_directional_h3_c2400_report.json`
- `Paired Diff Direction-Aware 26+ Bucket Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval_bucket_26plus_directional_h3_c2400_threshold_sweep.json`
- `Paired Diff Direction-Aware 26+ Error Window Analysis`: `reports/PRIMEVUL_DIRECTION_AWARE_26PLUS_ERROR_WINDOWS.md`
- `Paired Diff Direction-Aware 26+ Error Window Analysis JSON`: `reports/secure_code_primevul_pair_diff_directional_26plus_error_windows.json`
- `Paired Diff Direction-Aware Recall-Recovery Train Summary`: `reports/secure_code_primevul_pair_diff_directional_recall_recovery_train_3249_summary.json`
- `Paired Diff Direction-Aware Recall-Recovery Detector Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_recall_recovery_3249_v1_eval1792_dedup_report.json`
- `Paired Diff Direction-Aware Recall-Recovery Detector Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_recall_recovery_3249_v1_eval1792_dedup_threshold_sweep.json`
- `Paired Diff Direction-Aware Recall-Recovery 26+ Bucket Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_recall_recovery_3249_v1_eval_bucket_26plus_directional_h3_c2400_report.json`
- `Paired Diff Direction-Aware Recall-Recovery 26+ Bucket Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_recall_recovery_3249_v1_eval_bucket_26plus_directional_h3_c2400_threshold_sweep.json`
- `Paired Diff Direction-Aware Recall-Recovery 26+ Error Window Analysis`: `reports/PRIMEVUL_DIRECTION_AWARE_RECALL_RECOVERY_26PLUS_ERROR_WINDOWS.md`
- `Paired Diff Direction-Aware Recall-Recovery 26+ Error Window Analysis JSON`: `reports/secure_code_primevul_pair_diff_directional_recall_recovery_26plus_error_windows.json`
- `Paired Diff Direction-Aware Recall-Recovery v2 Train Summary`: `reports/secure_code_primevul_pair_diff_directional_recall_recovery_train_3113_summary.json`
- `Paired Diff Direction-Aware Recall-Recovery v2 Detector Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_recall_recovery_3113_v2_eval1792_dedup_report.json`
- `Paired Diff Direction-Aware Recall-Recovery v2 Detector Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_recall_recovery_3113_v2_eval1792_dedup_threshold_sweep.json`
- `Paired Diff Direction-Aware Recall-Recovery v2 26+ Bucket Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_recall_recovery_3113_v2_eval_bucket_26plus_directional_h3_c2400_report.json`
- `Paired Diff Direction-Aware Recall-Recovery v2 26+ Bucket Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_recall_recovery_3113_v2_eval_bucket_26plus_directional_h3_c2400_threshold_sweep.json`
- `Paired Diff Direction-Aware Recall-Recovery v2 26+ Error Window Analysis`: `reports/PRIMEVUL_DIRECTION_AWARE_RECALL_RECOVERY_V2_26PLUS_ERROR_WINDOWS.md`
- `Paired Diff Direction-Aware Recall-Recovery v2 26+ Error Window Analysis JSON`: `reports/secure_code_primevul_pair_diff_directional_recall_recovery_v2_26plus_error_windows.json`
- `Paired Diff Direction-Aware Bucket Router Report`: `reports/PRIMEVUL_DIRECTIONAL_BUCKET_ROUTER.md`
- `Paired Diff Direction-Aware Bucket Router JSON`: `reports/secure_code_primevul_directional_bucket_router_v1_report.json`
- `Paired Diff Direction-Aware Bucket Router Recall Report`: `reports/PRIMEVUL_DIRECTIONAL_BUCKET_ROUTER_RECALL.md`
- `Paired Diff Direction-Aware Bucket Router Recall JSON`: `reports/secure_code_primevul_directional_bucket_router_v1_recall_report.json`
- `Paired Diff Direction-Aware Bucket Router Calibrated Report`: `reports/PRIMEVUL_DIRECTIONAL_BUCKET_ROUTER_CALIBRATED.md`
- `Paired Diff Direction-Aware Bucket Router Calibrated JSON`: `reports/secure_code_primevul_directional_bucket_router_calibrated_v1_report.json`
- `Paired Diff Direction-Aware Bucket Router Statistics`: `reports/PRIMEVUL_DIRECTIONAL_BUCKET_ROUTER_STATISTICS.md`
- `Paired Diff Direction-Aware Bucket Router Statistics JSON`: `reports/secure_code_primevul_directional_bucket_router_statistics_v1.json`
- `Paired Diff Pair-Coupled Router`: `reports/PRIMEVUL_PAIR_COUPLED_ROUTER.md`
- `Paired Diff Pair-Coupled Router JSON`: `reports/secure_code_primevul_pair_coupled_router_v1_report.json`
- `Paired Diff Pair-Coupled Router Statistics`: `reports/PRIMEVUL_PAIR_COUPLED_ROUTER_STATISTICS.md`
- `Paired Diff Pair-Coupled Router Statistics JSON`: `reports/secure_code_primevul_pair_coupled_router_statistics_v1.json`
- `Paired Diff Pair-Coupled Multi-Split Balanced Report`: `reports/PRIMEVUL_PAIR_COUPLED_MULTISPLIT_BALANCED.md`
- `Paired Diff Pair-Coupled Multi-Split Balanced JSON`: `reports/secure_code_primevul_pair_coupled_multisplit_balanced_v1.json`
- `Paired Diff Pair-Coupled Multi-Split Group Report`: `reports/PRIMEVUL_PAIR_COUPLED_MULTISPLIT.md`
- `Paired Diff Pair-Coupled Multi-Split Group JSON`: `reports/secure_code_primevul_pair_coupled_multisplit_v1.json`
- `Paired Diff Pair Evidence Localization`: `reports/PRIMEVUL_PAIR_EVIDENCE_LOCALIZATION.md`
- `Paired Diff Pair Evidence Localization JSON`: `reports/secure_code_primevul_pair_evidence_localization_v1.json`
- `Paired Diff Hunk Pseudo-Label Train Summary`: `reports/PRIMEVUL_HUNK_PSEUDO_LABEL_TRAIN.md`
- `Paired Diff Hunk Pseudo-Label Eval Summary`: `reports/PRIMEVUL_HUNK_PSEUDO_LABEL_EVAL.md`
- `Paired Diff Hunk Linear Scorer`: `reports/PRIMEVUL_HUNK_LINEAR_SCORER.md`
- `Paired Diff Hunk Linear Scorer JSON`: `reports/secure_code_primevul_hunk_linear_scorer_v1.json`
- `Paired Diff Candidate Recall Eval`: `reports/PRIMEVUL_CANDIDATE_RECALL.md`
- `Paired Diff Candidate Recall Eval JSON`: `reports/secure_code_primevul_candidate_recall_eval_v1.json`
- `Paired Diff Candidate Recall Train`: `reports/PRIMEVUL_CANDIDATE_RECALL_TRAIN.md`
- `Paired Diff Candidate Recall Train JSON`: `reports/secure_code_primevul_candidate_recall_train_v1.json`
- `Paired Diff Hunk+Window Linear Scorer`: `reports/PRIMEVUL_HUNK_PLUS_WINDOW_LINEAR_SCORER.md`
- `Paired Diff Hunk+Window Linear Scorer JSON`: `reports/secure_code_primevul_hunk_plus_window_linear_scorer_v1.json`
- `Paired Diff Predicted-Side Hunk Scorer`: `reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md`
- `Paired Diff Predicted-Side Hunk Scorer JSON`: `reports/secure_code_primevul_predicted_side_hunk_scorer_v1.json`
- `Paired Diff Predicted-Side Failure Taxonomy`: `reports/PRIMEVUL_PREDICTED_SIDE_FAILURE_TAXONOMY.md`
- `Paired Diff Predicted-Side Failure Taxonomy JSON`: `reports/secure_code_primevul_predicted_side_failure_taxonomy_v1.json`
- `Paired Diff Confident Side-Inversion Set`: `reports/PRIMEVUL_CONFIDENT_SIDE_INVERSION_SET.md`
- `Paired Diff Confident Side-Inversion Set JSON`: `reports/secure_code_primevul_confident_side_inversions_gap50_v1.json`
- `Paired Diff Pair-Side Correction Gate`: `reports/PRIMEVUL_PAIR_SIDE_CORRECTION_GATE.md`
- `Paired Diff Pair-Side Correction Gate JSON`: `reports/secure_code_primevul_pair_side_correction_gate_v1.json`
- `Paired Diff Pair-Side Correction Multi-Split`: `reports/PRIMEVUL_PAIR_SIDE_CORRECTION_MULTISPLIT.md`
- `Paired Diff Pair-Side Correction Multi-Split JSON`: `reports/secure_code_primevul_pair_side_correction_multisplit_v1.json`
- `Original Diff Checkpoint on Localized Eval`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval1792_localized_report.json`
- `Original Diff Checkpoint on Localized Eval Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval1792_localized_threshold_sweep.json`
- `Localized Diff Detector Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_localized_3000_v1_eval1792_dedup_report.json`
- `Localized Diff Detector Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_localized_3000_v1_eval1792_dedup_threshold_sweep.json`
- `Contrastive Window Detector Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_contrastive_3000_v1_eval1792_dedup_report.json`
- `Contrastive Window Detector Threshold Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_contrastive_3000_v1_eval1792_dedup_threshold_sweep.json`
- `Diff-Only Detector 26+ Bucket Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval_bucket_26plus_threshold_sweep.json`
- `Diff-Only Detector 26+ Localized Bucket Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval_bucket_26plus_localized_h3_c1800_threshold_sweep.json`
- `Localized Diff Detector 26+ Localized Bucket Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_localized_3000_v1_eval_bucket_26plus_localized_h3_c1800_threshold_sweep.json`
- `Diff-Only Detector 26+ Contrastive Bucket Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_only_3000_v1_eval_bucket_26plus_contrastive_h3_c2200_threshold_sweep.json`
- `Localized Diff Detector 26+ Contrastive Bucket Report`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_localized_3000_v1_eval_bucket_26plus_contrastive_h3_c2200_report.json`
- `Contrastive Window Detector 26+ Contrastive Bucket Sweep`: `reports/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_contrastive_3000_v1_eval_bucket_26plus_contrastive_h3_c2200_threshold_sweep.json`
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
