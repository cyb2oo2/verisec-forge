# Results Index

> **CORRECTED — WITHDRAWN RESULTS.**
> This document previously presented PrimeVul detector results as evidence of learned
> secure-patch reasoning. That interpretation was withdrawn after adversarial
> structural-control analysis. Under the closed-world pair constraint the fine-tuned
> detector reaches balanced accuracy `0.8596`; a **semantics-free character-level diff
> structural control** reaches `0.8588` on the same evaluation population. The difference
> is `+0.0008`, with a pair-group clustered 95% CI spanning zero (`[-0.0202, +0.0222]`)
> and a non-significant group-level sign test (19 vs 18, `p=1.0`).
> **This experiment does not establish semantic secure-patch reasoning beyond diff structure.**
> Current status: [Result Status Ledger](../docs/RESULT_STATUS_LEDGER.md).


This index collects the application-facing reports and reproducibility entry points retained after pruning.

## Application Entry Points

Reviewer-facing narrative and reproducibility entry points.

- `README`: `README.md`
- `Reviewer Checklist`: `docs/REVIEWER_CHECKLIST.md`
- `Preprint Readiness Checklist`: `docs/PREPRINT_READINESS_CHECKLIST.md`
- `Preprint Preparation Plan`: `docs/PREPRINT_PREPARATION_PLAN.md`
- `Workshop / Preprint Targeting Plan`: `docs/WORKSHOP_PREPRINT_TARGETING_PLAN.md`
- `Current Workshop Target Shortlist`: `docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md`
- `External Feedback Packet`: `docs/EXTERNAL_FEEDBACK_PACKET.md`
- `One-Page Research Summary`: `docs/ONE_PAGE_RESEARCH_SUMMARY.md`
- `External Participation Guide`: `docs/EXTERNAL_PARTICIPATION_GUIDE.md`
- `External Model Report Card`: `docs/EXTERNAL_MODEL_REPORT_CARD.md`
- `Project Atlas`: `docs/PROJECT_ATLAS.md`
- `Experiment Matrix`: `reports/EXPERIMENT_MATRIX.md`
- `Application Packet`: `docs/APPLICATION_PACKET.md`
- `Application Focus`: `docs/APPLICATION_FOCUS.md`
- `Next Method Phase`: `docs/NEXT_METHOD_PHASE.md`
- `VeriPatch-RR External Adapter`: `docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md`
- `CI Testing Strategy`: `docs/CI_TESTING_STRATEGY.md`
- `Human Patch-Pair Annotation Protocol`: `docs/HUMAN_PATCH_PAIR_ANNOTATION_PROTOCOL.md`
- `Counterfactual Shortcut Protocol`: `docs/COUNTERFACTUAL_SHORTCUT_PROTOCOL.md`
- `VeriPatch-RR v0.1`: `reports/RELATIONAL_BENCHMARK_V2.md`
- `VeriPatch-RR Qwen Runtime Accounting`: `reports/secure_code_relational_benchmark_v2_qwen15b_runtime_summary.json`
- `VeriPatch-RR Qwen 1.5B Smoke`: `reports/VERIPATCH_RR_QWEN15B_SMOKE.md`
- `Qwen Relational Mechanism Audit`: `reports/QWEN_RELATIONAL_MECHANISM_AUDIT.md`
- `Qwen Side-Swap x Terminal-Phrase Interaction`: `reports/QWEN_SIDE_SWAP_TERMINAL_PHRASE_INTERACTION.md`
- `Qwen Side-Swap Positional Independence`: `reports/QWEN_SIDE_SWAP_POSITIONAL_INDEPENDENCE.md`
- `Qwen Label-Only Swap vs. Structural Swap`: `reports/QWEN_LABEL_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`
- `Qwen Polarity-Only Swap vs. Structural Swap`: `reports/QWEN_POLARITY_ONLY_SWAP_VS_STRUCTURAL_SWAP.md`
- `Task Formulation and the Status of Diff Polarity`: `docs/TASK_FORMULATION.md`
- `Polarity/Gold Confound Measurement`: `reports/POLARITY_GOLD_CONFOUND.md`
- `CrossVul Polarity/Gold Confound Measurement`: `reports/CROSSVUL_POLARITY_GOLD_CONFOUND.md`
- `CodeBERT Label/Polarity Mechanism Replication`: `reports/CODEBERT_LABEL_POLARITY_MECHANISM_REPLICATION.md`
- `Evidence Hierarchy`: `docs/EVIDENCE_HIERARCHY.md`
- `Experiment Completeness Audit and Remaining Evidence Gaps`: `docs/EXPERIMENT_COMPLETENESS_AUDIT.md`
- `Paper-Readiness Audit`: `docs/PAPER_READINESS_AUDIT.md`
- `Reviewer-Readiness Audit`: `docs/REVIEWER_READINESS_AUDIT.md`
- `PhD / Top-Lab Application Readiness Audit`: `docs/PHD_TOP_LAB_APPLICATION_READINESS_AUDIT.md`
- `External Review Request`: `docs/EXTERNAL_REVIEW_REQUEST.md`
- `External Review Email Templates`: `docs/EXTERNAL_REVIEW_EMAIL_TEMPLATE.md`
- `Repair Objective Design (+ v1 Outcome)`: `docs/REPAIR_OBJECTIVE_DESIGN.md`
- `Repair Experiment Preregistration (Criterion 5 Status)`: `docs/REPAIR_EXPERIMENT_PREREGISTRATION.md`
- `Repair Criteria Pre-Repair Baseline`: `reports/secure_code_repair_criteria_pre_repair_baseline_v1.json`
- `Repair Attempt: Antisymmetric-Head Run and Transfer Boundary (#54, #55)`: `reports/REPAIR_ANTISYMMETRIC_RESULT_V1.md`
- `Repair Attempt: PrimeVul In-Distribution Decomposition (#54)`: `reports/secure_code_repair_antisymmetric_decomposition_v1.json`
- `Repair Transfer Boundary: CrossVul External-Source Decomposition (#54)`: `reports/secure_code_repair_antisymmetric_crossvul_transfer_v1.json`
- `Repair Transfer Boundary: Nuisance-Transform Decomposition (#55)`: `reports/secure_code_repair_antisymmetric_nuisance_transfer_v1.json`
- `Cross-Model Relational Audit`: `reports/CROSS_MODEL_RELATIONAL_AUDIT.md`
- `Cross-Model Replication`: `reports/CROSS_MODEL_REPLICATION.md`
- `Decoder Stress Validation`: `reports/DECODER_STRESS_VALIDATION.md`
- `Decoder Failure Case Audit`: `reports/DECODER_FAILURE_CASE_AUDIT.md`
- `Same-Backbone Readout Ablation`: `reports/READOUT_ABLATION.md`
- `Readout Ablation Protocol`: `docs/READOUT_ABLATION_PROTOCOL.md`
- `Independent Readout Confirmation`: `reports/READOUT_CONFIRMATORY.md`
- `Readout Confirmation Protocol`: `docs/READOUT_CONFIRMATORY_PROTOCOL.md`
- `Frozen-Backbone Readout Control`: `reports/FROZEN_BACKBONE_READOUT_CONTROL.md`
- `Frozen-Backbone Readout Protocol`: `docs/FROZEN_BACKBONE_READOUT_PROTOCOL.md`
- `Paper 1 Draft Outline`: `docs/PAPER1_DRAFT_OUTLINE.md`
- `Qwen Batch-Shape Stability Audit`: `reports/secure_code_qwen_batch_shape_stability_v1.json`
- `Learned Joint Model Plan`: `docs/LEARNED_JOINT_MODEL_PLAN.md`
- `Pair Annotation Study Summary`: `reports/secure_code_primevul_pair_annotation_study_v1.json`
- `Counterfactual Intervention Summary`: `reports/secure_code_primevul_counterfactual_interventions_v1.json`
- `Joint Reasoning Dataset Summary`: `reports/secure_code_primevul_joint_reasoning_dataset_v1.json`
- `Project Story`: `PROJECT_STORY.md`
- `Reproducibility Guide`: `REPRODUCIBILITY.md`

## PrimeVul Paired-Diff Mainline

Shortcut controls, pair-coupled decoding, and statistical support.

- `Final Submission Statistics`: `reports/FINAL_SUBMISSION_STATISTICS.md`
- `Progressive Controls`: `reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md`
- `Main Results`: `reports/PRIMEVUL_MAIN_RESULTS.md`
- `Pair-Coupled Router`: `reports/PRIMEVUL_PAIR_COUPLED_ROUTER.md`
- `Pair-Coupled Multi-Split Balanced`: `reports/PRIMEVUL_PAIR_COUPLED_MULTISPLIT_BALANCED.md`
- `Pair-Coupled Significance`: `reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md`

## External Generalization And Routing

Disjoint PrimeVul stress tests, external datasets, and bounded source-aware routing.

- `CVE-Disjoint Eval`: `reports/PRIMEVUL_CVE_DISJOINT_EVAL.md`
- `Project-Disjoint Stress Eval`: `reports/PRIMEVUL_DISJOINT_STRESS_EVAL.md`
- `Time-Disjoint Comparison`: `reports/PRIMEVUL_TIME_DISJOINT_COMPARISON.md`
- `DeltaSecommits Expert Eval`: `reports/DELTASECCOMMITS_DELTA_ONLY_PAIR_DIFF_EVAL.md`
- `PatchEval Multi-Seed Adapter`: `reports/PATCHEVAL_ADAPTER_MULTISEED.md`
- `Three-Source Adapter Mixture`: `reports/THREE_SOURCE_ADAPTER_MIXTURE.md`
- `Learned Router Claim Boundary`: `reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md`

## Evidence-Coupled Audit

Evidence localization is **withdrawn**: the metric was circular and the human-confirmation step was anchored to pipeline-proposed windows. Side-inversion gate results require sample size and exact interval; see `PRIMEVUL_SIDE_INVERSION_GATE_UNCERTAINTY.md`.

- `Pair Evidence Localization`: `reports/PRIMEVUL_PAIR_EVIDENCE_LOCALIZATION.md`
- `Predicted-Side Hunk Scorer`: `reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md`
- `Side-Inversion Gate Summary`: `reports/PRIMEVUL_SIDE_INVERSION_GATE_SUMMARY.md`
- `Manual Adjudication Status Dashboard`: `reports/PRIMEVUL_MANUAL_ADJUDICATION_STATUS_DASHBOARD.md`
- `AI Adjudication Summary`: `reports/PRIMEVUL_AI_ADJUDICATION_SUMMARY.md`
