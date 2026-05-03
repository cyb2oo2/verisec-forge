# Data Lineage

This document tracks the current mainline data flow for the PrimeVul paired diff reasoning experiments.

## Source

- Upstream dataset family: `PrimeVul`
- Project use: defensive secure-code reasoning and patch/diff vulnerability judgment
- Main task: decide whether the candidate side of a paired diff is the vulnerable version

## Current Mainline Artifacts

### Paired Diff Eval

- Local path: `data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl`
- Rows: `1792`
- SHA256: `7bc138be4e24fdd91d2d7d9ba2b03e6c57df287ad31e3ff3b76656c4713c7bb9`
- Role: deduplicated paired diff eval rows with `pair_key`, metadata, labels, and unified diff prompt text

### Baseline Direction-Aware Predictions

- Local path: `outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_3000_v1_eval1792_dedup_predictions.jsonl`
- Rows: `1792`
- SHA256: `11137e2ef52c0951a98d86ac38f246f64d22366b0df04ae34f896c5157d4b4e3`
- Role: predictions from the baseline direction-aware detector

### Recall-Recovery Predictions

- Local path: `outputs/secure_code_primevul_cls_qwen15bcoder_lora_pair_diff_directional_recall_recovery_3249_v1_eval1792_dedup_predictions.jsonl`
- Rows: `1792`
- SHA256: `841215cee202ed45226a868041b4a17a0be90f076b310b7f30faf883c81d4b54`
- Role: predictions from the direction-aware recall-recovery v1 detector

## Validation-Selected Router

The calibrated router uses:

- `30%` of pair groups for calibration
- `70%` held-out pair groups for reporting
- split seed `42`
- selector `balanced_accuracy`
- candidate bucket thresholds `0.5, 0.6, 0.7, 0.8, 0.9`

Selected threshold:

- `26+` bucket threshold: `0.7`

Held-out result:

- balanced accuracy: `0.8136`
- group all-correct rate: `0.7117`
- orientation accuracy: `0.8581`

Same-split baseline control:

- balanced accuracy: `0.8136`
- group all-correct rate: `0.7101`
- orientation accuracy: `0.8514`

## Interpretation Boundary

The router result should be interpreted as a calibration and pair-consistency improvement, not as a new raw detection breakthrough. It slightly improves pair/group metrics while keeping row-level balanced accuracy flat on the held-out split.

## Pair Evidence Localization

The first evidence-localization layer uses the pair-coupled held-out predictions and extracts heuristic hunk-level support scores. It is not gold evidence-span supervision.

- Report: `reports/PRIMEVUL_PAIR_EVIDENCE_LOCALIZATION.md`
- JSON summary: `reports/secure_code_primevul_pair_evidence_localization_v1.json`
- JSON summary SHA256: `8150eb893decefa60354c7c2de47450a0d93b28a94ff148a5fff02a0ff2b4dc3`
- Row-level output: `outputs/secure_code_primevul_pair_evidence_localization_v1.jsonl`
- Row-level output rows: `1261`
- support rate: `0.6376`
- pseudo-localization accuracy: `0.6003`
- vulnerable pseudo-localization accuracy: `0.5952`
- safe pseudo-localization accuracy: `0.6054`
- best hunk-limit sweep pseudo-localization accuracy: `0.6051` at top-3 hunks
- supported prediction error rate: `0.0933`
- unsupported prediction error rate: `0.2516`

## Hunk Pseudo-Label Datasets

These artifacts convert paired diffs into hunk-level pseudo labels for cheap localizer experiments. They are not human evidence annotations.

Train:

- Source: `data/processed/secure_code_primevul_pair_diff_only_train_balanced_3000_metadata.jsonl`
- Output: `data/processed/secure_code_primevul_hunk_pseudo_train_top8.jsonl`
- Summary: `reports/PRIMEVUL_HUNK_PSEUDO_LABEL_TRAIN.md`
- Hunk rows: `4697`
- Source rows: `2999`
- Positive hunk rate: `0.4788`
- top-1 / top-8 coverage: `0.5575` / `0.5822`

Eval:

- Source: `data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl`
- Output: `data/processed/secure_code_primevul_hunk_pseudo_eval_top8.jsonl`
- Summary: `reports/PRIMEVUL_HUNK_PSEUDO_LABEL_EVAL.md`
- Hunk rows: `2536`
- Source rows: `1787`
- Positive hunk rate: `0.5335`
- top-1 / top-8 coverage: `0.5792` / `0.6150`

## Hunk Linear Scorer

The first learned hunk scorer is a dependency-free linear model trained on pseudo labels. It is a cheap reranking sanity check, not a human-validated evidence localizer.

- Report: `reports/PRIMEVUL_HUNK_LINEAR_SCORER.md`
- JSON: `reports/secure_code_primevul_hunk_linear_scorer_v1.json`
- Scored eval rows: `outputs/secure_code_primevul_hunk_linear_scorer_eval_v1.jsonl`
- Eval label accuracy: `0.8793`
- Eval top-1 coverage: keyword `0.5792`, linear scorer `0.5954`
- Eval top-2 coverage: keyword `0.6066`, linear scorer `0.6133`
- Eval top-3/top-8 coverage ceiling: `0.6150`

## Candidate Recall Analysis

This analysis compares whole-hunk candidates with changed-line window candidates using the same hunk pseudo-label protocol.

- Eval report: `reports/PRIMEVUL_CANDIDATE_RECALL.md`
- Eval JSON: `reports/secure_code_primevul_candidate_recall_eval_v1.json`
- Train report: `reports/PRIMEVUL_CANDIDATE_RECALL_TRAIN.md`
- Train JSON: `reports/secure_code_primevul_candidate_recall_train_v1.json`
- Eval hunk-only top-8 coverage: `0.6150`
- Eval line-window top-8 coverage: `0.7070`
- Eval hunk+window top-8 coverage: `0.7073`
- Train hunk-only top-8 coverage: `0.5822`
- Train hunk+window top-8 coverage: `0.7082`

## Hunk+Window Linear Scorer

This scorer trains the same dependency-free linear model on hunk+window pseudo-label candidates.

- Report: `reports/PRIMEVUL_HUNK_PLUS_WINDOW_LINEAR_SCORER.md`
- JSON: `reports/secure_code_primevul_hunk_plus_window_linear_scorer_v1.json`
- Train rows: `data/processed/primevul_candidate_recall_train_v1/hunk_plus_window_candidates.jsonl`
- Eval rows: `data/processed/primevul_candidate_recall_eval_v1/hunk_plus_window_candidates.jsonl`
- Eval top-1 coverage: keyword `0.5792`, linear scorer `0.6178`
- Eval top-3 coverage: keyword `0.6676`, linear scorer `0.6877`
- Eval top-5 coverage: keyword `0.6961`, linear scorer `0.7029`
- Eval top-8 ceiling: `0.7073`
- Caveat: top-1 vulnerable coverage `0.6782`, safe coverage `0.5572`
- Side-aware diagnostic top-1 coverage: `0.7073`
- Side-aware diagnostic top-1 vulnerable/safe coverage: `0.7039` / `0.7108`
- Side-aware caveat: this uses target-side alignment from the pseudo-label protocol and should be treated as an oracle-style upper bound until rerun with pair-coupled predicted sides.

## Predicted-Side Hunk Scorer

This report reuses the side-aware hunk+window scorer but replaces gold-side alignment with the pair-coupled predicted side.

- Report: `reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md`
- JSON: `reports/secure_code_primevul_predicted_side_hunk_scorer_v1.json`
- Candidates: `data/processed/primevul_candidate_recall_eval_v1/hunk_plus_window_candidates.jsonl`
- Predictions: `outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl`
- Matched source rows: `1257`
- Pair-coupled side accuracy: `0.8488`
- Matched oracle top-1 coverage: `0.7184`
- Pair-coupled predicted-side top-1 coverage: `0.6555`
- Correct-side top-1 coverage: `0.7610`
- Wrong-side top-1 coverage: `0.0632`

## Predicted-Side Failure Taxonomy

This report analyzes the source rows where pair-coupled predicted side disagrees with gold side, then inspects the top hunk selected by the predicted-side localizer.

- Report: `reports/PRIMEVUL_PREDICTED_SIDE_FAILURE_TAXONOMY.md`
- JSON: `reports/secure_code_primevul_predicted_side_failure_taxonomy_v1.json`
- Scored hunks: `outputs/secure_code_primevul_predicted_side_hunk_scorer_eval_v1.jsonl`
- Predictions: `outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl`
- Wrong sources: `190`
- False positives / false negatives: `95` / `95`
- Largest wrong changed-line bucket: `00-02` with `59`
- Largest wrong probability-gap bucket: `50+` with `86`
- Wrong top-hunk positive rate: `0.0632`
- Correct top-hunk positive rate: `0.7610`

## Confident Side-Inversion Set

This local artifact extracts high-confidence pair-side mistakes for calibration and hard-negative mining. The JSONL is a generated data artifact under `data/processed` and is intentionally not part of the tracked source tree by default.

- Report: `reports/PRIMEVUL_CONFIDENT_SIDE_INVERSION_SET.md`
- JSON summary: `reports/secure_code_primevul_confident_side_inversions_gap50_v1.json`
- Local JSONL: `data/processed/secure_code_primevul_confident_side_inversions_gap50_v1.jsonl`
- Source eval rows: `data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl`
- Predictions: `outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl`
- Selection rule: `pred != gold` and `pair_probability_gap >= 0.50`
- Rows: `86`
- Pair groups: `43`
- False positives / false negatives: `43` / `43`
- Average probability gap: `0.8225`

## Pair-Side Correction Gate

This diagnostic trains a lightweight correction gate on pair-key calibration groups. If a held-out group is predicted as inversion-prone, it falls back from pair-coupled labels to pre-coupled predictions.

- Single-split report: `reports/PRIMEVUL_PAIR_SIDE_CORRECTION_GATE.md`
- Single-split JSON: `reports/secure_code_primevul_pair_side_correction_gate_v1.json`
- Multi-split report: `reports/PRIMEVUL_PAIR_SIDE_CORRECTION_MULTISPLIT.md`
- Multi-split JSON: `reports/secure_code_primevul_pair_side_correction_multisplit_v1.json`
- Input predictions: `outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl`
- Seed42 balanced accuracy: baseline `0.8470`, correction `0.8481`
- Seed42 gated groups: `6`
- Multi-split balanced-accuracy delta mean: `0.0000`
- Multi-split group all-correct delta mean: `-0.0019`
- Interpretation: flat/negative diagnostic; richer contrastive features are needed.

## Contrastive Side-Correction

This diagnostic adds hunk/window pseudo-evidence aggregates to the side-correction gate, comparing the high-probability and low-probability sides inside each pair group.

- Report: `reports/PRIMEVUL_CONTRASTIVE_SIDE_CORRECTION.md`
- JSON: `reports/secure_code_primevul_contrastive_side_correction_v1.json`
- Input predictions: `outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl`
- Input hunk candidates: `data/processed/primevul_candidate_recall_eval_v1/hunk_plus_window_candidates.jsonl`
- Seed42 balanced accuracy: baseline `0.8470`, correction `0.8504`
- Multi-split balanced-accuracy delta mean: `-0.0002`
- Multi-split group all-correct delta mean: `-0.0047`
- Interpretation: negative/flat; pseudo-evidence aggregates are insufficient for robust side correction.

## Paired-Window Contrastive Dataset

This generated local artifact is the next model-ready side-correction input. It renders each mixed pair group as an `A/B` comparison where `Side A` is the current high-probability side and `Side B` is the low-probability side. Label `B` therefore means the current high-probability orientation should be inverted.

- Report: `reports/PRIMEVUL_PAIRED_WINDOW_CONTRASTIVE_DATASET.md`
- JSON: `reports/secure_code_primevul_paired_window_contrastive_eval_v1.json`
- Local JSONL: `data/processed/secure_code_primevul_paired_window_contrastive_eval_v1.jsonl`
- Input predictions: `outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl`
- Input hunk candidates: `data/processed/primevul_candidate_recall_eval_v1/hunk_plus_window_candidates.jsonl`
- Rows: `592`
- Label A / B rows: `509` / `83`
- High-gap orientation inversion pairs at `gap >= 0.50`: `44`
- Average prompt length: `2102.1402` characters
- Interpretation: training/calibration input for an explicit paired-window side model; not an independent performance result or human evidence-span annotation.

## Paired-Window Side Model

This is the first dependency-free model trained on the paired-window contrastive artifact. It is a signal check before GPU-backed side-model training.

- Report: `reports/PRIMEVUL_PAIRED_WINDOW_SIDE_MODEL.md`
- JSON: `reports/secure_code_primevul_paired_window_side_model_v1.json`
- Input: `data/processed/secure_code_primevul_paired_window_contrastive_eval_v1.jsonl`
- Protocol: five pair-key calibration/eval splits with seeds `7,13,42,99,123`
- Always-A baseline accuracy / balanced accuracy: `0.8598` / `0.5000`
- Model eval accuracy mean: `0.7328`
- Model eval balanced accuracy mean: `0.6065`
- Balanced-accuracy delta vs always-A mean: `+0.1065`
- Label-B inversion recall mean: `0.4367`
- Top-3 / top-5 flip precision mean: `0.7334` / `0.7200`
- Interpretation: side inversion signal exists, but the lightweight model over-flips correct high-probability sides under threshold decoding. Its near-term use is a high-priority review queue for a few top-scored candidate inversions, not automatic replacement of pair-coupled decoding.

## Side-Inversion Review Queue

This generated local artifact materializes the top-scored paired-window side-inversion candidates. It is the bridge from diagnostic side-model scores to a future verifier or human review loop.

- Report: `reports/PRIMEVUL_SIDE_INVERSION_REVIEW_QUEUE.md`
- JSON: `reports/secure_code_primevul_side_inversion_review_queue_top5_v1.json`
- Local JSONL: `data/processed/secure_code_primevul_side_inversion_review_queue_top5_v1.jsonl`
- Input: `data/processed/secure_code_primevul_paired_window_contrastive_eval_v1.jsonl`
- Top-k per seed: `5`
- Rows: `25`
- Unique pair keys: `16`
- True inversions: `18`
- Diagnostic precision: `0.7200`
- Interpretation: review/verifier input with gold labels retained for analysis; not an automatic correction result.

## Side-Inversion Verifier Dataset

This generated local artifact converts the review queue into strict supervised verifier targets. The verifier task is intentionally narrow: decide whether to accept a proposed flip from the detector's high-probability side to the side model's alternative side, using only the compact paired evidence windows.

- Report: `reports/PRIMEVUL_SIDE_INVERSION_VERIFIER_DATASET.md`
- JSON: `reports/secure_code_primevul_side_inversion_verifier_top5_v1.json`
- Local JSONL: `data/processed/secure_code_primevul_side_inversion_verifier_top5_v1.jsonl`
- Input queue: `data/processed/secure_code_primevul_side_inversion_review_queue_top5_v1.jsonl`
- Rows: `25`
- Unique pair keys: `16`
- Accept / reject flip rows: `18` / `7`
- Average prompt length: `2873.2` characters
- Output contract: `accept_flip`, `reason_code`, `evidence_side`, `confidence`
- Interpretation: supervised verifier/review target for future training; not an independent benchmark split and not a deployed automatic correction layer.
