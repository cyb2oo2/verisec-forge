# Design and implementation record

The repository covers the research workflow from evaluation design and experiment implementation to measurement repair, source-data preparation, statistical analysis, and reproducible reporting.

| Area | Implemented work | Technical record |
| --- | --- | --- |
| Evaluation design | Paired code candidates, order and label transformations, controlled presentation, and explicit decision semantics | [Relational runtime](../src/vrf/relational_runtime.py) |
| Experiment execution | Prediction identity and coverage validation, external-adapter contracts, and a small offline demonstration | [Prediction validation](../src/vrf/prediction_validation.py), [adapter contract](VERIPATCH_RR_EXTERNAL_ADAPTER.md) |
| Measurement and analysis | Changed-line visibility accounting, tie handling, paired comparisons, and stratified pair-cluster bootstrap analysis | [Evaluation implementation](../src/vrf/relational_evaluation.py), [current review](../reports/public_review_2026_09_10/REVIEW.md) |
| Source-data repair | Source extraction, function matching, source-aware identities, commit references, file hashes, and line provenance | [Source integrity](../src/vrf/source_integrity.py), [repair record](../reports/scientific_review_2026_09_07/p1/source_repair_v3.json) |
| Dataset preparation | Bidirectional examples, grouped splits, overlap quarantine, and input/tokenizer checks | [Dataset implementation](../src/vrf/training_dataset.py), [pilot report](TRAINING_DATASET_PILOT.md) |
| Reproducibility | Artifact manifests, evidence inventory, regression checks, CI, and result-status tracking | [Reproduction guide](../REPRODUCIBILITY.md), [result status](RESULT_STATUS.md) |

## Data, models, and dependencies

Experiments use PrimeVul, DeltaSecommits, and PatchEval cases with recorded source provenance. Historical model configurations use Qwen and CodeBERT families; exact model, precision, and settings are recorded per experiment. See the [data documentation](../data/README.md).

Runtime, test, parsing, and optional training dependencies are declared in [pyproject.toml](../pyproject.toml). Data, source code, and model weights retain their respective license terms.

## Experimental status

Current results establish measurement and source-integrity checks within the audited scope. Exploratory AI annotations remain provisional. The weak-supervision pilot is prepared but has not produced a new training result. The [current review](../reports/public_review_2026_09_10/REVIEW.md) and [result-status record](RESULT_STATUS.md) define which measurements remain valid and which interpretations are unsupported or superseded.
