# Experiment Matrix

This matrix is generated from `experiments/registry.json` by
`scripts/build_experiment_matrix.py`. It summarizes retained artifacts
and their claim boundaries; it does not introduce new results.

| Layer | Experiment | Primary Artifact | Claim | Boundary | Reproducibility |
| --- | --- | --- | --- | --- | --- |
| measurement | Current Scientific Review | [reports/scientific_review_2026_09_07/REVIEW.md](../reports/scientific_review_2026_09_07/REVIEW.md) | Existing-artifact reanalysis identifies measurement and interpretation defects. | No new model inference; historical evidence remains conditional and some validation is deferred. | local-artifact-audit |
| reproducibility | External Adapter Smoke | [docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md](../docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md) | Committed fixture supports integration and schema checks. | Not a model-quality result. | ci-smoke |
