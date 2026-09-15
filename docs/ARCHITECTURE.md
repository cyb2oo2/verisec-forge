# Code map

Current research status is defined by the [scientific review](../reports/scientific_review_2026_09_07/REVIEW.md).

| Area | Implementation | Purpose |
| --- | --- | --- |
| Rendering | `src/vrf/relational_benchmark.py`, `src/vrf/nuisance_transfer.py` | Candidates and presentations |
| Runtime | `src/vrf/relational_runtime.py` | Source-bound changed-line visibility; semantic equivalence remains unestablished |
| Evaluation | `src/vrf/relational_evaluation.py`, `src/vrf/repair_evaluation.py` | Metrics and comparisons; review caveats apply |
| Readouts | `src/vrf/readout_classifier.py`, `src/vrf/frozen_readout_control.py` | Readout and representation controls |
| Adapter | `src/vrf/external_adapter.py` | External prediction validation |
| Reproduction | `src/vrf/reproducibility.py` | Manifest and bundle checks |
| Annotation | `src/vrf/pair_annotation.py` | Human annotation workflow |
| Audit | `reports/scientific_review_2026_09_07/audit_existing_artifacts.py` | Existing-artifact reanalysis |

Broader analysis, training and demo code is retained. Its existence does not validate the original conclusions. Old generators can produce historical-format outputs locally; these are not automatically promoted into the current report index.
