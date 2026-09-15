# Evidence policy

The [2026-09-07 review](../reports/scientific_review_2026_09_07/REVIEW.md) supersedes earlier result narratives. Retained JSON/CSV files are historical evidence for reanalysis, not validated current conclusions. Their bytes are preserved; an embedded `ok` flag means only what the original script checked.

- Historical split-view runtime summaries cannot establish changed-hunk visibility: the renderer removes the markers used by the parser.
- The repair audit contains 200 pairs from each of PrimeVul, DeltaSecommits and PatchEval. Raw repaired predictions fail the repair gate.
- Structural projection must be separated from learned improvement. Antisymmetric scores do not alone guarantee polarity invariance or tie-safe binary decisions.
- A nonsignificant independence test does not establish independence or content blindness. Mixed-relation baselines need stratification and uncertainty accounting.
- Changed-line visibility is not human-confirmed evidence sufficiency. Small reviewer-confirmed queues and AI pilot labels do not replace independent blinded annotation.
- The frozen-readout train-cache mismatch was diagnosed as line endings only; recovered original bytes pass the derived P0 manifest. Original artifacts remain unchanged.

Use the [audit snapshot](../reports/scientific_review_2026_09_07/audit_results.json) for concrete measurements and the [evidence inventory](../reports/evidence_inventory.json) for historical files. `validation_deferred` suspends interpretation; original bytes have not been silently corrected.

Frozen protocols preserve historical decisions and deviations. They are not instructions to restart old experiments or proof that every planned condition was executed.

P0 corrected measurements and inference boundaries are recorded in the current review and its [derived results](../reports/scientific_review_2026_09_07/p0/results.json).
