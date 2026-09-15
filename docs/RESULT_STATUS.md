# Result status

Updated September 15, 2026. The latest entries of the [scientific review](../reports/scientific_review_2026_09_07/REVIEW.md) take precedence over its older chronological entries.

| Status | Evidence | Interpretation |
| --- | --- | --- |
| Current, scope-bounded | Changed lines visible in 577/600 split-view pairs | Source-line accounting, not semantic sufficiency |
| Current, scope-bounded | 32 repaired function pairs / 27 cases | Locally verified source mappings, not security-label gold |
| Current preparation | 838 weakly labeled pairs, split 571/134/133 | Prepared data; no new pilot training outcome |
| Exploratory | Projected split-view accuracy 58.58% → 62.05%, p=0.01686 | Retained-prediction reanalysis; fails original 0.01 threshold |
| Exploratory | Raw-repair residual 0.00835, 95% interval [0.00116, 0.01536] | Post hoc stratified diagnostic, not independence or learned repair |
| Exploratory | AI ledger: 13 single-side / 2 both / 17 unclear | Mixed-context provisional judgments, not gold or model accuracy |
| Failed / unsupported | Original raw repair gate | No transferable learned repair established |
| Superseded interpretation | Historical headline scores, independence claims, unconditional structural guarantees | Do not establish security understanding, content blindness, or tie-safe polarity invariance |
| Planned | New weak-supervision training pilot | Not run; no performance claim |

[P0 results](../reports/scientific_review_2026_09_07/p0/results.json) preserve corrected measurements. The [original audit](../reports/scientific_review_2026_09_07/audit_results.json) is a historical snapshot, including failures later diagnosed; a stored failure is not necessarily a currently failing software test. The [evidence inventory](../reports/evidence_inventory.json) binds retained files to hashes. The [cleanup manifest](../reports/scientific_review_2026_09_07/cleanup_manifest.json) records retired prose; Git preserves old versions.

Package version remains 0.1.0. Passing CI checks software integration and regression behavior, not historical model quality, label correctness, or fresh-clone training reproducibility. The homepage update does not revoke previous stopping decisions.
