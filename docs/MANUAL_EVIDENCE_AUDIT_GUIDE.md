# Manual Evidence Audit Guide

This guide now documents the retained evidence-audit boundary after pruning. The detailed review packets and batch-level intermediate reports were removed from the application-facing repository; the retained artifacts summarize the current state.

## Goal

The audit asks whether hunk/window evidence supports the vulnerable/fixed side decision. The key finding is:

> Evidence localization is coupled to upstream side correctness. When the model chooses the wrong side, evidence ranking mostly fails with it.

## Retained Evidence Artifacts

- [Pair Evidence Localization](../reports/PRIMEVUL_PAIR_EVIDENCE_LOCALIZATION.md)
- [Predicted-Side Hunk Scorer](../reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md)
- [Predicted-Side Failure Taxonomy](../reports/PRIMEVUL_PREDICTED_SIDE_FAILURE_TAXONOMY.md)
- [Manual Adjudication Status Dashboard](../reports/PRIMEVUL_MANUAL_ADJUDICATION_STATUS_DASHBOARD.md)
- [AI Adjudication Summary](../reports/PRIMEVUL_AI_ADJUDICATION_SUMMARY.md)
- [Manual Evidence Audit Loop Figure](../reports/assets/primevul_manual_evidence_audit_loop.svg)

## Current Interpretation

- Pseudo-label localization is useful for triage.
- AI-filled adjudication is useful for workflow rehearsal and prioritization.
- The 20 `high_quality_disagreement` and `insufficient_context` rows now carry a
  non-AI human-confirmed verdict (see the dashboard's `reviewer_counts`). These
  20 rows may be described as reviewer-confirmed evidence labels; the rest of
  the evidence-localization pipeline (pseudo-labels, AI-filled rows outside
  this set) should still not be described as independent human-gold
  supervision.
- Widening the human-confirmed set beyond these 20 rows is blocked on the
  current side-inversion candidate source, not on review effort: the four
  review queues (`scripts/build_manual_evidence_audit_set_round2.py`
  confirms this) contain only 42 unique `pair_key` values in total, and
  round 1's audit set already covers all of them. The next evidence
  milestone is a new upstream side-inversion candidate generation run
  (different rank range, gap threshold, or seed family), not resampling
  these existing queue files.

## Regeneration Boundary

The retained scripts can rebuild audit summaries when the local ignored inputs are materialized. Use:

```powershell
.\.venv\Scripts\python.exe scripts\reproduce_primevul_evidence_coupled.py --check-only
.\.venv\Scripts\python.exe scripts\reproduce_primevul_evidence_coupled.py
```

The exact artifact paths and expected metrics are listed in:

- `reproducibility/primevul_evidence_coupled_manifest.json`

For application review, lead with the retained summary reports rather than the removed batch packets.
