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
- Neither should be described as independent human-gold evidence supervision.
- The next publishable evidence milestone is a small non-AI adjudication pass over the highest-value disagreement and insufficient-context rows.

## Regeneration Boundary

The retained scripts can rebuild audit summaries when the local ignored inputs are materialized. Use:

```powershell
.\.venv\Scripts\python.exe scripts\reproduce_primevul_evidence_coupled.py --check-only
.\.venv\Scripts\python.exe scripts\reproduce_primevul_evidence_coupled.py
```

The exact artifact paths and expected metrics are listed in:

- `reproducibility/primevul_evidence_coupled_manifest.json`

For application review, lead with the retained summary reports rather than the removed batch packets.
