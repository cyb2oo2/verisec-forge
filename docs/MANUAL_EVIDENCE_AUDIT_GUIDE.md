# Manual Evidence Audit Guide

> **HISTORICAL DOCUMENT — CONTAINS WITHDRAWN RESULTS.**
> Contains results or interpretations withdrawn after adversarial structural-control
> analysis. Under the closed-world pair constraint the detector reaches `0.8596` balanced
> accuracy and a semantics-free character-level diff control reaches `0.8588` on the same
> population; the difference (`+0.0008`, clustered 95% CI `[-0.0202, +0.0222]`, sign test
> 19 vs 18, `p=1.0`) is not distinguishable from zero.
> **Do not cite as the repository's current scientific conclusion.**
> Current status: [Result Status Ledger](RESULT_STATUS_LEDGER.md).


This guide now documents the retained evidence-audit boundary after pruning. The detailed review packets and batch-level intermediate reports were removed from the application-facing repository; the retained artifacts summarize the current state.

## Goal

The audit asks whether hunk/window evidence supports the vulnerable/fixed side decision. The key finding is:

> Evidence localization is coupled to upstream side correctness. When the model chooses the wrong side, evidence ranking mostly fails with it.

## Retained Evidence Artifacts

- [Pair Evidence Localization](../reports/PRIMEVUL_PAIR_EVIDENCE_LOCALIZATION.md)
- [Predicted-Side Hunk Scorer](../reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md)
- [Predicted-Side Failure Taxonomy](../reports/PRIMEVUL_PREDICTED_SIDE_FAILURE_TAXONOMY.md)
- [Manual Adjudication Status Dashboard](../reports/PRIMEVUL_MANUAL_ADJUDICATION_STATUS_DASHBOARD.md)
- [Manual Evidence Round 2 Summary](../reports/PRIMEVUL_MANUAL_EVIDENCE_ROUND2_SUMMARY.md)
- [AI Adjudication Summary](../reports/PRIMEVUL_AI_ADJUDICATION_SUMMARY.md)
- [Manual Evidence Audit Loop Figure](../reports/assets/primevul_manual_evidence_audit_loop.svg)

## Current Interpretation

- Pseudo-label localization is useful for triage.
- AI-filled adjudication is useful for workflow rehearsal and prioritization.
- 30 `high_quality_disagreement` and `insufficient_context` rows across two
  rounds now carry a non-AI human-confirmed verdict (20 from round 1, 10
  from round 2 -- see `reports/PRIMEVUL_MANUAL_EVIDENCE_ROUND2_SUMMARY.md`).
  These 30 rows may be described as reviewer-confirmed evidence labels; the
  rest of the evidence-localization pipeline (pseudo-labels, AI-filled rows
  outside this set) should still not be described as independent human-gold
  supervision.
- Round 1 exhausted the original four review queues at the `pair_key`
  level (only 42 unique pairs total). Round 2 unblocked this with a new
  rank-11-15 slice of the same underlying 592-pair scored pool
  (`scripts/build_primevul_side_inversion_review_queue.py --rank-start 11`),
  not a resample of the existing queues. The pool still has headroom (550
  pairs were unused before round 2), but rank-11-15 is markedly
  lower-confidence by construction (classifier precision `0.16` there vs the
  original top-10 pools), so further rounds will be lower-yield -- 9 of
  round 2's 10 queued rows were `insufficient_context` deferrals, not
  corrections.

## Regeneration Boundary

The retained scripts can rebuild audit summaries when the local ignored inputs are materialized. Use:

```powershell
.\.venv\Scripts\python.exe scripts\reproduce_primevul_evidence_coupled.py --check-only
.\.venv\Scripts\python.exe scripts\reproduce_primevul_evidence_coupled.py
```

The exact artifact paths and expected metrics are listed in:

- `reproducibility/primevul_evidence_coupled_manifest.json`

For application review, lead with the retained summary reports rather than the removed batch packets.
