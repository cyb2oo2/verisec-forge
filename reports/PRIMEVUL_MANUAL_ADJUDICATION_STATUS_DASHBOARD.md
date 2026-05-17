# PrimeVul Manual Adjudication Status Dashboard

This dashboard summarizes the current manual evidence adjudication state.
It is not a final adjudication artifact; it tracks what is ready, blocked, or still awaiting reviewer action.

## Summary

- Total rows: `20`
- Completed rows: `6`
- Human-confirmed rows: `0`
- Overall completion rate: `0.3`
- Final adjudication: `false`
- Research gate: AI-filled adjudications are complete for the high-quality queue, but reviewer-confirmed labels begin only after non-AI human confirmation.

## Track Status

| Track | Rows | Completed | Completion | Status | Blocked By | Next Action |
| --- | ---: | ---: | ---: | --- | --- | --- |
| `high_quality_disagreement` | 6 | 6 | 1.0 | `ai_adjudicated_needs_human_confirmation` | human reviewer confirmation is still missing | Request human confirmation or revision of the AI-filled CSV before treating labels as reviewer-confirmed. |
| `insufficient_context` | 14 | 0 | 0.0 | `review_packet_ready` | requires wider-context inspection before final side labels | Inspect wider context for each row; keep insufficient_context when evidence remains ambiguous. |

## high_quality_disagreement

- Purpose: Resolve strongest pilot/gold evidence conflicts.
- Dry run: `false`
- Primary artifacts:
  - `data/processed/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv`
  - `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_WORKFLOW.md`
  - `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_BRIEF.md`
  - `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_PACKET.md`

Diagnostics:

- `gold_pilot_conflicts`: `6`
- `model_pilot_conflicts`: `4`
- `label_status_counts`: `corrected_side: 5, insufficient_context: 1`
- `evidence_span_sufficiency_counts`: `no: 1, partial: 2, yes: 3`
- `reviewer_counts`: `codex_ai_adjudication_v1: 6`
- `ai_completed`: `6`
- `human_confirmed_completed`: `0`
- `apply_errors`: `[]`
- `skipped_blank`: `0`

## insufficient_context

- Purpose: Decide whether narrow hunk/window evidence needs wider context.
- Dry run: `false`
- Primary artifacts:
  - `data/processed/secure_code_primevul_manual_evidence_insufficient_context_v1.jsonl`
  - `reports/PRIMEVUL_MANUAL_EVIDENCE_INSUFFICIENT_CONTEXT_BRIEF.md`

Diagnostics:

- `bucket_counts`: `00-02: 2, 03-05: 2, 06-10: 4, 11-25: 2, 26+: 4`
- `evidence_side_counts`: `both: 8, unclear: 6`
- `source_pool_counts`: `fresh_seeds_top5_v1: 6, project_holdout_top5_v1: 2, rank6_10_v1: 4, top5_v1: 2`

## Next Step

The high-quality queue now has an AI-filled adjudication pass. The next gate is human confirmation or revision of those `6` rows; only then should they be described as reviewer-confirmed. In parallel, use the insufficient-context brief to decide whether the current hunk/window packet needs wider code context before final labels are assigned.
