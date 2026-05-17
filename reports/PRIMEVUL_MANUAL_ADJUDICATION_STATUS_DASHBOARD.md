# PrimeVul Manual Adjudication Status Dashboard

This dashboard summarizes the current manual evidence adjudication state.
It is not a final adjudication artifact; it tracks what is ready, blocked, or still awaiting reviewer action.

## Summary

- Total rows: `20`
- Completed rows: `0`
- Overall completion rate: `0.0`
- Final adjudication: `false`
- Research gate: Reviewer-confirmed labels begin only after non-dry-run apply writes adjudicated JSONL.

## Track Status

| Track | Rows | Completed | Completion | Status | Blocked By | Next Action |
| --- | ---: | ---: | ---: | --- | --- | --- |
| `high_quality_disagreement` | 6 | 0 | 0.0 | `not_started_dry_run` | independent reviewer fields are blank | Fill the focused CSV, rerun apply with --dry-run, then apply without --dry-run. |
| `insufficient_context` | 14 | 0 | 0.0 | `review_packet_ready` | requires wider-context inspection before final side labels | Inspect wider context for each row; keep insufficient_context when evidence remains ambiguous. |

## high_quality_disagreement

- Purpose: Resolve strongest pilot/gold evidence conflicts.
- Dry run: `true`
- Primary artifacts:
  - `data/processed/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv`
  - `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_WORKFLOW.md`
  - `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_BRIEF.md`
  - `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_PACKET.md`

Diagnostics:

- `gold_pilot_conflicts`: `6`
- `model_pilot_conflicts`: `4`
- `apply_errors`: `[]`
- `skipped_blank`: `6`

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

Complete the high-quality CSV first because it is the smallest reviewer-confirmed gate. Then use the insufficient-context brief to decide whether the current hunk/window packet needs wider code context before final labels are assigned.
