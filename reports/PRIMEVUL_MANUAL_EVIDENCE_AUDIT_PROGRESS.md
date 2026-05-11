# PrimeVul Manual Evidence Audit Progress

This report tracks the CSV batch workflow for the manual evidence-span audit set.

## Current Progress

- Rows: `42`
- Completed annotations: `0`
- Blank annotations: `42`
- Invalid annotations: `0`
- Completion rate: `0.0`

## Batch Files

- `data/processed/manual_evidence_audit_batches/manual_evidence_audit_v1_batch_01.csv`: `10` rows
- `data/processed/manual_evidence_audit_batches/manual_evidence_audit_v1_batch_02.csv`: `10` rows
- `data/processed/manual_evidence_audit_batches/manual_evidence_audit_v1_batch_03.csv`: `10` rows
- `data/processed/manual_evidence_audit_batches/manual_evidence_audit_v1_batch_04.csv`: `10` rows
- `data/processed/manual_evidence_audit_batches/manual_evidence_audit_v1_batch_05.csv`: `2` rows

## Source Pool Progress

- `fresh_seeds_top5_v1`: blank=`15`
- `project_holdout_top5_v1`: blank=`8`
- `rank6_10_v1`: blank=`13`
- `top5_v1`: blank=`6`

## Recommended Pilot

Start with the first batch, run the apply script with `--dry-run`, then analyze annotations before continuing to the remaining batches.
