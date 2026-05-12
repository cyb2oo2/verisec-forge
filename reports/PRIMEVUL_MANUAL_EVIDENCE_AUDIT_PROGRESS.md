# PrimeVul Manual Evidence Audit Progress

This report tracks the CSV batch workflow for the manual evidence-span audit set.

## Current Progress

- Rows: `42`
- Completed annotations: `40`
- Blank annotations: `2`
- Invalid annotations: `0`
- Completion rate: `0.9524`

## Batch Files

- `data/processed/manual_evidence_audit_batches/manual_evidence_audit_v1_batch_01.csv`: `10` rows, completed=`10`, blank=`0`
- `data/processed/manual_evidence_audit_batches/manual_evidence_audit_v1_batch_02.csv`: `10` rows, completed=`10`, blank=`0`
- `data/processed/manual_evidence_audit_batches/manual_evidence_audit_v1_batch_03.csv`: `10` rows, completed=`10`, blank=`0`
- `data/processed/manual_evidence_audit_batches/manual_evidence_audit_v1_batch_04.csv`: `10` rows, completed=`10`, blank=`0`
- `data/processed/manual_evidence_audit_batches/manual_evidence_audit_v1_batch_05.csv`: `2` rows, completed=`0`, blank=`2`

## Source Pool Progress

- `fresh_seeds_top5_v1`: blank=`1`, completed=`14`
- `project_holdout_top5_v1`: completed=`8`
- `rank6_10_v1`: blank=`1`, completed=`12`
- `top5_v1`: completed=`6`

## Recommended Next Step

Continue with `data/processed/manual_evidence_audit_batches/manual_evidence_audit_v1_batch_05.csv`: run the apply script with `--dry-run`, then apply and analyze before moving to the next batch.
