# PrimeVul Manual Evidence Audit Set (Round 2)

This report has two parts. The first attempt sampled from the same four
side-inversion review queues as round 1, excluding every `audit_id` and
`pair_key` already used in `reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_SET.md`.
That attempt found the source exhausted: the four queues contain only `42`
unique pair keys in total, all already covered by round 1's audit set.

The second attempt used a genuinely new source: a rank-11-15 slice of the
same underlying 592-pair scored pool
(`data/processed/secure_code_primevul_paired_window_contrastive_eval_v1.jsonl`),
generated with `scripts/build_primevul_side_inversion_review_queue.py
--rank-start 11 --top-k 5` (mirroring how the original `rank6_10` pool was
generated, one rank window further out). This produced real new candidates.
Excluding by `pair_key` against round 1 (not just `audit_id` -- the same
pair can be re-selected at a different rank by a different per-seed
train/eval split) found:

## Summary

- New rank-11-15 queue: `25` rows / `24` unique pair keys
  (`reports/secure_code_primevul_side_inversion_review_queue_rank11_15_v1.json`)
- Overlap with round 1 (excluded): `5` pair keys
- Round-1 pair keys excluded (from the original four queues): `42`
- Materialized round-2 audit rows: `19`, zero overlap with round 1
- Output dataset: `data/processed/secure_code_primevul_manual_evidence_audit_round2_v1.jsonl`

These 19 rows received an AI pilot annotation pass (`codex_pilot_round2`)
and were classified into review queues; see
`reports/PRIMEVUL_MANUAL_EVIDENCE_PILOT_FINDINGS_ROUND2.md` for the
classification and `reports/PRIMEVUL_MANUAL_EVIDENCE_ROUND2_SUMMARY.md` for
the human-confirmed adjudication results.

## Pool Counts

- `rank11_15_v1`: `19`

## Annotation Contract

Same as round 1: `human_vulnerable_side`, `evidence_side`, `evidence_quality`,
`selected_window_ids`, `label_issue`, `notes`.

## Headroom for Future Rounds

The 592-pair scored pool still has `550` pairs that were unused before this
round, and round 2 used `19` of them. Further rounds remain possible from
the same pool (e.g. rank 16-20), but yield will likely keep declining: the
underlying classifier's own precision at identifying true side inversions
drops from the original top-10 pools to `0.16` at rank-11-15
(`reports/secure_code_primevul_side_inversion_review_queue_rank11_15_v1.json`),
and `9` of round 2's `10` queued rows were `insufficient_context`
deferrals rather than corrections.
