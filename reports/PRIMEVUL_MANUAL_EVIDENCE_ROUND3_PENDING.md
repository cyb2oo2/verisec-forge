# PrimeVul Manual Evidence Adjudication, Round 3 (Pending)

Round 3 follows the same process as round 2
(`reports/PRIMEVUL_MANUAL_EVIDENCE_ROUND2_SUMMARY.md`): a new rank window
(`--rank-start 16 --top-k 5`) of the same 592-pair scored pool, excluding
every `pair_key` already used in rounds 1 and 2.

**This round is intentionally left at the AI-pilot stage, not yet
human-confirmed.** Per-request, manual verification was postponed in favor
of research/experimental work; this report documents what is ready to
confirm whenever that resumes.

## Generation

- New rank-16-20 queue: `25` rows / `25` unique pair keys
  (`reports/secure_code_primevul_side_inversion_review_queue_rank16_20_v1.json`)
- Overlap with rounds 1+2 (excluded): `11` pair keys
- Materialized round-3 audit rows: `14`, zero overlap with rounds 1-2
  (`reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_SET_ROUND3.md`)

## AI Pilot Pass and Classification

All 14 rows received an AI pilot annotation (`codex_pilot_round3`) and were
classified (`reports/PRIMEVUL_MANUAL_EVIDENCE_PILOT_FINDINGS_ROUND3.md`):

- `high_quality_disagreement`: `0` -- no case where the pilot's read
  contradicts stored gold with quality 2-3 evidence. Unlike round 2 (the
  FFmpeg CVE-2020-35964 correction), this round's pilot annotations agree
  with gold everywhere a directional call was made.
- `insufficient_context`: `9` (`reports/PRIMEVUL_MANUAL_EVIDENCE_REVIEW_QUEUES_ROUND3.md`)
  -- no directional claim, low risk for bulk confirmation when resumed.
- Clean pilot/gold agreements (not queued): `5`

## What Remains

Apply the same procedure used for rounds 1-2 when resumed: export an
adjudication template for the 9 `insufficient_context` rows, confirm (likely
in bulk, since none assert a side), apply via
`scripts/apply_manual_evidence_adjudications.py`, and fold the totals into
the combined dashboard. No high-stakes case is waiting in this round, unlike
round 2.

## Claim Boundary

Nothing in this round is yet reviewer-confirmed. These are AI-pilot draft
annotations only (`codex_pilot_round3`), not independent human gold, and
must not be described as confirmed until the application step above runs.
