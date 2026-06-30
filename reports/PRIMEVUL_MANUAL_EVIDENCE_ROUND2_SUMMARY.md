# PrimeVul Manual Evidence Adjudication, Round 2

This is the second human-confirmed adjudication round, following round 1
(`reports/PRIMEVUL_MANUAL_ADJUDICATION_STATUS_DASHBOARD.md`, 20 rows). Round 1
exhausted the original four side-inversion review queues at the `pair_key`
level (`reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_SET_ROUND2.md` documents this
finding). Round 2 unblocks that by generating a genuinely new candidate
batch from the same underlying 592-pair scored pool
(`data/processed/secure_code_primevul_paired_window_contrastive_eval_v1.jsonl`),
using `scripts/build_primevul_side_inversion_review_queue.py --rank-start 11
--top-k 5` instead of resampling the existing rank-1-10 queues.

## Summary

- New candidate rows generated: `25` (`24` unique pair keys)
- Overlap with round 1 (excluded): `5` pair keys
- Round-2 audit set: `19` genuinely new rows, zero overlap with round 1
- AI pilot pass (`codex_pilot_round2`): `19/19` rows annotated
- Classified into review queues: `1` `high_quality_disagreement`, `9`
  `insufficient_context`, `9` clean pilot/gold agreements (not queued)
- Human-confirmed: `10/10` queued rows (`reviewer:
  cyb2oo2_human_confirmation_v1`)

## High-Quality Disagreement (1 row)

| Project / CVE | Gold | Pilot | Human-Confirmed | Evidence |
| --- | --- | --- | --- | --- |
| FFmpeg / CVE-2020-35964 | A | B | `corrected_side` -> B | Side A's candidate text adds an explicit bounds check (`if (delta > data_len[j]) return AVERROR_INVALIDDATA`) replacing an `av_assert0` that compiles out in release builds (`NDEBUG`); reads as the fixed side, contradicting stored gold A. |

## Insufficient Context (9 rows)

All nine make no directional claim; the visible hunk/window evidence does
not establish a clear side. Sources: Xilinx EmacLite pointer-format change
(linux CVE-2021-38205), 1-byte offset change (mutt CVE-2018-14349), a single
cleanup-call presence/absence (linux CVE-2022-1508), a validation-path
choice (minetest CVE-2022-24300), a kfree-vs-comment change (linux
CVE-2022-34494), a window-label conflict (nDPI CVE-2020-15473), a
length-calculation term whose direction conflicts with a naive read (samba
CVE-2014-0178), an opaque format-flag parameter (libvirt CVE-2020-14301),
and a sprintf call that is textually identical between previews (patch
CVE-2019-13638).

## Combined State (Round 1 + Round 2)

- Total human-confirmed evidence rows: `30`
- Total label corrections to stored gold: `7` (`6` from round 1, `1` from
  round 2)
- Total insufficient-context deferrals: `19` (`10` from round 1, `9` from
  round 2)

## Claim Boundary

This is human confirmation of 10 additional rows, drawn from a rank-11-15
slice of the same scored candidate pool used for round 1. It is not
project-wide independent gold, and the rank-11-15 pool is lower-confidence
by construction (the underlying classifier's own precision drops from the
rank-1-10 pools to `0.16` at rank-11-15, per
`reports/secure_code_primevul_side_inversion_review_queue_rank11_15_v1.json`)
-- the high rate of `insufficient_context` outcomes here (9 of 10 queued
rows) reflects that, not a change in review standards.
