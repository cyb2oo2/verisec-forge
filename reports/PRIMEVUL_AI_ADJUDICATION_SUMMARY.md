# PrimeVul AI Adjudication Summary

This report consolidates the adjudication pass over the high-quality disagreement and insufficient-context queues.
Once every row carries a non-AI reviewer, it reports human-confirmed labels for this 20-row set; it is still not project-wide independent human gold.

## Summary

- Rows: `20`
- AI-filled rows: `0`
- Human-confirmed rows: `20`
- Final human gold: `false`
- CSV table: `reports/secure_code_primevul_ai_adjudication_summary_v1.csv`

## Label Status Counts

- `confirmed_gold`: `3`
- `corrected_side`: `6`
- `insufficient_context`: `11`

## By Queue

- `high_quality_disagreement`: corrected_side=`5`, insufficient_context=`1`
- `insufficient_context`: confirmed_gold=`3`, corrected_side=`1`, insufficient_context=`10`

## Evidence Span Sufficiency

- `no`: `7`
- `partial`: `10`
- `yes`: `3`

## Corrected-Side Cases

| Queue | Project | CVE | Bucket | Final Side | Evidence | Rationale |
| --- | --- | --- | --- | --- | --- | --- |
| `high_quality_disagreement` | `squid` | `CVE-2021-46784` | `26+` | `B` | `yes` | Side B removes bounded snprintf temporary-buffer handling and reintroduces appendf formatting; selected window directly supports the pilot side. Independently confirmed by human reviewer; AI draft (reviewer=codex_ai_adjudication_v1) verdict and evidence sufficiency retained as-is after manual review of code diff windows. |
| `high_quality_disagreement` | `gnutls` | `CVE-2008-1948` | `11-25` | `A` | `yes` | Side A removes the short-record ciphertext length check; selected window directly supports the pilot side. Independently confirmed by human reviewer; AI draft (reviewer=codex_ai_adjudication_v1) verdict and evidence sufficiency retained as-is after manual review of code diff windows. |
| `high_quality_disagreement` | `squid` | `CVE-2021-46784` | `26+` | `A` | `yes` | Side A removes bounded snprintf temporary-buffer handling and reintroduces appendf formatting; selected window directly supports the pilot side. Independently confirmed by human reviewer; AI draft (reviewer=codex_ai_adjudication_v1) verdict and evidence sufficiency retained as-is after manual review of code diff windows. |
| `high_quality_disagreement` | `linux-2.6` | `CVE-2009-3238` | `11-25` | `B` | `partial` | Side B removes the replacement RNG path and restores custom key-hash random generation; selected window supports the pilot side but wider function context would strengthen confidence. Independently confirmed by human reviewer; AI draft (reviewer=codex_ai_adjudication_v1) verdict and evidence sufficiency retained as-is after manual review of code diff windows. |
| `high_quality_disagreement` | `linux` | `CVE-2020-36558` | `11-25` | `B` | `partial` | Side B removes resize_user and font resize handling around console resize; selected windows support the pilot side but wider surrounding logic would strengthen confidence. Independently confirmed by human reviewer; AI draft (reviewer=codex_ai_adjudication_v1) verdict and evidence sufficiency retained as-is after manual review of code diff windows. |
| `insufficient_context` | `linux` | `CVE-2020-12768` | `11-25` | `A` | `partial` | Side A removes save-area cleanup/error-path protection while B restores cleanup structure; selected evidence favors correcting the stored gold side. Independently confirmed by human reviewer; AI draft (reviewer=codex_ai_adjudication_v1) verdict and evidence sufficiency retained as-is after manual review. |

## Interpretation

All 20 rows now carry a non-AI reviewer; the project may report these as reviewer-confirmed labels for this 20-row set, not as AI-filled adjudication.
The large remaining `insufficient_context` count is useful: it shows that evidence-window localization often needs wider code context before a trustworthy final side label can be assigned.
