# PrimeVul Progressive Controls


> **CORRECTED — CONTAINS WITHDRAWN RESULTS.**
> Under the closed-world pair constraint the detector reaches balanced accuracy `0.8596`;
> a semantics-free character-level diff structural control reaches `0.8588` on the same
> evaluation population (difference `+0.0008`, pair-group clustered 95% CI
> `[-0.0202, +0.0222]`, sign test 19 vs 18, `p=1.0`).
> **No semantic advantage beyond diff structure was established.**
> The evidence-localization contrast and the `1.0000` safe-flip gate precision are also
> withdrawn. Current status: [Result Status Ledger](../docs/RESULT_STATUS_LEDGER.md).
This table compresses the PrimeVul research story into a small set of controls and system stages. It is designed for project overviews, application material, and reviewer orientation rather than exhaustive experiment comparison.

## Summary

![PrimeVul progressive controls](assets/primevul_progressive_controls.svg)

- Rows: `8`
- Headline: No semantic advantage beyond diff structure was established: a semantics-free character-level diff control matches the detector under the pair constraint (0.8588 vs 0.8596). The contribution is the measurement of shortcut-driven performance.
- Main limitation: Evidence localization and safe flip gates remain pseudo-label/small-queue diagnostics.

## Progressive Table

| stage | research question | key metric | value | supporting metric | interpretation |
| --- | --- | --- | ---: | --- | --- |
| Same-source baseline | Can a standard split look solved? | balanced_accuracy | 0.9524 | recall=0.9709, specificity=0.9339 | High score, but treated as artifact-sensitive rather than robust evidence. |
| Paired stress test | Does the same model survive vulnerable/fixed pairing? | balanced_accuracy | 0.4961 | threshold=0.9999 | Near-chance paired behavior invalidates the easy same-source headline. |
| Shortcut controls | Can metadata/candidate/counterpart controls explain the result? | best_control_balanced_accuracy | 0.5156 | metadata/candidate/counterpart controls | These three controls remove the diff, so they bound metadata and single-side context only. They do NOT protect the paired-diff formulation: a semantics-free character-level diff control reaches 0.8588 under the pair constraint. |
| Paired diff detector | Does diff-only reasoning form a stable harder-split signal? | three_seed_mean_balanced_accuracy | 0.8287 | range=0.8158-0.8382 | WITHDRAWN as a semantic result. Matched by a semantics-free character-level diff control; no advantage beyond diff structure established. |
| No-metadata check | Does the paired diff signal depend on Project/CVE/CWE prompt metadata? | balanced_accuracy | 0.8244 | threshold=0.8 | Removing metadata preserves the signal. |
| Pair-coupled decoding | Does enforcing paired consistency improve decisions? | mean_balanced_accuracy | 0.8572 | delta_bal=0.0348, delta_group=0.1114 | Pair-coupled decoding gives stable row-level and group-level gains. |
| Evidence propagation | Is evidence localization independent of side decisions? | predicted_side_top1 | 0.6555 | side_correct_top1=0.761, side_wrong_top1=0.0632 | WITHDRAWN. The target is antisymmetric in the predicted side, so this contrast is an identity of the labelling function, not a measurement. |
| Safe flip gate | Can high-confidence side inversions be repaired safely? | project_holdout_accept_precision | 1.0000 | accepted=9, introduced=0, stress_invalidated=1 | WITHDRAWN as a validated claim. Precision 1.0 rests on 4 accepted pairs (exact 95% CI [0.3976, 1.0]) and the gate was selected on the pool it is reported on. |

## Reading Order

Start with shortcut diagnosis, then paired diff controls, then pair-coupled decoding. Treat evidence localization and safe flip gates as the audit-loop extension, not as the main performance headline.
