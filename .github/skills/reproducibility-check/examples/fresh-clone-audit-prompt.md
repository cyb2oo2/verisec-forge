# Example prompt: fresh-clone reproducibility audit

> **Worked examples use the current, scientifically supported result.**
> Under the closed-world pair constraint the detector reaches balanced accuracy
> `0.8596` and the strongest semantics-free structural control reaches `0.8588`;
> the delta is `+0.0008` with a pair-group clustered 95% CI spanning zero, so no
> semantic advantage beyond diff structure is established. Withdrawn values appear
> only inside an explicit audit example whose requested action is to reject the
> claim. Source of truth: `docs/RESULT_STATUS_LEDGER.md`.


```text
Use the reproducibility-check skill.

Act as if this is a clean clone on a new machine:
1. State the exact install + smoke commands (PowerShell and bash).
2. Run the five focused smoke tests from ci.yml.
3. Run scripts/build_reproducibility_bundle.py --manifest
   reproducibility/veripatch_external_smoke_manifest.json --check-only.
4. If any hash mismatches, treat them as stop-the-line (do not re-hash).
5. For the claim "the detector shows no advantage over the strongest
   semantics-free structural control (0.8596 vs 0.8588, delta +0.0008)", trace
   report → registry → result_anchor_map and tag the reproducibility level.
```
