# Example prompt: register a seed-sweep experiment

> **Worked examples use the current, scientifically supported result.**
> Under the closed-world pair constraint the detector reaches balanced accuracy
> `0.8596` and the strongest semantics-free structural control reaches `0.8588`;
> the delta is `+0.0008` with a pair-group clustered 95% CI spanning zero, so no
> semantic advantage beyond diff structure is established. Withdrawn values appear
> only inside an explicit audit example whose requested action is to reject the
> claim. Source of truth: `docs/RESULT_STATUS_LEDGER.md`.


```text
Use the research-experiment-manager skill.

I finished a 5-split pair-coupled decoding seed sweep. Outputs are under
outputs/pair_coupled_seed_sweep_v2/*.jsonl. Headline:
  constrained detector BA 0.8596; strongest semantics-free control BA 0.8588;
delta +0.0008; pair-group clustered 95% CI [-0.0202, +0.0222]; not
distinguishable from zero.

Please:
1. Confirm this serves the pair-coupled decoding extension goal.
2. Draft a reports/ markdown summary that includes negative controls / CI / seeds.
3. Propose an experiments/registry.json entry (layer=model_evidence,
   reproducibility=report-backed) with a *bounded* claim string.
4. Do not edit paper/ yet — only prepare the report + registry patch.
5. List the focused tests I should run before merge.
```
