# Counterfactual Shortcut Intervention Protocol

## Research Question

Does a secure patch model change its decision when nuisance features change but patch security semantics should remain stable?

## VeriPatch-RR v0.1 Measurement Contract

| Intervention | Expected relation |
| --- | --- |
| Remove Project/CVE/CWE/Language headers | prediction invariant |
| Append numbered neutral comments after the complete diff | prediction invariant |
| Insert the same neutral comments before the diff | prediction invariant only on the no-truncation subset |
| Swap vulnerable/fixed side order through the canonical renderer | prediction flips equivariantly |
| Add 25/50/75% pre-diff context-budget pressure | reported separately; not treated as clean invariance when evidence is truncated |

Every intervention is represented by a standardized object containing the
transformed text, family, template, expected relation, validation tier,
validation basis, changed regions, and token accounting. Regex identifier
renaming and generic formatting normalization are excluded from the validated
v2 set until parser-aware implementations exist.

The benchmark JSONL is tokenizer-neutral. It stores complete prompt text,
exact changed-line occurrences and character spans, transformation metadata,
and runtime transformation instructions. Token counts and visibility are
materialized separately for each model.

The benchmark reports:

- transformed accuracy and robust accuracy
- relation violation rate
- probability relation error
- unexpected A-to-B and B-to-A changes
- no-critical-hunk-truncation results
- context-pressure results as a separate diagnostic
- pair-key cluster bootstrap intervals

## Commands

```powershell
.\.venv\Scripts\python.exe scripts\build_relational_benchmark_v2.py
```

The default build creates two suites:

- representative: seeded random sampling within each source, with sources
  macro-balanced in the combined primary suite
- balanced-stress: marginal balancing over diff and character-length buckets,
  with project and CWE concentration caps

Both suites sample `200` pairs from each of PrimeVul, DeltaSecommits, and
PatchEval with seed `42`. The report includes target and achieved marginals,
unavailable target buckets, maximum concentration, and effective project/CWE
counts.

Before inference, materialize the exact runtime:

```powershell
.\.venv\Scripts\python.exe scripts\materialize_relational_runtime.py `
  --model-id <model-id> `
  --tokenizer <tokenizer-id-or-path> `
  --max-length <model-input-limit> `
  --truncation-side right `
  --output data\processed\<model>-veripatch-rr-runtime.jsonl
```

Runtime accounting records tokenizer identity, special-token policy, token
counts, exact changed-line token spans, critical line/token visibility,
transformation-token visibility, and achieved context-pressure ratio.
Exact visibility accounting requires a fast tokenizer with native offset
mapping. Slow-tokenizer decode approximations are rejected rather than allowed
into the no-truncation analysis.

After model inference, produce one prediction row per benchmark `id` with:

- `id`
- `predicted_riskier_side` (`A`, `B`, or `INSUFFICIENT_CONTEXT`)
- `probability_a` when available

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_relational_benchmark_v2.py --predictions <prediction-jsonl>
```

## Claim Boundary

These interventions are controlled robustness checks, not proof that every
possible shortcut has been removed. A high violation rate under a validated
invariant transformation is causal evidence of nuisance sensitivity; a low
rate only protects the tested transformation family. Context-pressure rows can
change the evidence visible to a truncated model and therefore must not be
collapsed into the clean invariance headline.

Invalid outputs never satisfy a relation, even when both base and transformed
outputs are invalid. Reports distinguish protocol pass rate, relation accuracy
conditional on valid output, and end-to-end relation accuracy. Appropriate
abstention accuracy is intentionally absent until an independent
context-sufficiency label exists.

Headline metrics are computed only on the source-macro-balanced representative
suite. Balanced-stress results are reported independently. The evaluator also
emits `by_sampling_suite`, `by_dataset`, and
`by_sampling_suite_and_dataset`; it intentionally omits a mixed-suite
aggregate point estimate because the suites can share source pairs.
