# Counterfactual Shortcut Intervention Protocol

## Research Question

Does a secure patch model change its decision when nuisance features change but patch security semantics should remain stable?

## V2 Measurement Contract

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

The default build samples `200` pairs from each of PrimeVul, DeltaSecommits,
and PatchEval using seed `42`, stratified by language, CWE, diff size, token
length, project, and year.

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
