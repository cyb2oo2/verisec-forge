# Counterfactual Shortcut Intervention Protocol

## Research Question

Does a secure patch model change its decision when nuisance features change but patch security semantics should remain stable?

## Interventions

| Intervention | Expected relation |
| --- | --- |
| Remove Project/CVE/CWE/Language headers | prediction invariant |
| Normalize identifiers | prediction invariant |
| Normalize whitespace and formatting | prediction invariant |
| Add non-security comment padding | prediction invariant |
| Swap vulnerable/fixed side order | prediction flips equivariantly |
| Truncate unchanged context | confidence should fall or abstention should increase when context becomes insufficient |

The benchmark reports per-intervention unexpected-change rates rather than collapsing everything into one accuracy score.

## Commands

```powershell
.\.venv\Scripts\python.exe scripts\build_counterfactual_shortcut_benchmark.py --max-pairs 200
```

After running the detector or joint model on the materialized intervention rows, produce a JSONL containing:

- `intervention`
- `expected_relation`
- `base_pred`
- `intervention_pred`
- `base_confidence`
- `intervention_confidence`
- `intervention_abstain`

Then run:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_counterfactual_shortcut_predictions.py --predictions <prediction-jsonl>
```

## Claim Boundary

These interventions are controlled robustness checks, not proof that every possible shortcut has been removed. A high flip rate under invariant transformations is causal evidence that the model relies on nuisance features; a low flip rate only protects the tested intervention family.
