# VeriPatch-RR External Adapter

This adapter lets an external user evaluate their own predictions against a
fixed VeriPatch-RR artifact. It does not run a model. The user supplies one
prediction row per benchmark `id`.

## Prediction Contract

Each prediction row must contain:

```json
{
  "id": "benchmark row id",
  "predicted_riskier_side": "A | B | A_RISKIER | B_RISKIER | INSUFFICIENT_CONTEXT"
}
```

Optional fields:

- `probability_a`
- `confidence`
- `supports_abstention`

Invalid labels are rejected by the external adapter. They are not repaired or
manually relabeled.

If your model cannot abstain, set `supports_abstention=false` or omit the
field. The generated template sets it to `true` because the external contract
allows `INSUFFICIENT_CONTEXT`.

## Smoke Quickstart

Create or refresh the 30-pair smoke artifact:

```powershell
.\.venv\Scripts\python.exe scripts\build_veripatch_external_smoke.py
```

Generate a prediction template:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_veripatch_external.py `
  --benchmark examples\veripatch_rr_smoke_30.jsonl `
  --write-template examples\my_predictions.jsonl
```

Fill `examples\my_predictions.jsonl` by running your model over each row's
`text` field. A minimal model wrapper should implement:

```python
def predict(text: str) -> str:
    return "A"  # or "B" or "INSUFFICIENT_CONTEXT"
```

The generated template is intentionally invalid until predictions are filled.
Running evaluation on an unfilled template will fail schema validation.

Evaluate:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_veripatch_external.py `
  --benchmark examples\veripatch_rr_smoke_30.jsonl `
  --predictions examples\my_predictions.jsonl `
  --output reports\my_veripatch_rr_smoke_eval.json
```

## Claim Boundary

The bundled smoke set is a small sanity check for external integration. It is
not a benchmark result and should not be used to claim model quality. Full
VeriPatch-RR claims require model-specific runtime materialization and the
retained benchmark reports.

The checked-in smoke artifact uses distilgpt2 runtime accounting only as a
small adapter sanity check. It is not tokenizer-neutral and must not be used
for full claims about another model's runtime visibility.
