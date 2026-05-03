# PrimeVul Side-Inversion Verifier Dataset

This artifact converts the side-inversion review queue into a strict `accept_flip` / `reject_flip` verifier task. It defines the next verifier target; it is not a trained verifier result.

## Summary

- Rows: `25`
- Unique pair keys: `23`
- Accept / reject rows: `8` / `17`
- Accept rate: `0.32`
- Average prompt chars: `2685.44`
- Max prompt chars: `4666`

## Output Contract

```json
{"accept_flip": true, "reason_code": "evidence_supports_flip", "evidence_side": "B", "confidence": "medium"}
```

## Boundary

Gold labels are included to define supervised targets and offline metrics. A deployment verifier must only consume the prompt fields and produce the JSON contract.
