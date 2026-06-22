# Cross-Model Replication

PR #12 asks whether VeriPatch-RR failures generalize across model mechanisms.
It intentionally avoids new Qwen readout variants, routers, calibration, or side-order architectures.

| model | type | canonical | swap residual | both correct | strict suffix | forced-only suffix | invalid | insufficient context | interpretation |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `non_qwen_decoder_classifier` | decoder_sequence_classifier | n/a | n/a | n/a | n/a | n/a | n/a | n/a | Pending prediction artifact; this slot tests whether endpoint sensitivity is Qwen-specific. |
| `generative_instruction_judge` | generative_instruction_judge | 46.67% | -0.0293 | 0.50% | 83.83% | 88.87% (566) | 5.00% | 0.00% | Generative judge measured with strict A/B/INSUFFICIENT_CONTEXT outputs. |

## Current Interpretation

- `partial_predictions` means at least one required model slot has been evaluated, while at least one remains pending.
- Generative judge rows use strict output parsing. Invalid outputs are not repaired or manually relabeled.
- Strict suffix consistency counts `INVALID` and `INSUFFICIENT_CONTEXT` as failures; forced-only suffix consistency is a secondary diagnostic over rows where both base and suffix outputs are forced A/B labels.
- If invalid output rate exceeds 20%, the row should be interpreted as a protocol-following limitation as well as a relational result.
- The current completed generative slot uses `Qwen/Qwen2.5-0.5B-Instruct`; it broadens the mechanism beyond classification heads, but it is not a non-Qwen-family replication.
- A low side-swap residual together with low both-directions-correct indicates that the judge is not reliably flipping its decision under A/B side swaps.

## Required Model Slots

- **Non-Qwen decoder classifier:** tests whether terminal/readout endpoint sensitivity is Qwen-specific or broader among decoder classifiers.
- **Generative instruction judge:** tests whether side-order inconsistency also appears without a classification head.

## Claim Boundary

This report is a model-family replication layer. It does not introduce new readout ablations, routers, calibration sweeps, or side-order architectures. Results answer whether relational failures appear across model mechanisms under the fixed VeriPatch-RR protocol.
