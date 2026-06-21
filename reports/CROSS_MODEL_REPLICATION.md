# Cross-Model Replication

PR #12 asks whether VeriPatch-RR failures generalize across model mechanisms.
It intentionally avoids new Qwen readout variants, routers, calibration, or side-order architectures.

| model | type | canonical | swap residual | both correct | suffix consistency | invalid | insufficient context | interpretation |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `non_qwen_decoder_classifier` | decoder_sequence_classifier | n/a | n/a | n/a | n/a | n/a | n/a | Pending prediction artifact; this slot tests whether endpoint sensitivity is Qwen-specific. |
| `generative_instruction_judge` | generative_instruction_judge | n/a | n/a | n/a | n/a | n/a | n/a | Pending prediction artifact; this slot tests whether side-order failure appears without a classification head. |

## Required Model Slots

- **Non-Qwen decoder classifier:** tests whether terminal/readout endpoint sensitivity is Qwen-specific or broader among decoder classifiers.
- **Generative instruction judge:** tests whether side-order inconsistency also appears without a classification head.

## Claim Boundary

This report is a model-family replication layer. It does not introduce new readout ablations, routers, calibration sweeps, or side-order architectures. Results answer whether relational failures appear across model mechanisms under the fixed VeriPatch-RR protocol.
