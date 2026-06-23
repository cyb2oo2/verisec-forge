# Cross-Model Replication

PR #12 asks whether VeriPatch-RR failures generalize across model mechanisms.
It intentionally avoids new Qwen readout variants, routers, calibration, or side-order architectures.

| model | type | canonical | swap residual | both correct | strict suffix | forced-only suffix | invalid | insufficient context | interpretation |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `non_qwen_decoder_classifier` | decoder_sequence_classifier | 55.83% | -0.3410 | 6.67% | 74.33% | 74.33% (600) | 0.00% | 0.00% | Non-Qwen decoder classifier measured under fixed VeriPatch-RR. |
| `generative_instruction_judge` | generative_instruction_judge | 46.67% | -0.0293 | 0.50% | 83.83% | 88.87% (566) | 5.00% | 0.00% | Generative judge measured with strict A/B/INSUFFICIENT_CONTEXT outputs. |

## Prediction Distribution

| model | distribution | interpretation |
| --- | --- | --- |
| `non_qwen_decoder_classifier` | A=452, B=1348 | Used to diagnose label/side inertia before interpreting suffix consistency. |
| `generative_instruction_judge` | A=1620, B=90, INVALID=90 | Used to diagnose label/side inertia before interpreting suffix consistency. |

## Current Interpretation

- `ok` means both required PR #12 model slots have prediction artifacts.
- This report uses the representative suite with a representative-core filtered runtime containing canonical, side-swap, and suffix rows.
- Low canonical accuracy should be treated as a competency limitation before making broad model-family claims.
- Because both new PR #12 slots have low canonical accuracy, this is stress evidence for relational failure modes, not competency-controlled evidence that strong models universally fail.
- Runtime visibility is model-tokenizer specific; higher critical-hunk truncation weakens direct comparability with models that see more of the changed hunk.
- Generative judge rows use strict output parsing. Invalid outputs are not repaired or manually relabeled.
- Strict suffix consistency counts `INVALID` and `INSUFFICIENT_CONTEXT` as failures; forced-only suffix consistency is a secondary diagnostic over rows where both base and suffix outputs are forced A/B labels.
- If invalid output rate exceeds 20%, the row should be interpreted as a protocol-following limitation as well as a relational result.
- The current completed generative slot uses `Qwen/Qwen2.5-0.5B-Instruct`; it broadens the mechanism beyond classification heads, but it is not a non-Qwen-family replication.
- A low side-swap residual together with low both-directions-correct indicates that the judge is not reliably flipping its decision under A/B side swaps.
- The generative judge is strongly side-biased; therefore its suffix consistency should be interpreted as decision stability, not evidence of correct patch reasoning.

## Required Model Slots

- **Non-Qwen decoder classifier:** tests whether terminal/readout endpoint sensitivity is Qwen-specific or broader among decoder classifiers.
- **Generative instruction judge:** tests whether side-order inconsistency also appears without a classification head.

## Claim Boundary

This report is a model-family replication layer. It does not introduce new readout ablations, routers, calibration sweeps, or side-order architectures. Results answer whether relational failures appear across model mechanisms under the fixed VeriPatch-RR representative suite / representative-core filtered-runtime protocol. Because the new PR #12 slots have low canonical accuracy, they are treated as stress evidence for relational failure modes, not as competency-controlled evidence that strong models universally fail.
