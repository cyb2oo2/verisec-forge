# Main Results Table Draft

| Stage | Question | Result | Interpretation |
| --- | --- | ---: | --- |
| Same-source detector | Can a standard split look strong? | `0.9524` accuracy | High headline score is artifact-sensitive. |
| Paired negative controls | Do shortcuts explain pair success? | metadata `0.5022`, candidate `0.5078`, counterpart `0.5156` BA | Controls are near chance, protecting diff-based claims. |
| Diff-only paired detector | Is there real paired-diff signal? | three-seed mean BA `0.8287` | Paired diff reasoning is the credible mainline. |
| Pair-coupled decoding | Does task-structured decoding help? | five-split BA `0.8572`; delta `+0.0348` | Pair structure improves consistency. |
| Qwen side swap | Does pointwise competence imply side-order reasoning? | exact-contract swap `0.4600` | Near independence baseline. |
| CodeBERT side swap | Is failure Qwen-only? | exact-contract swap `0.5300` | Incomplete relational signal persists. |
| Endpoint gap | Is terminal collapse architecture dependent? | CodeBERT minus Qwen `+0.3767`, CI `[0.3317, 0.4200]` | Severe endpoint collapse is not reproduced by the encoder control. |
| Readout discovery | Can readout control endpoint sensitivity? | mean `0.8983`, changed-hunk `0.9983` post-diff consistency | Endpoint robustness is controllable. |
| Independent confirmation | Does the readout mechanism replicate? | suffix delta `+0.3095` mean / `+0.4903` changed-hunk | Mechanism replicates on new pairs/templates/seeds. |
| Frozen-backbone control | Is pooling itself causal over a fixed representation? | mean `+0.0260`; changed-hunk `+0.1970` | Mean is mainly training mediated; changed-hunk has direct structural effect. |

## Table Note

The readout rows are mechanism evidence. They do not establish canonical
non-inferiority and should not be described as promoted model improvements.
