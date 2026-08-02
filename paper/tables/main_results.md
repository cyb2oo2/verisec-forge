# Main Results Table Draft

> **STATUS: PARTIALLY WITHDRAWN AND NOT REGENERABLE.**
> This table cannot currently be rebuilt: `scripts/build_primevul_main_results.py`
> requires `reports/*_threshold_sweep.json` artifacts, and zero are present in the
> tree. Every number below is therefore **historical, unverified, and
> non-regenerable** until those artifacts are restored. Rows whose interpretation
> was withdrawn during the research-integrity remediation pass are marked inline.
> See [Research Integrity Verification](../../docs/RESEARCH_INTEGRITY_VERIFICATION.md)
> and [Remediation Notice](../../docs/RESEARCH_INTEGRITY_REMEDIATION.md).

## Provenance status

| Field | Value |
| --- | --- |
| Regenerable from tree | No — required threshold-sweep artifacts absent |
| Builder | `scripts/build_primevul_main_results.py` (now fails loudly; no fallback) |
| Threshold selection | `best_by_balanced_accuracy` **swept on the evaluation set**, not held out |
| Status of numbers | Historical, unverified |

## Historical results

| Stage | Question | Result (historical) | Interpretation |
| --- | --- | ---: | --- |
| Same-source detector | Can a standard split look strong? | `0.9524` accuracy | High headline score is artifact-sensitive. |
| Paired negative controls | Do the tested shortcuts explain pair success? | metadata `0.5022`, candidate `0.5078`, counterpart `0.5156` BA | These three controls are near chance. **They do not protect the diff-based claim**: all three remove the diff, so none tests diff structure. See the structural control row. |
| **Structural polarity control** | Does a semantics-free diff-shape rule solve the task? | see `reports/PRIMEVUL_POLARITY_STRUCTURAL_CONTROL.md` | **Added in remediation.** A rule reading only added/removed line counts is the correct floor for the diff-only rows below. |
| Diff-only paired detector | Is there real paired-diff signal? | three-seed mean BA `0.8287` | ~~Paired diff reasoning is the credible mainline.~~ **WITHDRAWN.** Must be read against the structural polarity control, not against chance. |
| Pair-coupled decoding | Does task-structured decoding help? | five-split BA `0.8572`; delta `+0.0348` | ~~Task-structured decoding improves held-out pair decision performance.~~ **WITHDRAWN.** The decoder consumes a closed-world cardinality constraint the baseline does not receive, and the reported interval came from overlapping splits. |
| Qwen side swap | Does pointwise competence imply side-order reasoning? | exact-contract swap `0.4600` | Near independence baseline. |
| CodeBERT side swap | Is failure Qwen-only? | exact-contract swap `0.5300` | Incomplete relational signal persists. |
| Endpoint gap | Is terminal collapse architecture dependent? | CodeBERT minus Qwen `+0.3767`, CI `[0.3317, 0.4200]` | Severe endpoint collapse is not reproduced by the encoder control. |
| Minimal broad replication | Do failures extend beyond original Qwen/CodeBERT classifiers? | distilgpt2 residual `-0.3410`; generative judge both-correct `0.50%` | Failure appears across additional mechanisms, but low canonical accuracy limits broad model-family claims. |
| Readout discovery | Can readout control endpoint sensitivity? | mean `0.8983`, changed-hunk `0.9983` post-diff consistency | Endpoint robustness is controllable. |
| Independent confirmation | Does the readout mechanism replicate? | suffix delta `+0.3095` mean / `+0.4903` changed-hunk | Mechanism replicates on new pairs/templates/seeds. |
| Frozen-backbone control | Is pooling itself causal over a fixed representation? | mean `+0.0260`; changed-hunk `+0.1970` | Mean is mainly training mediated; changed-hunk has direct structural effect. |

## Table Note

The readout rows are mechanism evidence. They do not establish canonical
non-inferiority and should not be described as promoted model improvements.

The negative-control row states a narrow fact: the three controls that *remove*
the diff score near chance. It does not license the broader claim that the
paired-diff formulation is shortcut-free, because a control that *retains* diff
structure while removing semantics was not part of the original suite.

Thresholds in the historical rows were selected by sweeping the evaluation set,
so the positive systems' numbers are optimistically biased. The negative-control
numbers are upper bounds under the same procedure, which makes "near chance" a
conservative reading for those rows only.
