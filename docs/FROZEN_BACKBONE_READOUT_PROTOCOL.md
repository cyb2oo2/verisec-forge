# Frozen-Backbone Readout Control Protocol

## Question

The confirmed readout study changes both the pooling rule and the
fine-tuning trajectory. This control asks whether pooling itself changes
terminal-context robustness when the Qwen backbone and LoRA representation
are held fixed.

## Frozen Representation

The complete backbone and LoRA parameters from
`readout_confirmatory_qwen15b_terminal_seed7_v1` are frozen. A single forward
pass over each input produces the same final hidden states for all candidates.
From those hidden states, the study caches:

- the terminal non-padding token;
- the attention-masked mean;
- the attention-masked changed-hunk mean, with explicit fallback accounting.

No backbone, LoRA, embedding, or tokenizer parameter is updated.

## Matched Heads

Each readout receives a newly initialized linear `hidden_size -> 2` head.
Within a seed, all heads start from identical weights and use identical:

- 3,000 training pair keys and cached hidden states;
- pair ordering and mini-batches;
- classification, pair-margin, and complementary-probability loss;
- AdamW optimizer, learning rate, weight decay, epochs, and steps.

Seeds `7` and `123` are fixed before confirmatory evaluation. The independent
180-pair readout-confirmation set is never used for optimization, epoch
selection, or hyperparameter selection.

Seeds `7` and `123` vary only the matched linear-head initialization and
training order. All results are conditional on the single terminal-seed7 frozen
Qwen backbone and LoRA representation; they are not independent
backbone-training seeds.

## Endpoints

The terminal head is the control. Mean and changed-hunk are compared on:

- canonical accuracy;
- visible-only unseen-suffix consistency;
- side-swap equivariance and its marginal-conditioned independence baseline;
- both-directions-correct;
- source-wise deltas;
- changed-hunk fallback.

## Interpretation

- A persistent suffix gain supports a direct pooling/readout effect.
- A strongly reduced gain supports an indirect gradient-flow or learned-
  representation mechanism.
- A persistent changed-hunk gain but unstable mean gain supports structural
  exclusion of suffix tokens as the dominant changed-hunk mechanism.

This experiment does not attempt to solve side-order reasoning.

## Claim Boundary

The experiment freezes one terminal-trained Qwen checkpoint. It isolates
readout over that representation but does not establish broad model-family
generality. Pair-bootstrap intervals remain conditional on the two selected
head-training seeds, which vary only the matched linear heads and training
order over the single terminal-seed7 frozen Qwen+LoRA representation.
