# Main Claims

## Thesis

Pointwise secure-code accuracy is not relational patch understanding. A model
can classify individual vulnerable/fixed examples while failing to preserve
the relation between the two sides of a patch pair.

## Contributions

1. **Relational evaluation instrument.** VeriPatch-RR tests side-order
   equivariance, endpoint robustness, nuisance sensitivity, critical-hunk
   visibility, and both-directions-correct behavior under paired patch
   transformations.
2. **Cross-architecture failure decomposition.** Qwen and CodeBERT both show
   incomplete side-order reasoning, but the severe terminal endpoint collapse
   is not reproduced by the CodeBERT encoder control.
3. **Readout mechanism evidence.** Qwen readout interventions control
   endpoint sensitivity, yet do not produce side-order reasoning.
4. **Frozen-representation mechanism split.** Mean pooling's endpoint gain is
   mainly training mediated, while changed-hunk pooling retains a direct
   structural effect when the backbone representation is frozen.

## Claim Boundaries

- This is a research artifact and measurement study, not a deployed
  vulnerability scanner.
- The strongest claim is about relational evaluation and mechanism
  decomposition, not about a promoted high-accuracy model.
- The broad model-family claim is intentionally limited: current evidence
  covers a Qwen decoder classifier and a CodeBERT encoder classifier.
- Canonical non-inferiority is not established for readout variants.
- Side-order reasoning remains unresolved and is the intended Paper 2
  direction.
- Frozen-backbone results are conditional on the single terminal-seed7
  Qwen+LoRA representation; seeds 7 and 123 vary only matched linear heads.

## One-Sentence Version

VeriPatch-RR shows that secure-patch classifiers can be pointwise competent
yet relationally inconsistent, and that readout design can control endpoint
robustness without solving side-order reasoning.
