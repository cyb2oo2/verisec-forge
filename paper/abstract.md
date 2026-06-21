# Abstract Draft

Secure-code models are commonly evaluated with pointwise vulnerability or
patch labels, but high pointwise accuracy can hide failures in relational
reasoning. We study this gap with VeriPatch-RR, a paired vulnerable/fixed
patch benchmark that tests whether model decisions remain consistent under
side swaps, suffix perturbations, context pressure, and model-specific
runtime visibility constraints.

Across a Qwen decoder classifier and a CodeBERT encoder classifier, we find
that pointwise competence does not imply side-order consistency. Both models
remain close to marginal-conditioned independent-decision baselines under
side swaps, even when evaluated with each model's own training contract.
However, severe terminal-context collapse is architecture dependent: Qwen is
strongly affected by post-diff endpoint text, while the CodeBERT first-token
encoder control is not.

We then isolate the Qwen readout mechanism. Same-backbone readout ablations
and an independent confirmation set show that endpoint robustness can be
controlled by readout-conditioned training, but this does not solve
side-order reasoning. A frozen-backbone matched-head control further separates
mechanisms: mean pooling's suffix benefit largely disappears when the
terminal-trained Qwen+LoRA representation is held fixed, while changed-hunk
pooling retains a direct suffix-consistency gain. These results support a
bounded claim: endpoint robustness is controllable, but secure patch
relational reasoning remains a distinct unresolved capability.

We release manifests, public bundles, and paper-facing figures to make the
measurement instrument reproducible and to support follow-up work on
antisymmetric side-order models.
