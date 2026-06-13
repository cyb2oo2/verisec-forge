# Same-Backbone Readout Ablation Protocol

## Research Question

Does readout design causally control terminal-context robustness for a fixed
Qwen2.5-Coder-1.5B secure-patch classifier?

## Frozen Components

Every run uses:

- the same pair-diff initialization checkpoint;
- the same 3,000 PrimeVul training pairs and deterministic length-bucket order;
- the same LoRA targets and trainable classification head;
- the same classification, margin, and complementary-probability objective;
- seed `42`, one epoch, 375 optimizer steps, and maximum length `1024`;
- the frozen 600-pair, eight-variant cross-model relational audit.

Only the hidden-state readout changes.

## Readouts

1. `terminal`: final non-padding token; exact control for the current Qwen head.
2. `first_token`: first attended token.
3. `mean`: attention-mask-weighted mean over visible tokens.
4. `changed_hunk`: mean over tokens overlapping changed diff lines, with a
   visible-token mean fallback when no changed token survives.
5. `fixed_terminal_anchor`: a fixed task-completion suffix whose tokens are
   reserved before truncation, followed by terminal-token readout.

## Primary Endpoints

- canonical accuracy;
- post-diff relation accuracy;
- terminal-phrase relation accuracy;
- side-swap equivariance;
- marginal-conditioned independent-decision swap baseline;
- both-directions-correct rate;
- clean pair coverage and conditional clean robust accuracy.

The primary method comparison is each non-terminal readout versus the retrained
`terminal` control on identical pair keys.

## Success Criterion

A readout is considered a successful robustness intervention only if:

1. post-diff relation accuracy improves materially over the retrained terminal
   control with a pair-bootstrap confidence interval excluding zero; and
2. canonical accuracy changes by no more than `0.02` in absolute value.

Side-swap and robust-accuracy changes are secondary endpoints. A readout that
improves consistency by collapsing predictions to one side is not successful.

## Statistical Protocol

- Pair-cluster bootstrap uses the fixed audit pair key.
- Report all readouts, not only the best one.
- Report aggregate and per-source effects for PrimeVul, DeltaSecommits, and
  PatchEval.
- Report jointly clean and both-canonical-correct subsets.
- Treat seed `42` as the discovery experiment. Any selected readout requires
  seeds `7` and `123` before a general method claim.

## Claim Boundary

The discovery matrix tests a causal readout intervention within one Qwen
checkpoint family. It does not isolate every difference between decoder and
encoder architectures and does not establish broad model-family generality.
The fixed-terminal-anchor readout changes the effective truncation budget and
therefore requires separately materialized runtime accounting before any clean
subset claim.
