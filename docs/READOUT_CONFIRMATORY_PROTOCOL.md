# Independent Readout Confirmatory Protocol

## Frozen Discovery Boundary

PR #8 and its 600 audit pairs are discovery-only. Their pair IDs, suffix
templates, and seed `42` are excluded from confirmatory selection and model
promotion.

## Candidates

Only two candidates selected before confirmatory evaluation are tested:

- `mean`;
- `changed_hunk`.

The terminal-token readout is the control. First-token and fixed-anchor
readouts are not reconsidered.

## Training Replication

Each candidate and the terminal control are trained with seeds `7` and `123`.
All other components remain fixed:

- Qwen2.5-Coder-1.5B pair-diff initialization;
- 3,000 PrimeVul training pairs;
- deterministic length-bucket ordering conditional on seed;
- LoRA targets and trainable classification head;
- classification, margin, and complementary-probability objective;
- one epoch, 375 optimizer steps, maximum length `1024`.

## Independent Evaluation Set

The confirmatory set contains 180 pair IDs not present in the discovery
instrument:

- 60 PrimeVul;
- 60 DeltaSecommits;
- 60 PatchEval.

Selection seed is `20260613`. Each pair receives:

- canonical rendering;
- canonical side swap;
- unseen short neutral suffix;
- unseen medium neutral suffix;
- unseen long neutral suffix.

The three suffix templates contain 8, 32, and 96 neutral comment lines and
were not used in discovery.

## Primary Endpoints

For each seed and pooled across seeds:

- canonical accuracy;
- suffix consistency at each unseen length;
- macro-average suffix consistency;
- side-swap equivariance and marginal-conditioned independence baseline;
- both-directions-correct rate;
- changed-hunk fallback rate;
- critical-hunk visibility.

Canonical accuracy is evaluated on all 180 pairs. Suffix consistency is
evaluated only on pair/template rows where at least one transformation token
remains visible after tokenization and truncation; visibility coverage is
reported separately.

## Confirmatory Success Rule

A candidate is confirmed only if:

1. the pair-cluster bootstrap 95% CI lower bound for its macro suffix
   consistency delta versus terminal is greater than `0`; and
2. the pair-cluster bootstrap 95% CI lower bound for canonical accuracy delta
   is at least `-0.02`; and
3. both seeds have positive macro suffix consistency deltas.

This is a new post-discovery non-inferiority protocol. It does not retroactively
change the symmetric equivalence rule used in PR #8.

## Statistical Scope

Pooled bootstrap intervals resample held-out pair clusters after averaging
the results from training seeds `7` and `123`. They quantify pair-level
uncertainty conditional on these two selected seeds; they do not estimate the
variance induced by drawing arbitrary training seeds from a seed population.
Seed-wise effects are therefore reported separately, and the confirmation
rule additionally requires a positive suffix delta in both seeds.

## Claim Boundary

The study confirms or rejects two preselected readout-conditioned training
candidates on new pair IDs and nuisance templates. It does not isolate frozen
representation pooling; that remains a separate control.
