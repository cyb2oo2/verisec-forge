# External Model Report Card

This document defines how an external user should summarize a model run through
the VeriPatch-RR external adapter. It is a reporting template.

It is not a new benchmark. It is not a leaderboard row. It is not a
model-quality claim.

Use the fillable template at
`reports/templates/external_model_report_card.md` when submitting results.

## When To Use This

Use this report card after you have:

1. generated predictions with the external adapter contract;
2. evaluated them with `scripts/evaluate_veripatch_external.py`;
3. retained the prediction file and generated evaluation report.

The checked-in 30-pair / 90-row smoke artifact is an adapter sanity check. It
can show whether a model wrapper and prediction file satisfy the contract. It
must not be used to claim model quality.

It is not a model-quality benchmark.

## Required Submission Contents

Include:

- model name and version;
- prediction command or script entry point;
- benchmark artifact path;
- prediction file path;
- generated evaluation report path;
- whether the model can abstain;
- any model-specific runtime materialization used for visibility claims.

If runtime materialization is not model-specific, do not make runtime visibility
claims for that model.

## Minimum Interpretation Rules

- Report pointwise metrics separately from relational metrics.
- Treat side-swap, suffix, and robust accuracy as relation tests, not ordinary
  vulnerability-detection accuracy.
- State whether the result came from the 30-pair smoke artifact or a retained
  full VeriPatch-RR report.
- State whether runtime visibility is model-tokenizer specific.
- Do not manually repair invalid labels.

## What Not To Claim

- Do not call the 30-pair smoke artifact a benchmark result.
- Do not compare models from smoke artifacts as if they were leaderboard rows.
- Do not claim tokenizer-neutral runtime visibility from the checked-in smoke
  artifact.
- Do not treat abstention behavior as comparable unless the model contract and
  `supports_abstention` setting are reported.
- Do not use a report card as endorsement by the VeriSec Forge maintainers.

## Preferred Submission Path

Open a GitHub issue only after the prediction file and generated evaluation
report are available. Use the report-card template and keep interpretation
bounded to the artifact actually evaluated.
