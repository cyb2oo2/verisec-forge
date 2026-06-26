# External Participation Guide

This guide describes lightweight ways to participate in VeriSec Forge /
VeriPatch-RR. It is for feedback and replication-oriented contributions, not
for submitting unsupported benchmark claims.

## 1. Give Claim-Strength Feedback

Start with `docs/EXTERNAL_FEEDBACK_PACKET.md`. Useful feedback includes:

- whether the main thesis is too broad, too narrow, or correctly bounded;
- whether the distinction between competency-controlled evidence and
  low-canonical stress evidence is clear;
- whether readout mechanism claims are convincing without overclaiming model
  improvement;
- whether the limitations are strong enough for a security/ML systems audience.

## 2. Run Your Own Model Through the External Adapter

Start with `docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md`. The external smoke path
accepts one prediction row per benchmark `id`:

```json
{
  "id": "benchmark row id",
  "predicted_riskier_side": "A | B | A_RISKIER | B_RISKIER | INSUFFICIENT_CONTEXT"
}
```

The checked-in 30-pair / 90-row smoke artifact is an adapter sanity check. It
is not a model-quality benchmark and is not tokenizer-neutral for other model
claims.

## 3. Suggest Related Work or Limitations

Useful suggestions should point to a specific section or claim boundary:

- missing related work for paired patch evaluation;
- stronger language for limitations;
- failure cases where the current evidence hierarchy is unclear;
- security-review concerns not covered by the current draft.

## Where To Send Feedback

For lightweight comments, email the maintainer directly or open a GitHub issue
using the preferred feedback format below.

For prediction submissions, open an issue and attach:

- the model name;
- the command used;
- the prediction file;
- the generated evaluation report.

Please do not open PRs that change claims or result interpretation without
first opening an issue.

## What Not To Submit

- New unsupported benchmark claims.
- Unverified model-quality claims from the 30-pair smoke artifact.
- Manual relabeling of invalid predictions.
- Claims that readout variants are promoted classifiers.
- Claims that low-canonical stress slots prove universal strong-model failure.

## Preferred Feedback Format

Use short, specific notes:

```text
Section or file:
Concern:
Why it matters:
Suggested fix:
```

For prediction submissions, include the command used, the prediction file, and
the generated evaluation report.
