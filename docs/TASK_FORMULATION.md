# Task definition

The measurement question is candidate identity: given two related code states A and B, which state is riskier? A valid renaming changes the answer label; a valid reversal of diff direction with identities preserved should preserve the candidate answer.

This differs from asking whether a directional patch fixes or introduces a vulnerability. Legal unified diffs use signs, headers and order to identify source and target code. Do not create an inconsistent diff and call the transformation semantics preserving.

Current transformations jointly change direction, order, hunk layout or naming. They support behavioral sensitivity, not isolation of a single token or internal mechanism. Label-only prediction inertia is a binding failure because the correct label must change.

Consistency is necessary but insufficient: choosing the shorter candidate can be perfectly consistent. Future validation must include security-semantic changes and a simple candidate-binding positive control.

Historical datasets force one vulnerable and one secure candidate. Both-safe, both-vulnerable, incomplete fixes and insufficient context need separate evaluation. Changed-line visibility does not establish sufficient security context.

See the [current review](../reports/scientific_review_2026_09_07/REVIEW.md).
