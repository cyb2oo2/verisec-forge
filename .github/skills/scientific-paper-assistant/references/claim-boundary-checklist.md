# Claim-Boundary Checklist

Run this over every quantitative sentence before it lands in `paper/`.

- [ ] The number appears verbatim in a `reports/*.md` file.
- [ ] The report is listed in `paper/result_anchor_map.md`.
- [ ] Confidence interval / spread is included (not just a point estimate).
- [ ] Sample size (`n=`) or seed count is stated for any mean.
- [ ] The sentence names the boundary ("but not…", "this is X, not Y").
- [ ] Evidence tier is correct: measurement ≠ mechanism ≠ model improvement.
- [ ] No smoke/pilot result is dressed up as a benchmark or model-quality claim.
- [ ] Negative controls are reported near the positive result.
- [ ] Every citation key resolves to a real, verifiable reference.
- [ ] Any unverifiable claim/citation is marked `TODO`, not fabricated.

## House-style phrasings
- "improves robustness, but this is not open-set expert discovery"
- "a post-hoc structural control, not evidence of stronger reasoning"
- "discovery-stage mechanism result rather than a promoted model improvement"
