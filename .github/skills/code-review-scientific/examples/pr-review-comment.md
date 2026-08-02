# Example PR review comment (scientific)

> Generated with the `code-review-scientific` skill. Adapt; do not paste blindly.

### Scientific review

**Summary:** Useful mechanism ablation, but the paper sentence overstates transfer
and the significance test should be paired.

#### Blocking
- `paper/draft_v0.md` calls CrossVul transfer "strong open-set generalization."
  Existing claim boundary is *bounded* source-aware transfer
  (`reports/CROSSVUL_ZERO_SHOT_PRIMEVUL_CHECKPOINT.md`). Rewrite to match the
  registry boundary before merge.

#### Non-blocking
- Prefer paired bootstrap over the same pair IDs instead of unpaired t-tests on
  row accuracy (house style in pair-coupled significance reports).
- Log de-confound stats (`orientation_vs_gold`, vuln-side rate) in the new
  preprocess script output, matching other materializers.

#### Questions
- Is seed `42` intentional for the confirmatory split, or should this match the
  preregistered seeds `7` / `123`?

#### Praise
- Negative controls remain in the same table as the positive delta.
- Manifest `--check-only` path added in the same PR as the artifact.

**Rubric:** scope=pass design=pass stats=needs work repro=pass claims=blocking software=pass
