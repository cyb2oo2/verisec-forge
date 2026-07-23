# Pair Annotation — Paper Claim Boundary

Use this block when mentioning the human pair audit in drafts, abstracts, or rebuttals.

## Recommended statement

The human pair audit is a stratified 50-pair single-author annotation under blinded packet presentation (metadata scrubbed; sides randomized). It supports qualitative evidence-coupled error analysis and author-facing case review. It is not independent dual-rater gold, does not report inter-annotator Cohen's κ, is not a prevalence estimate for PrimeVul, is not AI pilot labeling, and must not be promoted as a model-quality benchmark or replacement for the pair-coupled decoding mainline metrics.

## Allowed vs disallowed framings

| Framing | Allowed? |
| --- | --- |
| Stratified author audit (n=50) for qualitative evidence review | Yes |
| Dual independent human gold / inter-annotator κ | No |
| AI pilot or draft adjudication as human gold | No |
| Full-benchmark prevalence | No |
| Substitute for pair-coupled decoding mainline accuracy | No |
| Same claim as the 30-row evidence-localization human rounds | No |

## Artifact pointers

- Protocol: `docs/HUMAN_PATCH_PAIR_ANNOTATION_PROTOCOL.md`
- Study report: `reports/PRIMEVUL_PAIR_ANNOTATION_STUDY_V1.md`
- Status JSON: `reports/secure_code_primevul_pair_annotation_status_v1.json`
