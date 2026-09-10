# VeriSec Forge / VeriPatch-RR

**Evaluating whether AI security judgments follow the code when its presentation changes.**

VeriSec Forge studies language-model assessment of paired code candidates. Its central question is whether a model tracks the relevant candidate across changes in order, labels, and presentation, and what an evaluation can legitimately tell us about security reasoning.

**Current status: measurement validation, source-data repair, and preparation for a small weak-supervision pilot.** The September 7 scientific review, including its subsequent updates, supersedes earlier result narratives. No transferable learned repair or deployment-ready vulnerability detector is established.

## Start here

- [Current research review: English summary](reports/public_review_2026_09_10/REVIEW.md)
- [Full scientific review and update history: Chinese](reports/public_review_2026_09_10/REVIEW_ZH.md)
- [Machine-readable aggregate snapshot and source hashes](reports/public_review_2026_09_10/snapshot.json)

These documents describe the latest **local research state** as of September 10, 2026. This update publishes the review and aggregate evidence; it does not synchronize the entire local implementation, datasets, or checkpoints. Earlier reports and paper drafts still present elsewhere in the public repository are historical and must be read subject to this review.

## What the work contributes

**Controlled evaluation.** Paired candidates, order and label transformations, strict prediction coverage checks, and paired statistical analysis help distinguish model behavior from presentation effects and structural decoding constraints.

**Measurement repair.** Source-linked changed-line visibility, explicit tie/abstention handling, source-aware pair identities, and stratified pair-cluster bootstrap analysis improve measurement validity. Reanalysis uses retained predictions; it is not a new model run.

**Source traceability.** Repairing extraction and function matching across PrimeVul, DeltaSecommits, and PatchEval produced 32 structurally verified function pairs from 27 original cases, with commit, file-hash, and source-line provenance. This establishes source integrity within the checked scope, not correctness of security labels.

**Data preparation.** A PatchEval pilot contains 838 weakly labeled function pairs, represented as 1,676 bidirectional inputs. Splits group connected project, CVE, and lexical near-duplicate relationships; complete inputs pass hash and tokenizer checks without truncation. No new pilot training has run.

## Latest milestones and boundaries

| Workstream | Current evidence | Interpretation |
| --- | --- | --- |
| Measurement reanalysis | 577 of 600 pairs have changed lines fully visible in both split-view directions | Visibility does not establish semantic information equivalence |
| Raw repair evaluation | Original repair gate remains failed | Structural projection is separate from learned improvement |
| Source repair | 32 function pairs / 27 cases; 64 bidirectional prompts verified | Multiple functions from one case remain clustered |
| Exploratory AI review | After context review: 13 provisional single-side, 2 both-risk, 17 unclear | AI-authored diagnostics; neither independent human gold nor model accuracy |
| Weak-supervision pilot | 571 train / 134 validation / 133 test pairs | Upstream patch-direction labels; no new training result |

The pilot was prepared from 1,006 candidates: 117 failed input filters and 51 were quarantined through connected components after a 12-pair exploratory AI audit of training examples. The remaining 838 pairs are not individually verified gold. Validation and test retain upstream weak labels.

## Evidence limits

- High benchmark scores and presentation consistency do not by themselves demonstrate security understanding.
- Historical independence and structural-guarantee claims were too strong. A nonsignificant test does not establish independence; antisymmetry alone does not guarantee polarity-invariant, tie-safe decisions.
- Changed-line visibility, syntactic validity, and AI confidence do not prove that a security judgment is correct.
- Known project and lexical-overlap checks do not establish independence from foundation-model pretraining or exclude all semantic clones.
- Local artifact verification does not establish fresh-clone training reproducibility. The latest implementation and data are not all included in this documentation update.

## Public checkout checks

See the [CI testing strategy](docs/CI_TESTING_STRATEGY.md) for the retained public smoke checks. These check the published integration and historical fixtures; they do not certify the latest local research results.

## Next research step

Use the prepared data for a bounded baseline pilot and assess agreement with weak labels and candidate-order consistency. Stronger claims require better security-label evidence and comparisons that separate candidate identity tracking, semantic judgment, and structural decoding effects.

For exact measurements, corrected interpretations, and the chronology of decisions, read the [current review](reports/public_review_2026_09_10/REVIEW.md).
