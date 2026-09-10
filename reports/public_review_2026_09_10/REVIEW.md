# Current research review

VeriSec Forge / VeriPatch-RR | Public summary, September 10, 2026

This summary reflects the September 7 scientific review and its subsequent local updates. It supersedes the interpretation of earlier headline tables, paper drafts, and project narratives. The [full Chinese review](REVIEW_ZH.md) preserves the update history; [snapshot.json](snapshot.json) contains aggregate measurements and hashes of the source reports.

## Research question and completed work

The project investigates whether security judgments on paired code candidates remain associated with the relevant code when labels, order, and presentation change. Evaluation controls distinguish behavioral consistency from security reasoning, and structural post-processing from learned changes in predictions.

Completed local work includes measurement repair and reanalysis, source extraction and pairing repair, exploratory AI-assisted review with unresolved cases retained, and construction of a weak-supervision pilot. The public code predates some of these updates: this publication contains the current review and aggregate evidence, not a synchronized implementation or dataset release.

## Corrected measurements

The original split-view visibility parser relied on markers removed by the renderer. Reanalysis now uses source-line identities, candidate identities, and character spans. All 1,200 original texts and labels were retained, and token counts match the historical inputs. Forty-six rows truncate changed lines; 577 of 600 pairs have changed lines fully visible in both directions.

Within those 577 pairs, projected accuracy is 58.58% for the baseline and 62.05% for the repaired model. There are 42 fixed and 22 broken pairs; exact McNemar p = 0.01686 does not meet the original five-family threshold of 0.01. Each model has four ties, counted as incorrect abstentions. This exploratory reanalysis is not a new confirmation; full changed-line visibility does not establish semantic information equivalence.

The 600-pair audit combines 200 pairs each from PrimeVul, DeltaSecommits, and PatchEval. It must not be attributed wholly to PrimeVul. With corrected tie handling, pooled projected accuracy changes from 70.50% to 73.33% (21 fixed, 4 broken). These are projection results; raw repaired predictions still fail the original repair gate.

The independence baseline was revised to stratify by source, relation, and transformation family and to resample pair identities within source. The raw-repair null-minus-observed difference is 0.00835, with a 95% bootstrap interval of [0.00116, 0.01536]. This is a post hoc exploratory residual, not proof of independence, content blindness, or successful learned repair.

Prediction checks reject duplicate IDs, incomplete or extra coverage, invalid probabilities, and mixed model identities. Tie policies and sample identities are explicit. A frozen-readout cache hash discrepancy was traced to line endings; recovered original bytes pass a separate derived manifest. That local diagnosis does not establish fresh-clone training reproducibility.

## Source repair and exploratory annotation

Source extraction and function matching were repaired across PrimeVul, DeltaSecommits, and PatchEval. Fixed-commit recovery yielded 32 function pairs from 27 of the original 36 cases; nine cases were quarantined. The 32 pairs, 64 prompts, source bytes, and line mappings passed structural verification. Multiple functions from one case retain their cluster relationship.

Screening against 5,586 known code samples found no project or lexical near-duplicate hits within the implemented checks. Semantic clones and foundation-model pretraining exposure remain unresolved. Source integrity and parseability do not verify vulnerability labels.

All 32 repaired inputs underwent exploratory assistant-authored reannotation. Subsequent partial context recovery produced a diagnostic ledger of 13 provisional single-side labels, 2 both-risk cases, and 17 unclear cases. The denominator remains 32 pairs / 27 cases; the single-side subset spans 12 original case clusters. These judgments were made in an existing AI conversation context, not by independent blinded human reviewers. The ledger mixes original-input and context-augmented judgments and cannot be interpreted as same-condition model accuracy.

## Weak-supervision pilot

The local PatchEval pilot uses upstream patch direction as a noisy proxy for the vulnerable side.

| Split | Function pairs | Bidirectional inputs | Projects | CVEs |
| --- | ---: | ---: | ---: | ---: |
| Train | 571 | 1,142 | 245 | 402 |
| Validation | 134 | 268 | 120 | 122 |
| Test | 133 | 266 | 119 | 125 |
| Total | 838 | 1,676 | 484 | 649 |

The two directions are repeated representations, not independent samples. Of 1,006 candidates, 117 were excluded by source/input/overlap filters and 51 were quarantined as connected components after an exploratory AI audit of 12 training pairs. This does not show that all 51 were mislabeled, or that all retained labels are correct. Validation and test were not semantically reviewed or reassigned during that audit.

Project, CVE, and either-side lexical near-duplicate relations are grouped by transitive components before splitting. All full bidirectional inputs fit the configured limit; the maximum is 3,983 tokens. The local training entrypoint checks hashes, split paths, and actual tokenizer IDs before loading weights and rejects historical checkpoint reuse for this pilot configuration.

The source review records a data-only dry-run, release-integrity verification, and 436 passing local tests at that milestone. These are reported local checks, not a fresh public CI run or evidence of label accuracy. No GPU training or new model inference was launched for this pilot preparation. The separate 13-pair provisional single-side diagnostic subset was not inserted into the pilot as gold.

## Publication scope and next step

This documentation snapshot publishes the review and selected aggregates. Source hashes identify the local records used to construct it; they do not make unpublished records, code, checkpoints, or data independently reproducible. Historical public scripts and papers may describe earlier protocols and must not override this review. The Chinese record includes superseded proposals and initial findings; its most recent updates take precedence.

Next work is a bounded baseline pilot with weak-label agreement and swap consistency reported explicitly, plus continued investigation of unresolved security-label evidence. Transferable learned repair, deployment-quality detection, and publication-ready semantic-reasoning claims remain unestablished.
