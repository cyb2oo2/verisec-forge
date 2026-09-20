# VeriSec Forge / VeriPatch-RR

[![CI](https://github.com/cyb2oo2/verisec-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/cyb2oo2/verisec-forge/actions/workflows/ci.yml)

**Evaluating whether AI security judgments follow the code when its presentation changes.**

VeriSec Forge studies language-model assessment of paired code candidates. Its central question is whether a model tracks the relevant candidate across changes in order, labels, and presentation, and what an evaluation can legitimately tell us about security reasoning.

**Project scope:** evaluation design, experiment implementation and analysis, measurement and source repair, dataset preparation, and reproducibility tooling. See the [design and implementation record](docs/CONTRIBUTIONS.md).

**Current status: measurement validation and source-data repair within the audited scope; a weak-supervision dataset is prepared and awaits baseline training.** The September 7 scientific review, including its subsequent updates, supersedes earlier result narratives. No transferable learned repair or deployment-ready vulnerability detector is established.

## Start here

- [Current research review: English summary](reports/public_review_2026_09_10/REVIEW.md)
- [Full scientific review and update history: Chinese](reports/scientific_review_2026_09_07/REVIEW.md)
- [Version and result status](docs/RESULT_STATUS.md)
- [Design and implementation record](docs/CONTRIBUTIONS.md)
- [Machine-readable aggregate snapshot and source hashes](reports/public_review_2026_09_10/snapshot.json)

The September 2026 review supersedes earlier narratives. This publication synchronizes reviewed measurement and source-repair code, preserves historical machine evidence, and retires obsolete prose. Source datasets, annotation inputs, tokenizer caches, and checkpoints are not bundled; full research reproduction still requires local artifacts.

## What the work contributes

**Controlled evaluation.** Paired candidates, order and label transformations, strict prediction coverage checks, and paired statistical analysis help distinguish model behavior from presentation effects and structural decoding constraints.

**Measurement repair.** Source-linked changed-line visibility, explicit tie/abstention handling, source-aware pair identities, and stratified pair-cluster bootstrap analysis improve measurement validity. Reanalysis uses retained predictions; it is not a new model run.

**Source traceability.** Repairing extraction and function matching across PrimeVul, DeltaSecommits, and PatchEval produced 32 structurally verified function pairs from 27 original cases, with commit, file-hash, and source-line provenance. This establishes source integrity within the checked scope, not correctness of security labels.

**Data preparation.** A PatchEval pilot contains 838 weakly labeled function pairs, represented as 1,676 bidirectional inputs. Splits group connected project, CVE, and lexical near-duplicate relationships; complete inputs pass hash and tokenizer checks without truncation. No new pilot training has run.

## Latest milestones and boundaries

| Workstream | Current evidence | Interpretation |
| --- | --- | --- |
| Measurement reanalysis | 577 of 600 pairs have changed lines fully visible in both split-view directions | Visibility does not establish semantic information equivalence |
| Projected accuracy on those 577 pairs | **58.58% → 62.05%**; 42 fixed / 22 broken; exact McNemar **p=0.01686**; 4 ties per model counted incorrect | Exploratory reanalysis; fails the original five-family threshold of 0.01 |
| Raw repair evaluation | Original repair gate remains failed | Structural projection is separate from learned improvement |
| Source repair | 32 function pairs / 27 cases; 64 bidirectional prompts verified | Multiple functions from one case remain clustered |
| Exploratory AI review | After context review: 13 provisional single-side, 2 both-risk, 17 unclear | AI-authored diagnostics; neither independent human gold nor model accuracy |
| Weak-supervision pilot | 571 train / 134 validation / 133 test pairs | Dataset-provided patch-direction labels; no new training result |

The repair audit contains 200 pairs each from PrimeVul, DeltaSecommits, and PatchEval. Measurements reuse retained predictions; they are not a new confirmatory experiment. See [corrected P0 results](reports/scientific_review_2026_09_07/p0/results.json), [source repair](reports/scientific_review_2026_09_07/p1/source_repair_v3.json), and [pilot settings](docs/TRAINING_DATASET_PILOT.md).

The pilot was prepared from 1,006 candidates: 117 failed input filters and 51 were quarantined through connected components after a 12-pair exploratory AI audit of training examples. The remaining 838 pairs are not individually verified gold. Validation and test retain dataset-provided weak labels.

## Evidence limits

- High benchmark scores and presentation consistency do not by themselves demonstrate security understanding.
- Historical independence and structural-guarantee claims were too strong. A nonsignificant test does not establish independence; antisymmetry alone does not guarantee polarity-invariant, tie-safe decisions.
- Changed-line visibility, syntactic validity, and AI confidence do not prove that a security judgment is correct.
- Known project and lexical-overlap checks do not establish independence from foundation-model pretraining or exclude all semantic clones.
- Local artifact verification does not establish fresh-clone training reproducibility. Research data, annotation inputs, and weights are not all included in this checkout.

## Run a small offline example

Requires **Python 3.11+**; CI uses Python 3.11 on Windows and Ubuntu. Installation needs internet unless dependencies are cached. The example itself needs **no model, GPU, credentials, or paid API**.

```bash
git clone https://github.com/cyb2oo2/verisec-forge.git
cd verisec-forge
python -m venv .venv
```

Activate with `.venv\Scripts\Activate.ps1` in PowerShell or `source .venv/bin/activate` on Linux/macOS, then:

```bash
python -m pip install -e .
python scripts/run_offline_demo.py --output outputs/offline-demo
```

For the full regression suite, additionally install the test dependencies (including CPU tensor operations, but no model weights):

```bash
python -m pip install torch --index-url https://download.pytorch.org/whl/cpu
python -m pip install -e ".[dev,source-audit]"
python -m pytest -q
python scripts/build_reproducibility_bundle.py --manifest reproducibility/veripatch_external_smoke_manifest.json --check-only
```

Expected demo output: `status: ok`, `mode: MOCK_ONLY`, and paths to `predictions.jsonl` and `evaluation.json`. A constant-A fixture exercises the bundled smoke inputs and reporting. Its scores describe that fixture, **not an AI model**. Unfilled prediction templates are intentionally rejected; see the [adapter contract](docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md).

Core dependencies are FastAPI, Pydantic, and Uvicorn. Full verification adds pytest, NumPy, PyTorch, datasets utilities, an HTTP test client, and pinned tree-sitter parsers. Model-training tooling is optional and declared in [pyproject.toml](pyproject.toml). Research runs need separately acquired data and model/tokenizer weights; hosted inference may incur API charges. The quick start performs neither training nor hosted inference.

See the [CI testing strategy](docs/CI_TESTING_STRATEGY.md) and [reproduction guide](REPRODUCIBILITY.md) for verification scope. Software checks do not certify model quality or label correctness.

## Implementation map

| Component | Entry point |
| --- | --- |
| Source-line accounting | [relational_runtime.py](src/vrf/relational_runtime.py) |
| Prediction identity and coverage | [prediction_validation.py](src/vrf/prediction_validation.py) |
| Relational statistics | [relational_evaluation.py](src/vrf/relational_evaluation.py) |
| Source extraction and integrity | [source_integrity.py](src/vrf/source_integrity.py) |
| Grouped weak-supervision data | [training_dataset.py](src/vrf/training_dataset.py) |
| Current evidence index | [RESULTS_INDEX.md](reports/RESULTS_INDEX.md) |

## Version status

Package version: **0.1.0**. [Result status](docs/RESULT_STATUS.md) separates current checks, exploratory findings, unsupported interpretations, and planned work. The [cleanup manifest](reports/scientific_review_2026_09_07/cleanup_manifest.json) records retired prose and hashes; historical machine evidence remains intact. Old `ok` flags certify only the original checks, not the current scientific interpretation.

## Next research step

Use the prepared data for a bounded baseline pilot and assess agreement with weak labels and candidate-order consistency. Stronger claims require better security-label evidence and comparisons that separate candidate identity tracking, semantic judgment, and structural decoding effects.

For exact measurements, corrected interpretations, and the chronology of decisions, read the [current review](reports/public_review_2026_09_10/REVIEW.md).
