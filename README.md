# VeriSec Forge

**Shortcut-aware secure patch reasoning with paired-diff evaluation, pair-coupled decoding, and evidence-coupled audit.**

VeriSec Forge is now pruned as a PhD-application research artifact. The repository is not trying to be a general secure-coding assistant or a catalog of every experiment run along the way. It presents one focused research story:

> Can secure-code models be evaluated and improved under paired vulnerable/fixed patch conditions, without letting shortcut artifacts, output-format noise, or unsupported rationales masquerade as security reasoning?

The project is aimed at the standard of top security/ML systems groups: clear problem framing, falsifiable controls, reproducible artifacts, and honest claim boundaries.

![Patch review demo UI](reports/assets/patch_review_demo_ui.png)

## Core Contributions

1. **Shortcut-aware benchmark diagnosis.** Same-source PrimeVul detection reaches high headline accuracy, but paired vulnerable/fixed controls expose artifact-sensitive behavior. Negative controls stay near chance: metadata-only `0.5022`, candidate-only `0.5078`, and counterpart-only `0.5156` balanced accuracy.

2. **Paired diff reasoning and task-structured decoding.** Diff-only paired training is the credible mainline, with three-seed mean balanced accuracy `0.8287`. Pair-coupled decoding is the strongest system layer: five-split mean balanced accuracy `0.8572`, with strict same-split pair-minus-bucket delta `+0.0348` BA and bootstrap 95% CI `[0.0329, 0.0368]`.

3. **Evidence-coupled audit loop.** Evidence localization is treated as a decision-coupled diagnostic, not as a solved explanation task. Side-correct rows reach top-1 localization `0.7610`, while side-wrong rows fall to `0.0632`, making error propagation measurable.

4. **Bounded external generalization.** CVE-disjoint, project-disjoint, time-disjoint, DeltaSecommits, and PatchEval checks support a narrow claim: source-aware paired-diff experts and learned closed-world routing improve robustness, but this is not open-set expert discovery.

## Headline Evidence

| Claim | Main Result | Where To Read |
| --- | ---: | --- |
| Artifact-sensitive same-source success needs controls | same-source accuracy `0.9524`; paired controls near chance | [PrimeVul Progressive Controls](reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md) |
| Pair-coupled decoding is the strongest current layer | five-split mean BA `0.8572`; mean delta `+0.0348` | [Pair-Coupled Significance](reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md) |
| Learned joint side choice is promising but not yet strongest | held-out pair orientation `0.8283`; decoder reference `0.8572` | [Learned Joint Pairwise Baseline](reports/LEARNED_JOINT_PAIRWISE_BASELINE.md) |
| Low-margin abstention gives a stable review operating point | accepted accuracy `0.8767` at coverage `0.7896`; error capture `0.4087` | [Selective Calibration](reports/PRIMEVUL_JOINT_PAIRWISE_SELECTIVE_CALIBRATION.md) |
| Targeted adaptation can remove a measured shortcut | padding violation `0.4250 -> 0.1300`; paired `p<1.4e-23`; main-task delta not significant | [Nuisance Adaptation Pilot](reports/PRIMEVUL_NUISANCE_PAIRWISE_ADAPTATION_PILOT.md) |
| A larger frozen pair head does not solve the gap | hidden/score probes `0.6856` / `0.6941`; synthetic reverse exact match `1.21%` | [Learned Joint Pairwise Baseline](reports/LEARNED_JOINT_PAIRWISE_BASELINE.md) |
| Real-pair consistency helps, but synthetic supervision remains stronger | real-only `0.7219`; consistency `0.7437`; synthetic-supervised `0.8283` | [Joint Pairwise Baseline](reports/LEARNED_JOINT_PAIRWISE_BASELINE.md) |
| The synthetic-supervised model is also more stable in current stress tests | mean invariant change `0.2494` vs `0.2944` | [Joint Counterfactual Comparison](reports/PRIMEVUL_JOINT_COUNTERFACTUAL_COMPARISON.md) |
| Counterfactual interventions expose causal shortcut sensitivity | v1 padding flip rate `0.6075`; v2 separates length, position, and token-budget truncation | [Relational Benchmark V2](reports/RELATIONAL_BENCHMARK_V2.md) |
| Time/project/CVE stress tests preserve the mainline | time direct-train BA `0.8835`; composite BA `0.8853` | [Time-Disjoint Comparison](reports/PRIMEVUL_TIME_DISJOINT_COMPARISON.md) |
| Source-aware routing is useful but bounded | routed BA `0.8664`; closed-world delta `+0.0073` | [Learned Router Claim Boundary](reports/LEARNED_ROUTER_CLAIM_BOUNDARY.md) |
| Evidence quality depends on correct side choice | side-correct top-1 `0.7610`; side-wrong top-1 `0.0632` | [Predicted-Side Hunk Scorer](reports/PRIMEVUL_PREDICTED_SIDE_HUNK_SCORER.md) |

## Reading Order

Start with:

- [Application Packet](docs/APPLICATION_PACKET.md)
- [Application Focus](docs/APPLICATION_FOCUS.md)
- [Next Method Phase](docs/NEXT_METHOD_PHASE.md)
- [Relational Benchmark V2 Protocol](docs/COUNTERFACTUAL_SHORTCUT_PROTOCOL.md)
- [Project Story](PROJECT_STORY.md)
- [Results Index](reports/RESULTS_INDEX.md)
- [Reproducibility Guide](REPRODUCIBILITY.md)

Then inspect the artifact-backed demo:

- [Patch Review Demo](docs/PATCH_REVIEW_DEMO.md)
- [Patch Review Walkthrough](docs/PATCH_REVIEW_WALKTHROUGH.md)

## Repository Map

- `src/vrf/`: core library code for datasets, evaluation, routing, reporting, serving, and reproducibility helpers.
- `scripts/`: curated reproduction and report-building scripts for the retained research story.
- `reports/`: pruned result set; intermediate sweeps and obsolete branches were removed.
- `reproducibility/`: manifests and release metadata for local artifact validation and bundle packaging.
- `configs/`: only the patch-review demo config, the report index config, and the application summary config.
- `tests/`: focused tests for the retained core and application-facing scripts.

## Quick Verification

Install:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
```

Run tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Build the reviewer-facing relational benchmark:

```powershell
.\.venv\Scripts\python.exe scripts\build_relational_benchmark_v2.py
```

The v2 builder uses seeded stratified sampling over PrimeVul, DeltaSecommits,
and PatchEval, renders side swaps through one canonical prompt path, and records
token and critical-hunk truncation diagnostics for every intervention.

Validate local reproducibility inputs:

```powershell
.\.venv\Scripts\python.exe scripts\reproduce_primevul_calibrated_router.py --check-only
.\.venv\Scripts\python.exe scripts\reproduce_primevul_evidence_coupled.py --check-only
.\.venv\Scripts\python.exe scripts\build_reproducibility_bundle.py --manifest reproducibility\external_generalization_manifest.json --check-only --include-generated
```

Run the local patch-review UI:

```powershell
.\.venv\Scripts\python.exe -m vrf.cli serve --config configs\serve_patch_review_demo.json
```

Then open `http://127.0.0.1:8000/review-pair/ui`.

## What Was Pruned

The repository previously contained many historical branches: CodeXGLUE experiments, SFT/DPO/verifier dead ends, broad failure-analysis dumps, obsolete configs, generated egg-info metadata, and repeated side-inversion queue variants. Those were useful during exploration but weak for application review because they blurred the strongest research signal.

The retained repository emphasizes:

- paired patch/diff reasoning over generic vulnerability classification
- shortcut controls over raw leaderboard-style scores
- pair-coupled decoding over single-row prediction
- closed-world source-aware routing with explicit limitations
- evidence localization as diagnostic support, not an overclaimed explanation result

## Claim Boundaries

This project is a research artifact, not a deployed vulnerability scanner. The current evidence supports paired-diff reasoning and bounded source-aware routing under the materialized datasets and prediction artifacts. It does not claim open-set source discovery, human-gold evidence localization, or production-grade secure-code review.

The earlier regex identifier/formatting counterfactuals remain diagnostic
pilots, not validated semantics-preserving interventions. Reviewer-facing
counterfactual claims should use the v2 transformation tiers and report
context-pressure separately from no-truncation invariance.
