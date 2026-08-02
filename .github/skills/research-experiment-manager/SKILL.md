---
name: research-experiment-manager
description: >-
  Plan, register, run, and track research experiments reproducibly. Use when
  starting a new experiment, adding a run to experiments/registry.json, wiring
  hyperparameters/seeds/logging, comparing runs, or turning a run into a
  claim-backed report. Triggers: experiment, run, sweep, hyperparameter, seed,
  ablation, registry, result tracking, "which config produced this number".
---

> **Worked examples use the current, scientifically supported result.**
> Under the closed-world pair constraint the detector reaches balanced accuracy
> `0.8596` and the strongest semantics-free structural control reaches `0.8588`;
> the delta is `+0.0008` with a pair-group clustered 95% CI spanning zero, so no
> semantic advantage beyond diff structure is established. Withdrawn values appear
> only inside an explicit audit example whose requested action is to reject the
> claim. Source of truth: `docs/RESULT_STATUS_LEDGER.md`.


# Research Experiment Manager

Manage the full lifecycle of a VeriSec Forge experiment so that every reported
number traces back to a config, a seed, a script invocation, and a checked-in
artifact. This repo is a **measurement and mechanism study**: an experiment is
not "done" until its result is registered and claim-bounded.

## When to Use

- Designing a new experiment (ablation, control, stress test, seed sweep).
- Adding or updating an entry in `experiments/registry.json`.
- Deciding seeds, splits, and hyperparameters and recording them.
- Tracing a headline number back to the run that produced it.
- Promoting a run's output from `outputs/` into a curated `reports/` artifact.

## Core Principles (repo-specific)

1. **Every claim maps to a registry entry.** `experiments/registry.json` maps
   reports to bounded claims across four layers: `measurement`, `model_evidence`,
   `mechanism`, `reproducibility`. New results must slot into this hierarchy.
2. **Reproducibility level is explicit.** Tag each result as one of
   `report-backed`, `manifest-backed`, `ci-smoke`, `protocol-backed`.
3. **Thin scripts, reusable core.** Logic lives in `src/vrf/`; `scripts/` are
   invocation entrypoints that read a config and write a JSON/JSONL artifact.
4. **Never promote smoke/pilot into model-quality claims.** A 30-pair smoke is
   not a benchmark (see `docs/CI_TESTING_STRATEGY.md`).

## Instructions

### 1. Frame the experiment before running anything
- State the falsifiable question and the **negative control** that would sink it
  (a control that merely removes the diff cannot test diff structure; the
mandatory comparator is the strongest semantics-free structural control. For
context only, the diff-removing controls are metadata-only
  `0.5022`).
- Confirm it serves an allowed extension goal for the project (paired-diff /
  pair-coupled decoding; bounded external / routing generalization;
  evidence-coupled audit). If not, it belongs on a scratch branch.

### 2. Fix the reproducibility surface
- Record: dataset + split, seeds (prefer ≥3 for any headline mean), model id,
  tokenizer id, context length, and the exact script + config path.
- Put reusable logic in `src/vrf/`; keep the `scripts/` entrypoint thin.
- Write outputs as JSON/JSONL under `outputs/` (or `reports/` when curated).

### 3. Run with logging that survives the terminal
- Log to a file, not just stdout. Capture the resolved config and git commit at
  the top of every artifact so a stray number is never orphaned.
- For GPU/Qwen inference, respect the known VRAM limit: batch 2–4 on length-1024
  tails, or use `--resume` (see the batch-size note in project memory).

### 4. Register the result
- Add/update an entry in `experiments/registry.json` using the template in
  `templates/experiment_registry_entry.json`. Set `layer`,
  `reproducibility_level`, the source report path, and the bounded claim string.
- Keep the claim **narrower** than the number. Report CI/seeds, not a lone point.

### 5. Verify traceability
- Confirm `paper/result_anchor_map.md` (if the number is paper-facing) and the
  registry both point to the same report.
- Run the relevant focused test so the anchor stays green.

## Best Practices & Guardrails

- **Do** run ≥3 seeds and report mean + spread for any promoted metric.
- **Do** pre-register the success rule before looking at the result (this repo
  uses fixed rules like `|canonical delta| <= 0.02`).
- **Don't** invent a new headline metric when an existing evidence-hierarchy
  number answers the question.
- **Don't** revive pruned experiment families (CodeXGLUE, generic SFT/DPO/
  verifier, config-matrix dumps).
- **Don't** leave a run in `outputs/` uncited; either register it or delete it.

## Examples

**Register a new seed-sweep result**
```jsonc
// append to experiments/registry.json -> "experiments"
{
  "id": "primevul_pair_coupled_seed_sweep_v2",
  "title": "Pair-Coupled Decoding Seed Sweep (5 splits)",
  "layer": "model_evidence",
  "reproducibility_level": "report-backed",
  "report": "reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md",
  "claim": "Detector 0.8596 vs strongest semantics-free character control 0.8588; delta +0.0008, pair-group clustered 95% CI [-0.0202, +0.0222]; not distinguishable from zero.",
  "strongest_semantics_free_control": "char_polarity",
  "control_required": true
}
```

**Trace a number** — "Where does 0.8596 come from, and what is the strongest
semantics-free control it was compared against?"
1. Grep the registry / `paper/result_anchor_map.md` for the value.
2. Open the linked report, find the script + config it names.
3. Re-run `--check-only` on the reproducibility manifest if one exists.

## Dependencies / Tools

- `experiments/registry.json`, `paper/result_anchor_map.md`
- `src/vrf/` (evaluation, analysis), `scripts/analyze_*.py`, `scripts/build_*.py`
- Python ≥ 3.11; `pip install -e ".[dev]"` (add `.[train]` / `.[serve]` as needed)
- `scripts/build_reproducibility_bundle.py --check-only` for manifest validation
- Related skills: [[reproducibility-check]], [[model-training-workflow]], [[code-review-scientific]]
