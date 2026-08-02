---
name: model-training-workflow
description: >-
  Run training/fine-tuning (SFT, DPO, LoRA), manage checkpoints, and evaluate on
  paired-diff tasks with correct seeds and VRAM budgets. Use when writing or
  editing training scripts, launching a run, resuming, choosing batch size,
  organizing checkpoints, or evaluating a checkpoint. Triggers: train, finetune,
  SFT, DPO, LoRA, PEFT, checkpoint, resume, batch size, OOM, eval, Qwen, epoch.
---

> **Worked examples use the current, scientifically supported result.**
> Under the closed-world pair constraint the detector reaches balanced accuracy
> `0.8596` and the strongest semantics-free structural control reaches `0.8588`;
> the delta is `+0.0008` with a pair-group clustered 95% CI spanning zero, so no
> semantic advantage beyond diff structure is established. Withdrawn values appear
> only inside an explicit audit example whose requested action is to reject the
> claim. Source of truth: `docs/RESULT_STATUS_LEDGER.md`.


# Model Training Workflow

Drive training and evaluation for VeriSec Forge on modest hardware (12GB VRAM
class) without OOMs, lost checkpoints, or unreproducible runs. Training here is
in service of measurement — a checkpoint only matters once it produces a
registered, claim-bounded evaluation result.

## When to Use

- Launching or editing SFT / DPO / LoRA training (`transformers`, `trl`, `peft`).
- Choosing batch size / grad accumulation to fit VRAM; resuming after a crash.
- Organizing `checkpoints/` and pruning noise before commit.
- Evaluating a checkpoint on paired-diff / relational tasks.

## Instructions

### 1. Install the right extras
- `pip install -e ".[train]"` (accelerate, datasets, peft, transformers, trl,
  torch). Add `.[serve]` (vllm) only for serving.

### 2. Fix determinism up front
- Set and record the seed. For any promoted metric, run ≥3 seeds (this repo
  reports means with the strongest semantics-free structural control alongside,
e.g. detector BA `0.8596` against control BA `0.8588`).
- Record model id, tokenizer id, context length, LoRA config, LR, epochs, and
  effective batch size in the run's output/README.

### 3. Respect the VRAM budget (critical)
- Qwen inference at length-1024 tails thrashes 12GB at batch 8. **Use batch 2–4**
  or `--resume` (see project memory: `verisec_qwen_inference_batch_size`).
- Prefer gradient accumulation to reach an effective batch size rather than a
  large per-step batch. Enable gradient checkpointing / bf16 where supported.

### 4. Checkpoint hygiene
- Save periodically and keep `--resume`-able state. Each checkpoint dir already
  carries a `README.md` — keep it meaningful (config + step + metric).
- Do **not** commit large checkpoint weights; they are gitignored. Commit only
  small metadata/adapter configs the repo already tracks.
- See `references/checkpoint-hygiene.md` for the keep/prune rules.

### 5. Evaluate through the library, not ad-hoc
- Use `src/vrf/` evaluators (evaluation, relational_evaluation, joint_reasoning)
  and the curated `scripts/analyze_*` / `predict_*` entrypoints.
- Evaluate against the **pre-registered success rule**; report canonical delta,
  side-swap equivariance, and endpoint robustness separately — they are distinct.

### 6. Register the outcome
- Route the eval number into `experiments/registry.json` and a `reports/` file.
  A checkpoint with no registered result is scratch work.

## Best Practices & Guardrails

- **Do** resume rather than restart after an OOM; log the crash cause.
- **Do** keep separate metrics for invariance vs. side-order equivariance —
  fixing one does not fix the other (README documents this repeatedly).
- **Don't** train on the application surface for a goal outside the project's
  three extension categories.
- **Don't** commit checkpoint weights, optimizer states, or `outputs/` dumps.
- **Don't** promote a smoke run (e.g. `checkpoints/smoke_*`) into a quality claim.

## Examples

**Safe Qwen inference batch (avoids 12GB thrash)**
```powershell
.\.venv\Scripts\python.exe scripts\predict_veripatch_rr.py `
  --model <checkpoint> --batch-size 2 --resume
```

**Checkpoint dir contract**
```
checkpoints/<run_name>/
  checkpoint-<step>/   # resume-able state (gitignored weights)
  README.md            # config, step, headline metric, seed
```

## Dependencies / Tools

- `.[train]`: accelerate, datasets, peft, transformers, trl, torch (≥ CUDA runtime)
- `.[serve]`: vllm — serving only
- `src/vrf/` evaluators; `scripts/predict_*`, `scripts/analyze_*`
- Related skills: [[research-experiment-manager]], [[reproducibility-check]], [[code-review-scientific]]
