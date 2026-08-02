# Checkpoint Hygiene

## Keep
- Small adapter/LoRA configs and `README.md` metadata the repo already tracks.
- One or two checkpoints that back a **registered** eval result.
- The exact training config (seed, LR, epochs, LoRA rank/alpha, context length).

## Prune / do not commit
- Full base-model weights, optimizer states, RNG dumps (gitignored — keep it so).
- `checkpoints/smoke_*` beyond what a CI smoke needs.
- Intermediate steps with no registered result.
- Duplicate runs that differ only by an abandoned hyperparameter.

## Per-checkpoint README contract
Each `checkpoints/<run>/README.md` should state:
- Base model id + tokenizer id
- Seed(s)
- Effective batch size (per-step × grad-accum), LR, epochs
- LoRA config if applicable
- Headline eval metric + the report/registry entry it backs

## VRAM survival rules (12GB class)
- Qwen len-1024 tails: batch **2–4**, never 8.
- Prefer grad accumulation over large per-step batch.
- Enable gradient checkpointing + bf16 where supported.
- Always keep runs `--resume`-able; resume after OOM instead of restarting.
