# Training

This directory documents the staged training flow for Verifiable Reasoning Forge:

- `SFT -> DPO -> Reward Model -> GRPO`

Use the configs in `configs/` together with the CLI entrypoints:

- `vrf train-sft --config configs\sft.json`
- `vrf train-dpo --config configs\dpo.json`
- `vrf train-reward --config configs\reward_model.json`
- `vrf train-grpo --config configs\grpo.json`

The actual reusable implementation lives under `src/vrf/`.
