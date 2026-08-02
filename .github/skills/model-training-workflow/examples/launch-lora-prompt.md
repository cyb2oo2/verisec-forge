# Example prompt: LoRA training under VRAM budget

```text
Use the model-training-workflow skill.

Launch LoRA SFT for Qwen 1.5B on the paired-diff config
configs/research_primevul_joint_pairwise_qwen15b_v1.json (or the closest retained
config). Constraints:
- 12GB VRAM class: per-step batch 2–4 on long contexts; use grad accumulation
- seeds 7, 13, 123 for any number we might promote
- checkpoint README must record model id, tokenizer, LoRA rank/alpha, LR, epochs
- do not commit weights; only keep metadata the repo already tracks
- after training, evaluate with src/vrf/ evaluators and stop before paper edits
- register only if the result is claim-bounded (research-experiment-manager)
```
