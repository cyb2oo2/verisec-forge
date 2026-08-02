# Example prompt: materialize model-specific runtime

```text
Use the data-processing-pipeline skill.

Materialize a VeriPatch-RR runtime JSONL for model <model-id> with max-length 512.
Requirements:
- Raw vulnerability samples are text only — never execute them.
- Side swaps through one canonical render path.
- Truncation uses this model's tokenizer, context length, and special-token policy.
- Log orientation-vs-gold de-confound stats and class balance.
- Emit/refresh a reproducibility manifest and validate with --check-only.
- Put reusable transforms in src/vrf/; keep the script thin.
```
