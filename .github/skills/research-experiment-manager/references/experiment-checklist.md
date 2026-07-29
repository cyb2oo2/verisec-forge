# Experiment Pre-Flight & Sign-Off Checklist

## Before running
- [ ] Falsifiable question written down in one sentence.
- [ ] Negative control identified (what result would sink the claim?).
- [ ] Serves an allowed extension goal for the project — else scratch branch.
- [ ] Seeds chosen (≥3 for any headline mean).
- [ ] Dataset + split named explicitly.
- [ ] Success rule pre-registered (e.g. `|canonical delta| <= 0.02`).
- [ ] Reusable logic placed in `src/vrf/`, script kept thin.

## During
- [ ] Resolved config + git commit captured at top of the output artifact.
- [ ] Logging goes to a file, not only stdout.
- [ ] GPU batch size respects VRAM limits (Qwen: batch 2–4 on len-1024 tails).

## After
- [ ] Output written as JSON/JSONL (`outputs/` or curated `reports/`).
- [ ] `experiments/registry.json` entry added/updated.
- [ ] `layer` + `reproducibility_level` set correctly.
- [ ] Claim string is narrower than the raw number (CI/seeds reported).
- [ ] `paper/result_anchor_map.md` updated if paper-facing.
- [ ] Focused anchor test still green.
- [ ] Smoke/pilot NOT promoted into a model-quality claim.
