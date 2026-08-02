# Scientific Code Review Rubric

Score each dimension `pass` / `needs work` / `blocking`. A single `blocking`
blocks merge until addressed.

## 1. Scope

| Check | Status |
| --- | --- |
| Change serves paired-diff / pair-coupled, external routing, or evidence audit | |
| No revival of pruned families (CodeXGLUE, generic SFT-DPO-verifier matrices) | |
| Diff is focused; no drive-by refactors | |

## 2. Experimental design

| Check | Status |
| --- | --- |
| Falsifiable question and negative control present | |
| Seeds ≥3 for any promoted mean; seeds recorded | |
| Split / disjointness axis matches the claim | |
| Success rule pre-registered or justified as exploratory | |

## 3. Statistics

| Check | Status |
| --- | --- |
| Effect size + uncertainty (CI / spread), not p alone | |
| Paired comparison when systems share rows | |
| Multiple-comparison awareness (or pre-registered primary) | |
| Smoke/pilot not used as quality evidence | |

## 4. Reproducibility

| Check | Status |
| --- | --- |
| Config + commit captured in artifacts | |
| JSON/JSONL outputs; scripts thin, logic in `src/vrf/` | |
| Manifest / `--check-only` path when releasable | |
| No secrets, large weights, or executed vulnerability samples | |

## 5. Claim hygiene

| Check | Status |
| --- | --- |
| Number lives in `reports/` before paper text | |
| Paper-facing numbers appear in `result_anchor_map.md` | |
| Boundary sentence present ("X, not Y") | |
| Evidence tier correct (measurement / mechanism / model) | |

## 6. Software quality

| Check | Status |
| --- | --- |
| Types / style match neighbors | |
| Tests updated for retained behavior or smoke contracts | |
| Windows + Linux path safety | |
| CI boundary respected (no training/GPU in smoke) | |

## Review output template

```markdown
### Scientific review

**Summary:** <one sentence>

#### Blocking
- ...

#### Non-blocking
- ...

#### Questions
- ...

#### Praise
- ...

**Rubric:** scope=… design=… stats=… repro=… claims=… software=…
```
