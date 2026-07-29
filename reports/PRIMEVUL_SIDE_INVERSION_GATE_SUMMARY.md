# PrimeVul Side-Inversion Gate Summary

> **STATUS: SELECTION-ON-HOLDOUT - UNCERTAINTY REQUIRED.**
> The preferred gate (`project_holdout_top5:evidence_conditioned`) is the only variant defined for the only pool where the original `strict_or` gate failed, and it is selected and scored on that same pool. It is selected-on-holdout, not independently validated. Precision must be reported with its sample size and exact binomial interval; see `reports/PRIMEVUL_SIDE_INVERSION_GATE_UNCERTAINTY.md`.
> See [Research Integrity Verification](../docs/RESEARCH_INTEGRITY_VERIFICATION.md) and [Remediation Notice](../docs/RESEARCH_INTEGRITY_REMEDIATION.md).


This generated table compares safe-flip gates across side-inversion candidate pools. It separates in-pool, rank-holdout, fresh-seed, and project-holdout behavior so the evidence-coupled system is not judged from a single pool.

## Summary

- Gate reports: `6`
- Pools: `4`
- Zero-introduced-error reports: `5`
- Stress-invalidated reports: `1`
- Selection-allowed reports: `1`
- Audit-only reports: `5`
- Protocol violations: `0`

## Gate Selection Protocol

- Discovery pool: `top5`
- Rank holdout pool: `rank6_10`
- Fresh-seed pool: `fresh_seed_top5`
- Cross-project stress pool: `project_holdout_top5`
- Selection policy: Prefer zero-introduced-error gates; break ties by accepted repairs. A gate that introduces side errors on the project-holdout stress pool is not cross-project safe.
- Current preferred gate: `project_holdout_top5:evidence_conditioned`

## Cross-Pool Gates

| pool | variant | role | selectable | status | accepted | repaired | introduced | precision | recall | missed | net row gain | gate |
| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| top5 | strict_or | discovery | yes | development_safe | 10 | 10 | 0 | 1.0 | 0.5556 | 8 | 10 | `pair_repeat_count>=3 OR evidence_score>=13` |
| rank6_10 | strict_or | rank_holdout_validation | no | development_safe | 2 | 2 | 0 | 1.0 | 0.25 | 6 | 2 | `pair_repeat_count>=3 OR evidence_score>=13` |
| fresh_seed_top5 | strict_or | fresh_seed_validation | no | development_safe | 9 | 9 | 0 | 1.0 | 0.6923 | 4 | 9 | `pair_repeat_count>=3 OR evidence_score>=13` |
| project_holdout_top5 | strict_or | project_stress_test | no | stress_invalidated | 12 | 9 | 3 | 0.75 | 0.75 | 3 | 6 | `pair_repeat_count>=3 OR evidence_score>=13` |
| project_holdout_top5 | evidence_conditioned | project_stress_candidate | no | preferred_stress_safe | 9 | 9 | 0 | 1.0 | 0.75 | 3 | 9 | `(pair_repeat_count>=3 AND evidence_score>=0) OR evidence_score>=13` |
| project_holdout_top5 | conservative | project_stress_baseline | no | stress_safe_but_lower_recall | 3 | 3 | 0 | 1.0 | 0.25 | 9 | 3 | `pair_repeat_count>=4 OR evidence_score>=13` |

## Interpretation

The project-holdout pool is the stress test for cross-project safety. The evidence-conditioned gate is the current preferred safety point there because it preserves zero introduced side errors while accepting more repairs than the conservative repeat-only fallback.
