# PrimeVul Side-Inversion Gate Summary

This generated table compares safe-flip gates across side-inversion candidate pools. It separates in-pool, rank-holdout, fresh-seed, and project-holdout behavior so the evidence-coupled system is not judged from a single pool.

## Summary

- Gate reports: `6`
- Pools: `4`
- Zero-introduced-error reports: `5`

## Cross-Pool Gates

| pool | variant | accepted | repaired | introduced | precision | recall | missed | net row gain | gate |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| top5 | strict_or | 10 | 10 | 0 | 1.0 | 0.5556 | 8 | 10 | `pair_repeat_count>=3 OR evidence_score>=13` |
| rank6_10 | strict_or | 2 | 2 | 0 | 1.0 | 0.25 | 6 | 2 | `pair_repeat_count>=3 OR evidence_score>=13` |
| fresh_seed_top5 | strict_or | 9 | 9 | 0 | 1.0 | 0.6923 | 4 | 9 | `pair_repeat_count>=3 OR evidence_score>=13` |
| project_holdout_top5 | strict_or | 12 | 9 | 3 | 0.75 | 0.75 | 3 | 6 | `pair_repeat_count>=3 OR evidence_score>=13` |
| project_holdout_top5 | evidence_conditioned | 9 | 9 | 0 | 1.0 | 0.75 | 3 | 9 | `(pair_repeat_count>=3 AND evidence_score>=0) OR evidence_score>=13` |
| project_holdout_top5 | conservative | 3 | 3 | 0 | 1.0 | 0.25 | 9 | 3 | `pair_repeat_count>=4 OR evidence_score>=13` |

## Interpretation

The project-holdout pool is the stress test for cross-project safety. The evidence-conditioned gate is the current preferred safety point there because it preserves zero introduced side errors while accepting more repairs than the conservative repeat-only fallback.
