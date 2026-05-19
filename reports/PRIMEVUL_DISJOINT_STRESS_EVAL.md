# PrimeVul Disjoint Stress Evaluation

This report evaluates the same paired-diff predictions after filtering eval rows whose metadata value appears in paired-diff training metadata.
It is a stress matrix for shortcut/generalization risk, not a newly trained model.

Time-disjoint feasibility:

- Status: `not_feasible`
- Reason: eval has no CVE years absent from paired-diff training metadata
- Unseen eval CVE years: `[]`

## Summary

| Field | Rows After | Pairs After | Safe/Vuln | Diff BA | Pair BA | Delta BA | Pair Group | Delta Group | Overlap After |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `project` | `355` | `171` | `178/177` | `0.8085` | `0.8225` | `0.014` | `0.7778` | `0.0994` | `0` |
| `cve` | `1703` | `830` | `851/852` | `0.8168` | `0.8491` | `0.0323` | `0.8205` | `0.1229` | `0` |
| `commit_id` | `1787` | `873` | `893/894` | `0.8159` | `0.8444` | `0.0285` | `0.8167` | `0.1191` | `0` |
| `file_hash` | `1433` | `721` | `708/725` | `0.8176` | `0.8445` | `0.0269` | `0.8225` | `0.1138` | `0` |

## Interpretation

- `project` is the hardest current same-artifact stress split because it removes projects seen during paired-diff training, but the remaining subset is much smaller.
- `cve`, `commit_id`, and `file_hash` mainly test identifier/memorization leakage while preserving most of the paired eval distribution.
- Time-disjoint evaluation is not reported here because the current train/eval sample has no unseen CVE years in eval.
