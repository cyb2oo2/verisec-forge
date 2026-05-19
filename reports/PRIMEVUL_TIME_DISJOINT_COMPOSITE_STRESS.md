# PrimeVul Time-Disjoint Composite Stress Evaluation

This report evaluates the direct time-split detector under stricter composite filters.
The base split is already temporal: train `<=2020`, eval `>=2021`, with zero CVE and pair-key overlap.

## Base Split

- Train rows: `6000`
- Eval rows: `1562`
- Train years: `[2000, 2002, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020]`
- Eval years: `[2021, 2022]`
- CVE overlap: `0`
- Pair-key overlap: `0`

## Results

| Scenario | Constraints | Rows | Pairs | Safe/Vuln | Baseline BA | Pair BA | Delta BA | Pair Group | Delta Group |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `time_only` | `time only` | `1562` | `761` | `781/781` | `0.8745` | `0.8835` | `0.009` | `0.8765` | `0.0473` |
| `time_project_disjoint` | `project` | `296` | `140` | `148/148` | `0.8716` | `0.8581` | `-0.0135` | `0.8429` | `0.0358` |
| `time_file_hash_disjoint` | `file_hash` | `1295` | `649` | `641/654` | `0.8752` | `0.8896` | `0.0144` | `0.8844` | `0.0493` |
| `time_project_file_hash_disjoint` | `project, file_hash` | `218` | `108` | `109/109` | `0.8761` | `0.8853` | `0.0092` | `0.8796` | `0.0555` |
| `time_project_cve_commit_file_disjoint` | `project, cve, commit_id, file_hash` | `218` | `108` | `109/109` | `0.8761` | `0.8853` | `0.0092` | `0.8796` | `0.0555` |

## Interpretation

- `time_only` is the full later-CVE eval split for the direct time-trained detector.
- `time_project_disjoint` asks whether the result survives when later-CVE eval rows from training-period projects are removed.
- `time_project_cve_commit_file_disjoint` is the strictest current composite slice. In this PrimeVul sample, CVE and commit are already disjoint under the time split; the extra pressure mainly comes from project and file-hash filtering.
- These are stress slices, not new training runs. Small composite slices should be treated as reviewer-facing robustness evidence rather than headline benchmark scores.
