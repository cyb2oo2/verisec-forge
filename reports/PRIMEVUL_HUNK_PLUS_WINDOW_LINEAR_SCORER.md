# PrimeVul Hunk Linear Scorer

This report trains a dependency-free linear hunk scorer on pseudo labels. It is a cheap sanity baseline before heavier evidence-localizer training.

## Label Metrics

- Train accuracy: `0.8288`
- Eval accuracy: `0.844`
- Eval precision/recall/specificity: `0.7989` / `0.9371` / `0.7423`
- Side-aware eval accuracy: `1.0`
- Side-aware eval precision/recall/specificity: `1.0` / `1.0` / `1.0`

## Top-K Coverage

| split | scorer | k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| train | keyword_rank | 1 | 0.5575 | 0.5627 | 0.5524 | 1672 | 2999 |
| train | keyword_rank | 2 | 0.6155 | 0.614 | 0.6171 | 1846 | 2999 |
| train | keyword_rank | 3 | 0.6589 | 0.6573 | 0.6604 | 1976 | 2999 |
| train | keyword_rank | 5 | 0.6956 | 0.6947 | 0.6965 | 2086 | 2999 |
| train | keyword_rank | 8 | 0.7082 | 0.7093 | 0.7071 | 2124 | 2999 |
| train | linear_scorer | 1 | 0.5889 | 0.6653 | 0.5123 | 1766 | 2999 |
| train | linear_scorer | 2 | 0.6469 | 0.6887 | 0.6051 | 1940 | 2999 |
| train | linear_scorer | 3 | 0.6752 | 0.6987 | 0.6518 | 2025 | 2999 |
| train | linear_scorer | 5 | 0.7009 | 0.7067 | 0.6951 | 2102 | 2999 |
| train | linear_scorer | 8 | 0.7082 | 0.7093 | 0.7071 | 2124 | 2999 |
| train | side_aware_linear_scorer | 1 | 0.7082 | 0.7093 | 0.7071 | 2124 | 2999 |
| train | side_aware_linear_scorer | 2 | 0.7082 | 0.7093 | 0.7071 | 2124 | 2999 |
| train | side_aware_linear_scorer | 3 | 0.7082 | 0.7093 | 0.7071 | 2124 | 2999 |
| train | side_aware_linear_scorer | 5 | 0.7082 | 0.7093 | 0.7071 | 2124 | 2999 |
| train | side_aware_linear_scorer | 8 | 0.7082 | 0.7093 | 0.7071 | 2124 | 2999 |
| eval | keyword_rank | 1 | 0.5792 | 0.5743 | 0.5841 | 1035 | 1787 |
| eval | keyword_rank | 2 | 0.6279 | 0.6257 | 0.63 | 1122 | 1787 |
| eval | keyword_rank | 3 | 0.6676 | 0.6626 | 0.6726 | 1193 | 1787 |
| eval | keyword_rank | 5 | 0.6961 | 0.6939 | 0.6984 | 1244 | 1787 |
| eval | keyword_rank | 8 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
| eval | linear_scorer | 1 | 0.6178 | 0.6782 | 0.5572 | 1104 | 1787 |
| eval | linear_scorer | 2 | 0.6609 | 0.6905 | 0.6312 | 1181 | 1787 |
| eval | linear_scorer | 3 | 0.6877 | 0.6983 | 0.6771 | 1229 | 1787 |
| eval | linear_scorer | 5 | 0.7029 | 0.7028 | 0.7029 | 1256 | 1787 |
| eval | linear_scorer | 8 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
| eval | side_aware_linear_scorer | 1 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
| eval | side_aware_linear_scorer | 2 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
| eval | side_aware_linear_scorer | 3 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
| eval | side_aware_linear_scorer | 5 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |
| eval | side_aware_linear_scorer | 8 | 0.7073 | 0.7039 | 0.7108 | 1264 | 1787 |

## Learned Weights

- `direction_unclear`: `-7.709541`
- `candidate_introduces_risk`: `-2.485329`
- `changed_lines`: `2.378924`
- `removed_lines`: `-1.933213`
- `candidate_removes_risk`: `-1.712148`
- `added_lines`: `-1.608388`
- `hunk_rank_inverse`: `1.345537`
- `candidate_adds_protection`: `-0.472206`
- `candidate_removes_protection`: `-0.407757`
- `bias`: `0.193265`
- `risk_support`: `0.160877`
- `keyword_count`: `0.157975`
- `protection_delta`: `-0.139204`
- `safety_support`: `0.129299`
- `safer_delta`: `0.085392`
- `net_risk_support`: `0.031578`
- `risk_delta`: `-0.022234`

## Side-Aware Learned Weights

- `alignment_margin`: `4.98836`
- `direction_unclear`: `-3.487628`
- `opposing_support`: `-2.543854`
- `aligned_support`: `2.444506`
- `bias`: `-2.166238`
- `aligned_protection_delta`: `2.144695`
- `aligned_risk_delta`: `2.139137`
- `candidate_introduces_risk`: `-0.807918`
- `changed_lines`: `-0.762403`
- `candidate_removes_risk`: `-0.748858`
- `aligned_safer_delta`: `0.704529`
- `side_is_vulnerable`: `-0.393312`
- `keyword_count`: `-0.237816`
- `hunk_rank_inverse`: `-0.228272`
- `candidate_removes_protection`: `0.217216`
- `candidate_adds_protection`: `0.147599`
- `safety_support`: `-0.089049`
- `removed_lines`: `0.083556`
- `net_risk_support`: `0.07875`
- `risk_delta`: `0.046096`
- `protection_delta`: `-0.035368`
- `added_lines`: `0.021205`
- `risk_support`: `-0.010299`
- `safer_delta`: `0.002714`
