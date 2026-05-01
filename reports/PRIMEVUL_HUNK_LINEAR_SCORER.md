# PrimeVul Hunk Linear Scorer

This report trains a dependency-free linear hunk scorer on pseudo labels. It is a cheap sanity baseline before heavier evidence-localizer training.

## Label Metrics

- Train accuracy: `0.8712`
- Eval accuracy: `0.8793`
- Eval precision/recall/specificity: `0.8544` / `0.9327` / `0.8183`

## Top-K Coverage

| split | scorer | k | coverage | vulnerable_coverage | safe_coverage | covered_rows | rows |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| train | keyword_rank | 1 | 0.5575 | 0.5627 | 0.5524 | 1672 | 2999 |
| train | keyword_rank | 2 | 0.5799 | 0.5813 | 0.5784 | 1739 | 2999 |
| train | keyword_rank | 3 | 0.5802 | 0.5813 | 0.5791 | 1740 | 2999 |
| train | keyword_rank | 5 | 0.5815 | 0.5833 | 0.5797 | 1744 | 2999 |
| train | keyword_rank | 8 | 0.5822 | 0.584 | 0.5804 | 1746 | 2999 |
| train | linear_scorer | 1 | 0.5662 | 0.5627 | 0.5697 | 1698 | 2999 |
| train | linear_scorer | 2 | 0.5795 | 0.58 | 0.5791 | 1738 | 2999 |
| train | linear_scorer | 3 | 0.5812 | 0.5827 | 0.5797 | 1743 | 2999 |
| train | linear_scorer | 5 | 0.5815 | 0.5833 | 0.5797 | 1744 | 2999 |
| train | linear_scorer | 8 | 0.5822 | 0.584 | 0.5804 | 1746 | 2999 |
| eval | keyword_rank | 1 | 0.5792 | 0.5743 | 0.5841 | 1035 | 1787 |
| eval | keyword_rank | 2 | 0.6066 | 0.6 | 0.6132 | 1084 | 1787 |
| eval | keyword_rank | 3 | 0.6128 | 0.6067 | 0.6188 | 1095 | 1787 |
| eval | keyword_rank | 5 | 0.615 | 0.6089 | 0.6211 | 1099 | 1787 |
| eval | keyword_rank | 8 | 0.615 | 0.6089 | 0.6211 | 1099 | 1787 |
| eval | linear_scorer | 1 | 0.5954 | 0.5821 | 0.6087 | 1064 | 1787 |
| eval | linear_scorer | 2 | 0.6133 | 0.6067 | 0.62 | 1096 | 1787 |
| eval | linear_scorer | 3 | 0.615 | 0.6089 | 0.6211 | 1099 | 1787 |
| eval | linear_scorer | 5 | 0.615 | 0.6089 | 0.6211 | 1099 | 1787 |
| eval | linear_scorer | 8 | 0.615 | 0.6089 | 0.6211 | 1099 | 1787 |

## Learned Weights

- `direction_unclear`: `-8.967458`
- `candidate_introduces_risk`: `-4.825815`
- `added_lines`: `-2.484078`
- `changed_lines`: `2.469109`
- `candidate_removes_risk`: `-2.068077`
- `hunk_rank_inverse`: `1.733541`
- `removed_lines`: `-1.732575`
- `risk_support`: `0.795416`
- `candidate_adds_protection`: `-0.724474`
- `safety_support`: `0.715782`
- `bias`: `-0.510246`
- `protection_delta`: `0.484096`
- `safer_delta`: `-0.412884`
- `candidate_removes_protection`: `-0.246128`
- `risk_delta`: `0.150846`
- `keyword_count`: `0.126503`
- `net_risk_support`: `0.079635`
