# External Model Report Card

This template is for external VeriPatch-RR adapter submissions. It is not a
leaderboard row, benchmark release, or endorsement.

## 1. Model And Runtime

- Model name:
- Model version / checkpoint:
- Provider or repository:
- Inference date:
- Runtime environment:
- Can the model abstain? yes / no
- `supports_abstention` setting:

## 2. Adapter Inputs

- Benchmark artifact:
- Prediction file:
- Evaluation report:
- Prediction command or script:

## 3. Prediction Contract

- Output labels used:
- Invalid labels present? yes / no
- Duplicate IDs present? yes / no
- Missing IDs present? yes / no
- Extra IDs present? yes / no

## 4. Reported Metrics

Copy metrics from the generated evaluation report. Keep pointwise and
relational metrics separate.

| Metric | Value | Source field |
| --- | ---: | --- |
| Base accuracy |  | `headline.base_accuracy` |
| Transformed accuracy |  | `headline.relation_tests.transformed_accuracy` |
| End-to-end relation accuracy |  | `headline.relation_tests.end_to_end_relation_accuracy` |
| Robust accuracy |  | `headline.relation_tests.robust_accuracy` |
| Relation violation rate |  | `headline.relation_tests.relation_violation_rate` |

## 5. Runtime Visibility

- Was runtime accounting materialized for this exact model/tokenizer? yes / no
- Tokenizer:
- Context length:
- Truncation side:
- Special-token policy:

Do not make runtime visibility claims if this section is incomplete or borrowed
from another model.

## 6. Interpretation

Use bounded language:

```text
This run validates that the submitted prediction file can be evaluated by the
external adapter on the stated artifact. The reported relational metrics apply
only to that artifact and runtime configuration.
```

## 7. Claim Boundary

Check each box before submitting:

- [ ] I do not describe the 30-pair smoke artifact as a model-quality benchmark.
- [ ] I do not make tokenizer-neutral runtime visibility claims unless I
      materialized runtime accounting for this model.
- [ ] I do not compare this result as a leaderboard entry.
- [ ] I do not manually repair invalid predictions.
- [ ] I do not present this report card as endorsement.
