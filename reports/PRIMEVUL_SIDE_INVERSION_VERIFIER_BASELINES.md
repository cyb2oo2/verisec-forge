# PrimeVul Side-Inversion Verifier Baselines

This report evaluates lightweight baselines for the strict `accept_flip` verifier target. It is a signal check before training a GPU-backed verifier.

## Summary

- Rows: `25`
- Accept / reject rows: `18` / `7`
- Best balanced-accuracy baseline: `evidence_margin>=10` at `0.6944`
- Best accept-precision baseline: `evidence_margin>=10` at `1.0`
- Evidence score mean accept / reject: `-0.0556` / `-4.8571`

## Metrics

| baseline | accuracy | bal_acc | accept_recall | reject_specificity | accept_precision | accepted | tp | tn | fp | fn |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| accept_all | 0.72 | 0.5 | 1.0 | 0.0 | 0.72 | 25 | 18 | 0 | 7 | 0 |
| reject_all | 0.28 | 0.5 | 0.0 | 1.0 | 0.0 | 0 | 0 | 7 | 0 | 18 |
| side_model_score>=0.5 | 0.72 | 0.5 | 1.0 | 0.0 | 0.72 | 25 | 18 | 0 | 7 | 0 |
| side_model_score>=0.9 | 0.72 | 0.5 | 1.0 | 0.0 | 0.72 | 25 | 18 | 0 | 7 | 0 |
| side_model_score>=0.99 | 0.64 | 0.4444 | 0.8889 | 0.0 | 0.6957 | 23 | 16 | 0 | 7 | 2 |
| side_model_score>=0.999 | 0.56 | 0.3889 | 0.7778 | 0.0 | 0.6667 | 21 | 14 | 0 | 7 | 4 |
| evidence_margin>=-5 | 0.52 | 0.5357 | 0.5 | 0.5714 | 0.75 | 12 | 9 | 4 | 3 | 9 |
| evidence_margin>=0 | 0.56 | 0.6071 | 0.5 | 0.7143 | 0.8182 | 11 | 9 | 5 | 2 | 9 |
| evidence_margin>=5 | 0.52 | 0.623 | 0.3889 | 0.8571 | 0.875 | 8 | 7 | 6 | 1 | 11 |
| evidence_margin>=10 | 0.56 | 0.6944 | 0.3889 | 1.0 | 1.0 | 7 | 7 | 7 | 0 | 11 |

## Interpretation

A useful trained verifier should beat these rules on held-out pair groups while preserving high accept precision. If a simple evidence-margin rule already dominates, the next step should improve evidence extraction rather than train a broader language-model verifier.
