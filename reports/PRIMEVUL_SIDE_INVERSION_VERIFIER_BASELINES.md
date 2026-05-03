# PrimeVul Side-Inversion Verifier Baselines

This report evaluates lightweight baselines for the strict `accept_flip` verifier target. It is a signal check before training a GPU-backed verifier.

## Summary

- Rows: `25`
- Accept / reject rows: `18` / `7`
- Best balanced-accuracy baseline: `repeat>=3_or_evidence>=10` at `0.7778`
- Best accept-precision baseline: `repeat>=3_or_evidence>=10` at `1.0`
- Best zero-false-accept baseline by coverage: `repeat>=3_or_evidence>=10` accepts `10` flips
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
| pair_repeat_count>=2 | 0.72 | 0.7183 | 0.7222 | 0.7143 | 0.8667 | 15 | 13 | 5 | 2 | 5 |
| pair_repeat_count>=3 | 0.64 | 0.75 | 0.5 | 1.0 | 1.0 | 9 | 9 | 7 | 0 | 9 |
| pair_repeat_count>=4 | 0.28 | 0.5 | 0.0 | 1.0 | 0.0 | 0 | 0 | 7 | 0 | 18 |
| repeat>=2_or_evidence>=-5 | 0.72 | 0.5873 | 0.8889 | 0.2857 | 0.7619 | 21 | 16 | 2 | 5 | 2 |
| repeat>=2_or_evidence>=0 | 0.76 | 0.6587 | 0.8889 | 0.4286 | 0.8 | 20 | 16 | 3 | 4 | 2 |
| repeat>=2_or_evidence>=5 | 0.72 | 0.6746 | 0.7778 | 0.5714 | 0.8235 | 17 | 14 | 4 | 3 | 4 |
| repeat>=2_or_evidence>=10 | 0.76 | 0.746 | 0.7778 | 0.7143 | 0.875 | 16 | 14 | 5 | 2 | 4 |
| repeat>=3_or_evidence>=-5 | 0.64 | 0.619 | 0.6667 | 0.5714 | 0.8 | 15 | 12 | 4 | 3 | 6 |
| repeat>=3_or_evidence>=0 | 0.68 | 0.6905 | 0.6667 | 0.7143 | 0.8571 | 14 | 12 | 5 | 2 | 6 |
| repeat>=3_or_evidence>=5 | 0.64 | 0.7063 | 0.5556 | 0.8571 | 0.9091 | 11 | 10 | 6 | 1 | 8 |
| repeat>=3_or_evidence>=10 | 0.68 | 0.7778 | 0.5556 | 1.0 | 1.0 | 10 | 10 | 7 | 0 | 8 |
| repeat>=4_or_evidence>=-5 | 0.52 | 0.5357 | 0.5 | 0.5714 | 0.75 | 12 | 9 | 4 | 3 | 9 |
| repeat>=4_or_evidence>=0 | 0.56 | 0.6071 | 0.5 | 0.7143 | 0.8182 | 11 | 9 | 5 | 2 | 9 |
| repeat>=4_or_evidence>=5 | 0.52 | 0.623 | 0.3889 | 0.8571 | 0.875 | 8 | 7 | 6 | 1 | 11 |
| repeat>=4_or_evidence>=10 | 0.56 | 0.6944 | 0.3889 | 1.0 | 1.0 | 7 | 7 | 7 | 0 | 11 |

## Interpretation

A useful trained verifier should beat these rules on held-out pair groups while preserving high accept precision. The multi-split consensus rule is especially important: if repeated top-k selection already gives zero-false-accept coverage, a trained verifier should be judged by whether it recovers additional true flips without accepting reject cases.
