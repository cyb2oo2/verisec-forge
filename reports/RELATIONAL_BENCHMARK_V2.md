# VeriPatch-RR v0.1

## Purpose

VeriPatch-RR is a tokenizer-neutral relational robustness benchmark for secure
patch reasoning. It tests whether vulnerable/fixed side decisions obey
invariant and equivariant contracts, while separating clean relation failures
from model-specific token-budget pressure.

## Frozen Benchmark

| Item | Value |
| --- | ---: |
| Sampling suites | representative + balanced-stress |
| Pair rows | 1,200 |
| Unique source pairs | 890 |
| Sources | PrimeVul, DeltaSecommits, PatchEval |
| Base rows | 1,200 |
| Intervention rows | 8,400 |
| Total rows | 9,600 |

The benchmark stores complete text, exact changed-line occurrences and
character offsets, transformation contracts, and runtime transformation
instructions. It does not store tokenizer-specific visibility claims.

## Sampling

The representative suite is seeded random sampling from each source. The
balanced-stress suite greedily targets equal diff and character-length
marginals while capping project and CWE concentration.

For PrimeVul, balanced stress reaches exactly `40` pairs in each of the five
diff buckets and lowers maximum project concentration from `0.155` to `0.015`.
Impossible targets are exposed rather than hidden: DeltaSecommits contains only
the `00-02` changed-line bucket in the current source artifact.

## Runtime Contract

Every model must materialize its own accounting with:

- model and tokenizer identity
- maximum length and left/right truncation policy
- special-token policy
- base and transformed token counts
- exact changed-line token offsets
- critical lines/tokens total and visible
- first and last critical token
- transformation tokens total and visible
- target and achieved context-pressure ratio

A full Qwen 1.5B tokenizer accounting smoke test materialized all `9,600` rows
at length `512`. It found `2,644` rows with incomplete critical-hunk visibility
and `773` rows where the transformation introduced that truncation. This is an
accounting result, not a model robustness result.

## Evaluation Contract

Invariant and side-swap rows report protocol pass rate, conditional relation
accuracy, end-to-end relation accuracy, probability consistency, robust
accuracy, and pair-cluster bootstrap intervals using `dataset::pair_key`.

Context-pressure rows do not contribute to robust accuracy. They report
decision change, abstention, confidence drop, forced-decision error, and
evidence-visible versus evidence-truncated subsets. Appropriate-abstention
accuracy remains undefined until independent context-sufficiency labels exist.

## Claim Boundary

Regex identifier renaming and generic formatting normalization remain v1
diagnostic pilots. They are not validated semantics-preserving interventions.
The next valid experiment is frozen cross-model inference on VeriPatch-RR v0.1,
not further benchmark tuning.
