# Secure Code Benchmark Plan

## Objective

Build a compact but research-useful benchmark slice for defensive secure code reasoning. The benchmark should support two structured tasks:

1. `weakness_identification`
2. `fix_ranking`

The benchmark is intended to drive:

- baseline evaluation
- SFT data construction
- preference data construction
- failure analysis
- benchmark noise analysis

## Dataset selection criteria

The first real benchmark slice should prioritize sources that provide at least one of:

- vulnerability labels or CWE-like categories
- code snippets or diffs
- repair candidates or patched code
- metadata that can support evidence localization

## Initial benchmark strategy

Use a narrow, high-signal subset rather than a broad mixed benchmark.

- Task A subset:
  - short functions or snippets
  - explicit vulnerability labels
  - manageable language scope, starting with Python and JavaScript
- Task B subset:
  - vulnerable code plus at least two repair options
  - one preferred secure fix
  - explanation-oriented evaluation

## Normalized schema

All benchmark records should be normalized into the repository schema:

- `id`
- `task_type`
- `language`
- `prompt`
- `code`
- `diff`
- `context`
- `split`
- `difficulty`
- `source`
- `has_vulnerability`
- `vulnerability_type`
- `severity`
- `gold_fix_choice`
- `response`
- `chosen`
- `rejected`
- `score`

## Structured output contract

The model should return JSON with:

- `has_vulnerability`
- `vulnerability_type`
- `severity`
- `evidence`
- `explanation`
- `fix_principle`
- `confidence`
- `fix_choice`

## Evaluation dimensions

- label correctness
- evidence support
- explanation support
- format stability
- high-confidence error rate
- parse fallback usage

## Failure taxonomy

- `format_failure`
- `label_failure`
- `evidence_failure`
- `explanation_failure`
- `high_confidence_error`

## Immediate next experiments

1. Normalize a first real benchmark slice into the repository schema.
2. Run a baseline model with the secure-code JSON protocol.
3. Convert the training split into structured SFT responses.
4. Compare base vs SFT on the fixed secure-code eval slice.
