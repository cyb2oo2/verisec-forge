# Content Source Router

This report evaluates source routing from input text rather than row metadata.

## Protocol

- Forbidden row fields: `source_dataset, id, pair_key, programming_language, file_extension, file_path, patch_url`
- Surface router input: pair_text/prompt only, including visible task headers such as Project/CVE/CWE/Language.
- Diff-body router input: only text after the Unified diff marker.
- Limitation: The surface router is content-based in the sense that it consumes only the model prompt text, but the prompt still contains dataset-shaped headers. The diff-body router is stricter and intentionally reported as a lower-bound sanity check.

## Routing Accuracy

| Router | Row Accuracy | Pair Accuracy |
| --- | ---: | ---: |
| `surface_content` | `1.0` | `1.0` |
| `diff_body_only` | `0.4466` | `0.4436` |

## System Results

| System | BA | F1 | Group All-Correct | Orientation |
| --- | ---: | ---: | ---: | ---: |
| `single matched-mixed` | `0.8591` | `0.8584` | `0.8482` | `0.86` |
| `oracle source-routed` | `0.8664` | `0.8659` | `0.857` | `0.8674` |
| `surface-content router` | `0.8664` | `0.8659` | `0.857` | `0.8674` |

## Deltas

- Surface router minus single BA: `0.0073`
- Surface router minus single group all-correct: `0.0088`
- Surface router minus oracle BA: `0.0`
- Surface router minus oracle group all-correct: `0.0`

## Interpretation

A prompt-surface content router can recover the oracle source routing on the current benchmark, but a stricter diff-body-only heuristic is much weaker. This confirms that routing is feasible from the input artifact while also showing that robust semantic routing should avoid prompt/header fingerprints.
