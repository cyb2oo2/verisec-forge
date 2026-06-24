# Reviewer Checklist

This checklist is the fast path for a technical reviewer who wants to inspect
the repository without treating smoke tests, stress slots, or pilot artifacts
as stronger evidence than they are.

## 1. Fast Path: What to Read First

1. [README](../README.md)
2. [Paper v0 Draft](../paper/draft_v0.md)
3. [Main Results Table](../paper/tables/main_results.md)
4. [Result Anchor Map](../paper/result_anchor_map.md)
5. [Cross-Model Relational Audit](../reports/CROSS_MODEL_RELATIONAL_AUDIT.md)
6. [Cross-Model Replication](../reports/CROSS_MODEL_REPLICATION.md)
7. [Readout Ablation](../reports/READOUT_ABLATION.md)
8. [Readout Confirmation](../reports/READOUT_CONFIRMATORY.md)
9. [Frozen-Backbone Readout Control](../reports/FROZEN_BACKBONE_READOUT_CONTROL.md)
10. [VeriPatch-RR External Adapter](VERIPATCH_RR_EXTERNAL_ADAPTER.md)
11. [CI Testing Strategy](CI_TESTING_STRATEGY.md)

## 2. Main Claims and Where They Are Supported

| Claim | Read First | Supporting Reports | Boundary |
| --- | --- | --- | --- |
| Pointwise accuracy can hide shortcut-sensitive benchmark behavior. | `paper/draft_v0.md` Section 5 | `reports/PRIMEVUL_PROGRESSIVE_CONTROLS.md`; `reports/PRIMEVUL_MAIN_RESULTS.md`; `reports/PRIMEVUL_PAIR_COUPLED_SIGNIFICANCE.md` | Same-source score is diagnostic evidence, not semantic proof of secure patch reasoning. |
| Side-order relational consistency is separate from ordinary pointwise competence. | `paper/draft_v0.md` Section 6.1 | `reports/CROSS_MODEL_RELATIONAL_AUDIT.md`; `reports/secure_code_cross_model_relational_audit_v1.json` | The strongest comparison is Qwen decoder classifier versus CodeBERT encoder classifier under retained controls. |
| Cross-model replication broadens failure evidence without proving universal strong-model failure. | `reports/CROSS_MODEL_REPLICATION.md` | `reports/secure_code_cross_model_replication_v1.json` | Low-canonical stress evidence is reported as stress evidence, not as a universal model-quality conclusion. |
| Endpoint robustness is readout-controllable. | `paper/draft_v0.md` Section 7 | `reports/READOUT_ABLATION.md`; `reports/READOUT_CONFIRMATORY.md`; `docs/READOUT_ABLATION_PROTOCOL.md`; `docs/READOUT_CONFIRMATORY_PROTOCOL.md` | This is mechanism evidence; no readout variant is promoted as an accuracy-preserving better classifier. |
| Changed-hunk pooling has a direct structural effect under a frozen-backbone control. | `reports/FROZEN_BACKBONE_READOUT_CONTROL.md` | `docs/FROZEN_BACKBONE_READOUT_PROTOCOL.md`; `reproducibility/frozen_backbone_readout_control_manifest.json` | The result is conditional on one terminal-seed7 frozen Qwen+LoRA representation. |
| External users can exercise the prediction interface on a fixed smoke artifact. | `docs/VERIPATCH_RR_EXTERNAL_ADAPTER.md` | `examples/veripatch_rr_smoke_30.jsonl`; `reproducibility/veripatch_external_smoke_manifest.json`; `docs/CI_TESTING_STRATEGY.md` | The 30-pair / 90-row smoke artifact is an adapter sanity check, not a model-quality benchmark. |

## 3. What This Repo Does Not Claim

- It is not a deployed vulnerability scanner.
- It does not solve secure patch reasoning.
- It does not prove all strong models fail.
- It does not promote readout variants as better classifiers.
- It does not make the external smoke artifact tokenizer-neutral.
- It does not replace human security review.

## 4. Fresh Clone Verification

For the broad local regression path:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

For the hosted fresh-clone smoke gate, inspect
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) and
[CI Testing Strategy](CI_TESTING_STRATEGY.md). CI validates whitespace,
focused smoke tests, and the checked-in external smoke manifest. It does not
train models, run GPU inference, regenerate full benchmarks, or establish new
model-quality claims.

## 5. External Adapter Smoke

Start with [VeriPatch-RR External Adapter](VERIPATCH_RR_EXTERNAL_ADAPTER.md).
The external contract is:

```python
def predict(text: str) -> str:
    return "A"  # or "B", "A_RISKIER", "B_RISKIER", "INSUFFICIENT_CONTEXT"
```

The checked-in prediction template is intentionally invalid until predictions
are filled. CI verifies that the unfilled template fails validation and that a
deterministic dummy prediction file can exercise the evaluation plumbing.

## 6. If You Only Have 10 Minutes

1. Read the README headline evidence table.
2. Read `paper/draft_v0.md` Abstract, Introduction, Sections 5-8, and
   Limitations.
3. Read `paper/tables/main_results.md`.
4. Read `paper/result_anchor_map.md`.
5. Read `docs/CI_TESTING_STRATEGY.md`.
