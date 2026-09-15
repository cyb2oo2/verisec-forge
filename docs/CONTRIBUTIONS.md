# Personal contribution and attribution

**Yibo Chen (cyb2oo2)** maintains this research under **Prof. Yongzhuang Wei (韦永壮)**. Commit history records implementation changes; it does not establish unaided authorship of every line or independent validation of every result.

| Area | Work led and maintained by Yibo Chen | Dependencies and boundaries |
| --- | --- | --- |
| Research design | Paired evaluation, presentation controls, claim boundaries, and iteration after measurement failures | Supervised research; behavioral results alone do not identify internal mechanisms |
| Implementation | Evaluation pipeline, prediction checks, source accounting, source repair, dataset grouping, manifests, regression checks | AI coding assistance was used; ownership does not imply every line was written unaided |
| Experiments and analysis | Experiment integration, retained-prediction reanalysis, data diagnostics, evidence organization | Upstream models and benchmarks; historical training differs from current data-only pilot preparation |
| Annotation workflow | Source recovery, review organization, explicit unresolved-case accounting | Exploratory judgments are assistant-authored, not independent human labels; unavailable service-model metadata remains unknown |

## Upstream work

- **PrimeVul, DeltaSecommits, PatchEval:** upstream cases and patch-direction information. Source code belongs to its original projects. See [data documentation](../data/README.md) and [source provenance](../reports/scientific_review_2026_09_07/p1/source_repair_v3.json).
- **Qwen and CodeBERT families:** upstream pretrained models used historically, not models pretrained by this project. Exact model and precision depend on each experiment's configuration and runtime record.
- **Transformers, PEFT, datasets, Accelerate, TRL, PyTorch:** optional model/training infrastructure.
- **tree-sitter and language grammars:** source parsing; syntax acceptance is not security validation.
- **FastAPI, Pydantic, Uvicorn, pytest, GitHub Actions:** software and verification infrastructure.

See [dependencies](../pyproject.toml). Repository licensing does not replace upstream code, data, or model terms. The [scientific review](../reports/scientific_review_2026_09_07/REVIEW.md) documents AI assistance and provisional evidence; collaborators are not represented as independently endorsing these findings.
