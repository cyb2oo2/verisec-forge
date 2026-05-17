# PrimeVul High-Quality Evidence Adjudication Workflow

This is the focused independent-review pass for the high-quality disagreement queue.
It is intentionally narrower than the full 20-row adjudication template so the first reviewer pass can resolve the strongest evidence conflicts before moving to insufficient-context cases.

## Scope

- Input queue: `data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl`
- CSV template: `data/processed/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv`
- Reviewer packet: `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_PACKET.md`
- Rows: `6`
- Final adjudication: `false` until the reviewer fields are completed and applied.

## Required Reviewer Fields

- `final_vulnerable_side`: `A`, `B`, or `unclear`.
- `label_status`: `confirmed_gold`, `corrected_side`, `ambiguous`, `insufficient_context`, or `not_security_relevant`.
- `evidence_span_sufficient`: `yes`, `no`, `partial`, or `not_applicable`.
- `final_evidence_window_ids`: visible selected window IDs, such as `A1;B1`, when applicable.
- `reviewer`, `reviewed_at`, and `rationale`: reviewer provenance and decision rationale.

## Commands

```powershell
.\.venv\Scripts\python.exe scripts\export_high_quality_manual_evidence_adjudication_template.py
.\.venv\Scripts\python.exe scripts\apply_manual_evidence_adjudications.py `
  --queues data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl `
  --adjudications data/processed/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv `
  --output data/processed/secure_code_primevul_manual_evidence_high_quality_adjudicated_v1.jsonl `
  --summary-output reports/secure_code_primevul_manual_evidence_high_quality_adjudication_apply_summary_v1.json `
  --dry-run
.\.venv\Scripts\python.exe scripts\apply_manual_evidence_adjudications.py `
  --queues data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl `
  --adjudications data/processed/secure_code_primevul_manual_evidence_high_quality_adjudication_template_v1.csv `
  --output data/processed/secure_code_primevul_manual_evidence_high_quality_adjudicated_v1.jsonl `
  --summary-output reports/secure_code_primevul_manual_evidence_high_quality_adjudication_apply_summary_v1.json
.\.venv\Scripts\python.exe scripts\analyze_manual_evidence_adjudications.py `
  --input data/processed/secure_code_primevul_manual_evidence_high_quality_adjudicated_v1.jsonl `
  --queues data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl `
  --json-output reports/secure_code_primevul_manual_evidence_high_quality_adjudication_analysis_v1.json `
  --md-output reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_ANALYSIS.md
```

The empty template is not independent gold. It is only the review contract. Treat the `codex_pilot` and `codex_draft` fields as triage aids until a human reviewer completes the CSV and the apply step succeeds.
