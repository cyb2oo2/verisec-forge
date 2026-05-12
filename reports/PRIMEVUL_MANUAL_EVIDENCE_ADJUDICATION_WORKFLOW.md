# PrimeVul Manual Evidence Adjudication Workflow

This workflow turns the `codex_pilot` review queues into independent adjudication records.

## Inputs

- `data/processed/secure_code_primevul_manual_evidence_high_quality_disagreements_v1.jsonl`
- `data/processed/secure_code_primevul_manual_evidence_insufficient_context_v1.jsonl`

## Template

- CSV template: `data/processed/secure_code_primevul_manual_evidence_adjudication_template_v1.csv`
- Rows: `20`
- Focused review packet: `reports/PRIMEVUL_MANUAL_EVIDENCE_HIGH_QUALITY_ADJUDICATION_PACKET.md`

## Required Reviewer Fields

- `final_vulnerable_side`: `A`, `B`, or `unclear`.
- `label_status`: `confirmed_gold`, `corrected_side`, `ambiguous`, `insufficient_context`, or `not_security_relevant`.
- `evidence_span_sufficient`: `yes`, `no`, `partial`, or `not_applicable`.
- `final_evidence_window_ids`: selected visible window IDs when applicable.
- `reviewer`, `reviewed_at`, and `rationale`: provenance and reasoning for the final decision.

## Commands

```powershell
.\.venv\Scripts\python.exe scripts\export_manual_evidence_adjudication_template.py
.\.venv\Scripts\python.exe scripts\render_manual_evidence_adjudication_packet.py
.\.venv\Scripts\python.exe scripts\apply_manual_evidence_adjudications.py --dry-run
.\.venv\Scripts\python.exe scripts\apply_manual_evidence_adjudications.py
.\.venv\Scripts\python.exe scripts\analyze_manual_evidence_adjudications.py
```

Fill the reviewer fields in the CSV template before running the non-dry-run apply command.
Treat the pilot annotation as a triage signal only. The adjudication output is the first artifact that can be treated as reviewer-confirmed.
