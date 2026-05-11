# Manual Evidence Audit Guide

This guide defines the first human-checkable evidence-span audit for the PrimeVul paired-diff line.

## Goal

The audit asks whether the generated hunk/window evidence actually supports the paired vulnerable/fixed side decision. It is designed to test the current core finding:

Evidence localization is coupled to upstream side correctness. When the side decision is wrong, evidence ranking often fails with it.

## Dataset

Primary file:

- `data/processed/secure_code_primevul_manual_evidence_audit_v1.jsonl`

Summary report:

- `reports/PRIMEVUL_MANUAL_EVIDENCE_AUDIT_SET.md`

Human-readable review packet:

- `reports/PRIMEVUL_MANUAL_EVIDENCE_REVIEW_PACKET.md`

The first version is built from the side-inversion review queues:

- `top5_v1`
- `rank6_10_v1`
- `fresh_seeds_top5_v1`
- `project_holdout_top5_v1`

The script requests `50` rows but currently materializes `42` unique pair keys after deduplication. This is expected and should be reported honestly: the high-signal side-inversion pools are useful but still small.

## Annotation Fields

- `human_vulnerable_side`: choose `A`, `B`, or `unclear`.
- `evidence_side`: choose `A`, `B`, `both`, `none`, or `unclear`.
- `evidence_quality`: use `0` for no usable evidence, `1` for weak hint, `2` for plausible evidence, and `3` for strong direct evidence.
- `selected_window_ids`: list the windows that justify the decision, such as `A1`, `A2`, or `B1`.
- `label_issue`: choose `none`, `ambiguous`, `wrong_label`, or `insufficient_context`.
- `notes`: short rationale explaining the judgment.
- `annotator`: annotator name or handle.
- `reviewed_at`: ISO-8601 timestamp.

## Annotation Rules

1. Prefer code-change evidence over CVE/project metadata.
2. Mark `unclear` when the window is too small to justify either side.
3. Mark `insufficient_context` when the likely vulnerability depends on code outside the shown windows.
4. Mark `wrong_label` only when the provided side label is clearly contradicted by the evidence and context.
5. Use `evidence_quality=3` only when the selected window directly shows a security-relevant guard, check, sanitization, bounds fix, auth decision, lifetime fix, or equivalent risk change.

## Blinding Policy

The default CSV templates and Markdown review packet are blinded: they hide gold side, model side, detector probabilities, and CVE/project metadata. This keeps the manual audit focused on whether the shown code-change evidence supports side `A`, side `B`, both, neither, or an unclear judgment.

Use `--include-labels` only for debugging the workflow, not for primary annotation.

## Regeneration

```powershell
.\.venv\Scripts\python.exe scripts\build_manual_evidence_audit_set.py `
  --sample-size 50 `
  --seed 42 `
  --output data\processed\secure_code_primevul_manual_evidence_audit_v1.jsonl
.\.venv\Scripts\python.exe scripts\render_manual_evidence_review_packet.py
```

## CSV Annotation Workflow

Export a CSV template:

```powershell
.\.venv\Scripts\python.exe scripts\export_manual_evidence_annotation_template.py
```

Or export smaller batch files for pilot annotation:

```powershell
.\.venv\Scripts\python.exe scripts\export_manual_evidence_annotation_batches.py --batch-size 10
```

Fill the annotation columns in the generated CSV:

- `human_vulnerable_side`
- `evidence_side`
- `evidence_quality`
- `selected_window_ids`
- `label_issue`
- `notes`
- `annotator`
- `reviewed_at`

Then validate and apply the completed annotations:

```powershell
.\.venv\Scripts\python.exe scripts\apply_manual_evidence_annotations.py `
  --annotations data\processed\manual_evidence_audit_batches\manual_evidence_audit_v1_batch_01.csv `
  --dry-run

.\.venv\Scripts\python.exe scripts\apply_manual_evidence_annotations.py `
  --annotations data\processed\manual_evidence_audit_batches\manual_evidence_audit_v1_batch_01.csv
```

The apply script rejects unknown `audit_id` values, invalid enum values, invalid evidence quality values, and selected window IDs that do not exist for the row.

## Next Step

After annotation, run:

```powershell
.\.venv\Scripts\python.exe scripts\analyze_manual_evidence_audit.py
```

The analysis reports completion rate, invalid annotation rows, human-vs-gold agreement, evidence-vs-gold agreement, evidence quality distribution, and label issue rates.
