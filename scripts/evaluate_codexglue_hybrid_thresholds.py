from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.evaluation import evaluate_run
from vrf.io_utils import read_jsonl, write_json, write_jsonl
from vrf.schemas import EvidenceSpan, SecureCodeGenerationRecord, SecureCodeSample
from vrf.text_utils import security_label_correct


def build_hybrid_rows(
    dataset_path: str,
    probability_path: str,
    auditor_generations_path: str,
    threshold: float,
    model_version: str,
) -> list[dict]:
    samples = {row["id"]: SecureCodeSample.from_dict(row) for row in read_jsonl(dataset_path)}
    probabilities = {row["id"]: row for row in read_jsonl(probability_path)}
    auditor = {row["id"]: SecureCodeGenerationRecord(**row) for row in read_jsonl(auditor_generations_path)}

    rows_out: list[dict] = []
    for sample_id, sample in samples.items():
        prob_row = probabilities[sample_id]
        auditor_row = auditor[sample_id]
        pred_has = bool(float(prob_row["vuln_probability"]) >= threshold)

        if pred_has:
            predicted_vulnerability_type = "unknown"
            predicted_severity = "unknown"
            if auditor_row.has_vulnerability:
                evidence = [item.to_dict() for item in auditor_row.evidence]
                explanation = auditor_row.explanation or "A vulnerability-like defect is detected by the classifier."
                fix_principle = auditor_row.fix_principle or "Investigate the unsafe behavior and replace it with a safer implementation."
            else:
                evidence = []
                explanation = "A vulnerability-like defect is detected by the classifier and should be reviewed as unsafe."
                fix_principle = "Investigate the unsafe behavior and replace it with a safer implementation."
            evidence_supported = bool(evidence)
        else:
            predicted_vulnerability_type = "none"
            predicted_severity = "none"
            evidence = []
            explanation = auditor_row.explanation or "No vulnerability-like defect is detected for this function."
            fix_principle = auditor_row.fix_principle or "Preserve safe coding practices and avoid introducing unsafe behavior."
            evidence_supported = True

        label_correct = security_label_correct(
            pred_has,
            predicted_vulnerability_type,
            sample.has_vulnerability,
            sample.vulnerability_type,
        )

        record = SecureCodeGenerationRecord(
            id=sample.id,
            task_type=sample.task_type,
            prompt=sample.prompt,
            code=sample.code,
            diff=sample.diff,
            language=sample.language,
            has_vulnerability=pred_has,
            predicted_vulnerability_type=predicted_vulnerability_type,
            predicted_severity=predicted_severity,
            evidence=[EvidenceSpan.from_dict(item) for item in evidence],
            explanation=explanation,
            fix_principle=fix_principle,
            confidence=float(prob_row["vuln_probability"]),
            label_correct=label_correct,
            evidence_supported=evidence_supported,
            explanation_supported=bool(explanation.strip()),
            format_ok=True,
            token_count=max(1, len(explanation.split()) + len(fix_principle.split())),
            latency_ms=auditor_row.latency_ms,
            model_version=model_version,
            backend_type="hybrid",
            parse_method="hybrid_classifier",
            parse_confidence=1.0,
            parse_trigger="none",
            raw_text=json.dumps(
                {
                    "has_vulnerability": pred_has,
                    "vulnerability_type": predicted_vulnerability_type,
                    "severity": predicted_severity,
                    "evidence": evidence,
                    "explanation": explanation,
                    "fix_principle": fix_principle,
                    "confidence": float(prob_row["vuln_probability"]),
                    "fix_choice": "",
                },
                ensure_ascii=False,
            ),
        )
        rows_out.append(record.to_dict())
    return rows_out


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate hybrid classifier+auditor operating points on CodeXGLUE.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--probabilities", required=True)
    parser.add_argument("--auditor-generations", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--thresholds", default="0.2,0.5,0.8")
    args = parser.parse_args()

    thresholds = [float(item.strip()) for item in args.thresholds.split(",") if item.strip()]
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    summaries = []
    for threshold in thresholds:
        tag = str(threshold).replace(".", "p")
        generations_path = output_dir / f"secure_code_codexglue_hybrid_threshold_{tag}_generations.jsonl"
        report_json_path = output_dir / f"secure_code_codexglue_hybrid_threshold_{tag}_report.json"
        report_csv_path = output_dir / f"secure_code_codexglue_hybrid_threshold_{tag}_rows.csv"

        rows = build_hybrid_rows(
            dataset_path=args.dataset,
            probability_path=args.probabilities,
            auditor_generations_path=args.auditor_generations,
            threshold=threshold,
            model_version=f"hybrid_codexglue_detector_auditor_threshold_{tag}",
        )
        write_jsonl(generations_path, rows)

        report = evaluate_run(
            {
                "dataset_path": args.dataset,
                "generations_path": str(generations_path),
                "report_json_path": str(report_json_path),
                "report_csv_path": str(report_csv_path),
                "metrics": {},
            },
            config_path=f"hybrid_threshold_{tag}",
        )
        summary = dict(report["summary"])
        summary["threshold"] = threshold
        summaries.append(summary)

    payload = {
        "thresholds": summaries,
        "best_by_presence_accuracy": max(summaries, key=lambda row: (row["presence_accuracy"], row["safe_specificity"])),
        "best_by_vulnerable_recall": max(summaries, key=lambda row: (row["vulnerable_recall"], row["presence_accuracy"])),
        "best_by_safe_specificity": max(summaries, key=lambda row: (row["safe_specificity"], row["presence_accuracy"])),
    }
    write_json(output_dir / "secure_code_codexglue_hybrid_threshold_summary.json", payload)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
