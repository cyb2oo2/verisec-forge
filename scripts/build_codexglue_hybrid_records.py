from __future__ import annotations

import argparse
import json
from pathlib import Path

from vrf.io_utils import read_jsonl
from vrf.schemas import EvidenceSpan, SecureCodeGenerationRecord, SecureCodeSample
from vrf.text_utils import security_label_correct


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a hybrid CodeXGLUE detector+a auditor generation file.")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--classifier-preds", required=True)
    parser.add_argument("--auditor-generations", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--model-version", default="hybrid_codexglue_detector_auditor_v1")
    args = parser.parse_args()

    samples = {row["id"]: SecureCodeSample.from_dict(row) for row in read_jsonl(args.dataset)}
    preds = {row["id"]: row for row in read_jsonl(args.classifier_preds)}
    auditor = {row["id"]: SecureCodeGenerationRecord(**row) for row in read_jsonl(args.auditor_generations)}

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows_out: list[dict] = []
    for sample_id, sample in samples.items():
        pred_row = preds[sample_id]
        auditor_row = auditor[sample_id]
        pred_has = bool(pred_row["pred"])

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
            confidence=None,
            label_correct=label_correct,
            evidence_supported=evidence_supported,
            explanation_supported=bool(explanation.strip()),
            format_ok=True,
            token_count=max(1, len(explanation.split()) + len(fix_principle.split())),
            latency_ms=auditor_row.latency_ms,
            model_version=args.model_version,
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
                    "confidence": None,
                    "fix_choice": "",
                },
                ensure_ascii=False,
            ),
        )
        rows_out.append(record.to_dict())

    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows_out:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(json.dumps({"rows": len(rows_out), "output": str(output_path)}, indent=2))


if __name__ == "__main__":
    main()
