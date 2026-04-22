from __future__ import annotations

from typing import Any, Protocol

from vrf.schemas import EvidenceSpan, SecureCodeGenerationRecord, SecureCodeSample
from vrf.task_profiles import system_prompt_for_task
from vrf.text_utils import (
    parse_security_structured_response,
    security_label_correct,
    security_parse_confidence,
    token_count,
)


class GenerationBackend(Protocol):
    config: Any
    model_version: str
    backend_type: str

    def extract_answer_text(
        self,
        question: str,
        model_response: str,
        system_prompt: str | None = None,
    ) -> str | None: ...

    def verify_safe_prediction_text(
        self,
        question: str,
        model_response: str,
        system_prompt: str | None = None,
    ) -> str | None: ...


def _build_default_security_payload() -> dict[str, Any]:
    return {
        "has_vulnerability": None,
        "vulnerability_type": "unknown",
        "severity": "unknown",
        "evidence": [],
        "explanation": "",
        "fix_principle": "",
        "confidence": None,
        "fix_choice": "",
    }


def _coerce_evidence(items: Any) -> list[EvidenceSpan]:
    if not isinstance(items, list):
        return []
    evidence: list[EvidenceSpan] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            evidence.append(EvidenceSpan.from_dict(item))
        except TypeError:
            continue
    return evidence


def _coerce_verifier_override(payload: dict[str, Any]) -> bool:
    has_vulnerability = payload.get("has_vulnerability")
    if has_vulnerability is not True:
        return False
    vulnerability_type = str(payload.get("vulnerability_type", "")).strip().lower()
    if vulnerability_type in {"", "none"}:
        return False
    return True


def _safe_confidence_value(value: Any, threshold: float) -> bool:
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return float(value) <= threshold
    if isinstance(value, str):
        try:
            return float(value.strip()) <= threshold
        except ValueError:
            return False
    return False


def build_generation_record_from_text(
    backend: GenerationBackend,
    sample: SecureCodeSample,
    text: str,
    latency_ms: float,
) -> SecureCodeGenerationRecord:
    task_system_prompt = backend.config.system_prompt or system_prompt_for_task(sample.task_type)
    parsed_payload, structured_ok, parse_style = parse_security_structured_response(text)
    payload = _build_default_security_payload()
    payload.update(parsed_payload)
    format_ok = structured_ok
    parse_method = "structured_json" if structured_ok else "none"
    verifier_used = False
    verifier_overrode = False
    verifier_trigger = "none"
    verifier_confidence: float | None = None
    verifier_raw_text = ""

    confidence, confidence_reasons, hard_fail = security_parse_confidence(
        text,
        payload,
        parse_style,
    )
    parse_trigger = "none"

    needs_second_pass = False
    if backend.config.enable_second_pass:
        if hard_fail:
            needs_second_pass = True
            parse_trigger = "hard_fail"
        elif confidence < backend.config.second_pass_confidence_threshold:
            needs_second_pass = True
            parse_trigger = "low_confidence"

    if needs_second_pass:
        extracted_answer_text = backend.extract_answer_text(sample.prompt, text, system_prompt=task_system_prompt)
        if extracted_answer_text:
            fallback_payload, fallback_ok, _ = parse_security_structured_response(extracted_answer_text)
            if fallback_ok:
                payload = _build_default_security_payload()
                payload.update(fallback_payload)
                format_ok = True
                parse_method = "second_pass_model"
                confidence = 1.0 if parse_trigger == "hard_fail" else max(confidence, 0.95)
            elif parse_method != "structured_json":
                parse_method = "none"
    elif confidence_reasons:
        parse_trigger = ",".join(confidence_reasons)

    predicted_has_vulnerability = payload["has_vulnerability"]
    predicted_vulnerability_type = str(payload.get("vulnerability_type", "unknown"))

    if (
        backend.config.enable_safe_verifier
        and predicted_has_vulnerability is False
        and (
            confidence < backend.config.safe_verifier_parse_threshold
            or _safe_confidence_value(payload.get("confidence"), backend.config.safe_verifier_confidence_threshold)
        )
    ):
        verifier_used = True
        verifier_trigger = "safe_low_confidence"
        verifier_text = backend.verify_safe_prediction_text(sample.prompt, text, system_prompt=task_system_prompt)
        if verifier_text:
            verifier_raw_text = verifier_text
            verifier_payload, verifier_ok, verifier_style = parse_security_structured_response(verifier_text)
            if verifier_ok:
                verifier_confidence, _, verifier_hard_fail = security_parse_confidence(
                    verifier_text,
                    verifier_payload,
                    verifier_style,
                )
                if not verifier_hard_fail and _coerce_verifier_override(verifier_payload):
                    payload = _build_default_security_payload()
                    payload.update(verifier_payload)
                    predicted_has_vulnerability = payload["has_vulnerability"]
                    predicted_vulnerability_type = str(payload.get("vulnerability_type", "unknown"))
                    format_ok = True
                    parse_method = "safe_verifier"
                    parse_trigger = verifier_trigger
                    confidence = max(confidence, verifier_confidence)
                    verifier_overrode = True
            else:
                verifier_confidence = 0.0

    label_correct = security_label_correct(
        predicted_has_vulnerability,
        predicted_vulnerability_type,
        sample.has_vulnerability,
        sample.vulnerability_type,
    )
    evidence = _coerce_evidence(payload.get("evidence"))
    evidence_supported = bool(evidence) if predicted_has_vulnerability else not evidence
    explanation_supported = bool(str(payload.get("explanation", "")).strip())

    return SecureCodeGenerationRecord(
        id=sample.id,
        task_type=sample.task_type,
        prompt=sample.prompt,
        code=sample.code,
        diff=sample.diff,
        language=sample.language,
        has_vulnerability=predicted_has_vulnerability,
        predicted_vulnerability_type=predicted_vulnerability_type,
        predicted_severity=str(payload.get("severity", "unknown")),
        evidence=evidence,
        explanation=str(payload.get("explanation", "")).strip(),
        fix_principle=str(payload.get("fix_principle", "")).strip(),
        confidence=payload.get("confidence"),
        label_correct=label_correct,
        evidence_supported=evidence_supported,
        explanation_supported=explanation_supported,
        format_ok=format_ok,
        token_count=token_count(text),
        latency_ms=round(latency_ms, 3),
        model_version=backend.model_version,
        backend_type=backend.backend_type,
        parse_method=parse_method,
        parse_confidence=confidence,
        parse_trigger=parse_trigger,
        verifier_used=verifier_used,
        verifier_overrode=verifier_overrode,
        verifier_trigger=verifier_trigger,
        verifier_confidence=verifier_confidence,
        verifier_raw_text=verifier_raw_text,
        raw_text=text,
    )
