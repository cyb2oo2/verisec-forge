from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@dataclass(slots=True)
class EvidenceSpan:
    file_path: str
    line_start: int | None = None
    line_end: int | None = None
    symbol: str | None = None
    snippet: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EvidenceSpan":
        return cls(**raw)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_evidence_list(raw_items: Any) -> list[EvidenceSpan]:
    if raw_items is None:
        return []
    if isinstance(raw_items, str):
        cleaned = raw_items.strip()
        return [EvidenceSpan(file_path="snippet", snippet=cleaned)] if cleaned else []
    if isinstance(raw_items, dict):
        raw_items = [raw_items]
    normalized: list[EvidenceSpan] = []
    for item in raw_items:
        if isinstance(item, EvidenceSpan):
            normalized.append(item)
        elif isinstance(item, dict):
            normalized.append(EvidenceSpan.from_dict(item))
        elif isinstance(item, str):
            cleaned = item.strip()
            if cleaned:
                normalized.append(EvidenceSpan(file_path="snippet", snippet=cleaned))
    return normalized


@dataclass(slots=True)
class SecureCodeSample:
    id: str
    task_type: str
    language: str
    prompt: str
    code: str | None = None
    diff: str | None = None
    context: str | None = None
    split: str = "train"
    difficulty: str = "unknown"
    source: str = "unknown"
    has_vulnerability: bool | None = None
    vulnerability_type: str | None = None
    severity: str | None = None
    gold_fix_choice: str | None = None
    gold_evidence: list[dict[str, Any]] | None = None
    gold_explanation: str | None = None
    gold_fix_principle: str | None = None
    response: str | None = None
    chosen: str | None = None
    rejected: str | None = None
    score: float | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SecureCodeSample":
        return cls(**raw)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SecureCodeGenerationRecord:
    id: str
    task_type: str
    prompt: str
    code: str | None
    diff: str | None
    language: str
    has_vulnerability: bool | None
    predicted_vulnerability_type: str
    predicted_severity: str
    evidence: list[EvidenceSpan]
    explanation: str
    fix_principle: str
    confidence: float | None
    label_correct: bool
    evidence_supported: bool
    explanation_supported: bool
    format_ok: bool
    token_count: int
    latency_ms: float
    model_version: str
    backend_type: str
    parse_method: str = "schema"
    parse_confidence: float = 1.0
    parse_trigger: str = "none"
    verifier_used: bool = False
    verifier_overrode: bool = False
    verifier_trigger: str = "none"
    verifier_confidence: float | None = None
    verifier_raw_text: str = ""
    ensemble_used: bool = False
    ensemble_overrode: bool = False
    timestamp: str = field(default_factory=utc_now_iso)
    raw_text: str = ""
    error: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SecureCodeGenerationRecord":
        payload = dict(raw)
        payload["evidence"] = normalize_evidence_list(payload.get("evidence", []))
        return cls(**payload)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence"] = [item.to_dict() for item in self.evidence]
        return data


@dataclass(slots=True)
class SecureCodeEvalRow:
    id: str
    task_type: str
    label_correct: bool
    evidence_supported: bool
    explanation_supported: bool
    format_ok: bool
    high_confidence_error: bool
    invalid_output: bool
    token_count: int
    difficulty: str
    source: str
    language: str
    model_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class MathSample:
    id: str
    prompt: str
    gold_answer: str
    split: str
    difficulty: str
    source: str
    response: str | None = None
    chosen: str | None = None
    rejected: str | None = None
    score: float | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "MathSample":
        return cls(**raw)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class GenerationRecord:
    id: str
    prompt: str
    gold_answer: str
    reasoning: str
    final_answer: str
    parsed_answer: str
    is_correct: bool
    format_ok: bool
    token_count: int
    latency_ms: float
    model_version: str
    backend_type: str
    parse_method: str = "rule"
    parse_confidence: float = 1.0
    parse_trigger: str = "none"
    timestamp: str = field(default_factory=utc_now_iso)
    raw_text: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EvalRow:
    id: str
    correct: bool
    format_ok: bool
    token_count: int
    timeout: bool
    invalid_answer: bool
    repeated_reasoning: bool
    reasoning_failure: bool
    extraction_failure: bool
    difficulty: str
    source: str
    model_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExperimentRecord:
    stage: str
    model_name: str
    config_path: str
    artifact_path: str
    metrics: dict[str, Any]
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
