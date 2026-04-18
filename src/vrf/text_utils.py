from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import Any


FINAL_ANSWER_PATTERN = re.compile(r"Final Answer:\s*(.+)", re.IGNORECASE)
INLINE_FINAL_ANSWER_PATTERN = re.compile(
    r"(?:final answer is|answer is|therefore[, ]+the final answer is)\s*(.+?)(?:$|\n)",
    re.IGNORECASE,
)
REASONING_PATTERN = re.compile(
    r"Reasoning:\s*(.+?)(?:\n\s*Final Answer:|(?:^|\s)Final Answer:|$)",
    re.IGNORECASE | re.DOTALL,
)
NUMERIC_PATTERN = re.compile(r"-?\d+(?:\.\d+)?")
KV_LINE_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*?)\s*$")
FENCE_PATTERN = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE | re.MULTILINE)
JSONISH_KEY_PATTERN = re.compile(r'([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*:)')
TRAILING_COMMA_PATTERN = re.compile(r",\s*([}\]])")
SECURITY_PAIR_KEY_PATTERN = re.compile(
    r'"?(has_vulnerability|vulnerability_type|vuln_type|cwe|severity|evidence|explaination|explanation|'
    r'rationale|reason|fix_principle|remediation|fix|confidence|fix_choice)"?\s*(?::|,)\s*',
    re.IGNORECASE,
)

VULNERABILITY_TYPE_ALIASES: dict[str, str] = {
    "none": "none",
    "safe": "none",
    "no-vulnerability": "none",
    "no-vuln": "none",
    "buffer-overflow": "cwe-787",
    "buffer_overflow": "cwe-787",
    "out-of-bounds-write": "cwe-787",
    "out_of_bounds_write": "cwe-787",
    "out-of-bounds-read": "cwe-125",
    "out_of_bounds_read": "cwe-125",
    "buffer-overread": "cwe-125",
    "buffer_overread": "cwe-125",
    "buffer-overread-or-overflow": "cwe-125",
    "integer-overflow": "cwe-190",
    "integer_underflow": "cwe-191",
    "integer-underflow": "cwe-191",
    "divide-by-zero": "cwe-369",
    "division-by-zero": "cwe-369",
    "null-pointer-dereference": "cwe-476",
    "null_pointer_dereference": "cwe-476",
    "double-free": "cwe-415",
    "double_free": "cwe-415",
    "use-after-free": "cwe-416",
    "use_after_free": "cwe-416",
    "memory-leak": "cwe-401",
    "memory_leak": "cwe-401",
    "improper-input-validation": "cwe-20",
    "input-validation": "cwe-20",
    "insecure-deserialization": "cwe-502",
    "deserialization": "cwe-502",
    "code-injection": "cwe-94",
    "command-injection": "cwe-78",
    "improper-check-or-handling-of-exceptional-conditions": "cwe-703",
    "improper-check-of-exceptional-conditions": "cwe-703",
}

CWE_EQUIVALENCE_GROUPS: tuple[set[str], ...] = (
    {"cwe-119", "cwe-120", "cwe-122", "cwe-125", "cwe-787"},
    {"cwe-189", "cwe-190", "cwe-191"},
    {"cwe-20", "cwe-1284"},
    {"cwe-703", "cwe-754"},
)

FAMILY_ROOT_BY_CWE: dict[str, str] = {
    "cwe-119": "cwe-119",
    "cwe-120": "cwe-119",
    "cwe-122": "cwe-119",
    "cwe-125": "cwe-119",
    "cwe-415": "cwe-119",
    "cwe-416": "cwe-119",
    "cwe-476": "cwe-119",
    "cwe-787": "cwe-119",
    "cwe-20": "cwe-20",
    "cwe-22": "cwe-20",
    "cwe-59": "cwe-20",
    "cwe-78": "cwe-20",
    "cwe-79": "cwe-20",
    "cwe-94": "cwe-20",
    "cwe-502": "cwe-20",
    "cwe-200": "cwe-200",
    "cwe-189": "cwe-189",
    "cwe-190": "cwe-189",
    "cwe-191": "cwe-189",
    "cwe-369": "cwe-189",
    "cwe-399": "cwe-399",
    "cwe-400": "cwe-399",
    "cwe-401": "cwe-399",
    "cwe-772": "cwe-399",
    "cwe-362": "cwe-703",
    "cwe-703": "cwe-703",
    "cwe-754": "cwe-703",
    "cwe-264": "cwe-264",
    "cwe-284": "cwe-264",
    "cwe-287": "cwe-264",
    "cwe-310": "cwe-264",
    "cwe-320": "cwe-264",
    "cwe-617": "cwe-835",
    "cwe-834": "cwe-835",
    "cwe-835": "cwe-835",
}


def normalize_answer(text: str) -> str:
    cleaned = text.strip().lower().replace(",", "").replace("$", "")
    cleaned = re.sub(r"\s+", " ", cleaned)
    if cleaned.endswith(".0"):
        cleaned = cleaned[:-2]
    return cleaned


def parse_reasoning_and_answer(text: str) -> tuple[str, str, bool]:
    reasoning_match = REASONING_PATTERN.search(text)
    answer_match = FINAL_ANSWER_PATTERN.search(text)
    inline_answer_match = INLINE_FINAL_ANSWER_PATTERN.search(text)
    reasoning = reasoning_match.group(1).strip() if reasoning_match else ""
    if answer_match:
        answer = answer_match.group(1).strip()
    elif inline_answer_match:
        answer = inline_answer_match.group(1).strip()
    else:
        answer = ""
    return reasoning, answer, bool(reasoning and answer)


def extract_json_object(text: str) -> dict[str, Any] | None:
    stripped = FENCE_PATTERN.sub("", text.strip())
    if not stripped:
        return None

    candidates: list[str] = []
    if stripped.startswith("{") and stripped.endswith("}"):
        candidates.append(stripped)

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidates.append(stripped[start:end + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            normalized_candidate = _normalize_jsonish_candidate(candidate)
            if normalized_candidate:
                try:
                    parsed = json.loads(normalized_candidate)
                except json.JSONDecodeError:
                    continue
            else:
                continue
        if isinstance(parsed, dict):
            return parsed

    decoder = json.JSONDecoder()
    for idx, char in enumerate(stripped):
        if char != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(stripped[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _normalize_jsonish_candidate(candidate: str) -> str | None:
    normalized = candidate.strip()
    if not normalized.startswith("{") or "}" not in normalized:
        return None
    normalized = normalized.replace("\r\n", "\n")
    normalized = normalized.replace("\t", " ")
    normalized = re.sub(r"^\{\{+", "{", normalized)
    normalized = re.sub(r"\}\}+$", "}", normalized)
    normalized = re.sub(r'"([A-Za-z_][A-Za-z0-9_]*)""\s*:', r'"\1":', normalized)
    normalized = re.sub(r'\{\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*,\s*', r'{"\1": ', normalized)
    normalized = re.sub(r',\s*\{\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*,\s*', r', "\1": ', normalized)
    normalized = re.sub(r"\band\s+([A-Za-z_][A-Za-z0-9_]*)\s*:", r"\1:", normalized)
    normalized = re.sub(r"\bNone\b", "null", normalized)
    normalized = re.sub(r"\bNULL\b", "null", normalized)
    normalized = re.sub(r"\bundefined\b", "null", normalized)
    normalized = re.sub(r"\bTrue\b", "true", normalized)
    normalized = re.sub(r"\bFalse\b", "false", normalized)
    normalized = normalized.replace("'", '"')
    normalized = JSONISH_KEY_PATTERN.sub(r'\1"\2"\3', normalized)
    normalized = TRAILING_COMMA_PATTERN.sub(r"\1", normalized)
    return normalized


def extract_security_kv_payload(text: str) -> dict[str, Any] | None:
    stripped = FENCE_PATTERN.sub("", text.strip())
    if not stripped:
        return None

    lines = [line.rstrip() for line in stripped.splitlines() if line.strip()]
    if not lines:
        return None

    payload: dict[str, Any] = {}
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        match = KV_LINE_PATTERN.match(line)
        if not match:
            idx += 1
            continue

        key = match.group(1).strip().lower()
        value = match.group(2).strip().strip(",")

        if key == "evidence":
            evidence_items: list[dict[str, Any]] = []
            if value and value not in {"[]", "-"}:
                evidence_items.append({"file_path": "snippet", "snippet": value})
            idx += 1
            while idx < len(lines):
                follow = lines[idx].strip()
                if KV_LINE_PATTERN.match(lines[idx]):
                    break
                if follow.startswith("- "):
                    snippet = follow[2:].strip()
                    if snippet:
                        evidence_items.append({"file_path": "snippet", "snippet": snippet})
                idx += 1
            payload[key] = evidence_items
            continue

        payload[key] = value
        idx += 1

    return payload or None


def extract_security_pair_payload(text: str) -> dict[str, Any] | None:
    stripped = FENCE_PATTERN.sub("", text.strip())
    if not stripped:
        return None

    pair_matches = list(
        re.finditer(
            r'\{\s*"?(has_vulnerability|vulnerability_type|vuln_type|cwe|severity|evidence|explaination|'
            r'explanation|rationale|reason|fix_principle|remediation|fix|confidence|fix_choice)"?\s*,\s*(.*?)\s*\}',
            stripped,
            re.IGNORECASE | re.DOTALL,
        )
    )
    loose_matches = list(SECURITY_PAIR_KEY_PATTERN.finditer(stripped))
    if not pair_matches and not loose_matches:
        return None

    payload: dict[str, Any] = {}
    extracted_items: list[tuple[str, str]] = []
    if pair_matches:
        extracted_items.extend((match.group(1).strip().lower(), match.group(2).strip()) for match in pair_matches)
    else:
        for idx, match in enumerate(loose_matches):
            key = match.group(1).strip().lower()
            value_start = match.end()
            value_end = len(stripped)
            if idx + 1 < len(loose_matches):
                value_end = loose_matches[idx + 1].start()
            raw_value = stripped[value_start:value_end].strip().strip(",").strip()
            raw_value = raw_value.lstrip("{").rstrip("}")
            raw_value = raw_value.strip().strip(",").strip()
            extracted_items.append((key, raw_value))

    for key, raw_value in extracted_items:
        if not raw_value:
            payload[key] = ""
            continue

        if raw_value.startswith("[") and raw_value.endswith("]"):
            try:
                payload[key] = json.loads(_normalize_jsonish_candidate('{"tmp": ' + raw_value + "}"))["tmp"]
                continue
            except Exception:
                payload[key] = raw_value
                continue

        lowered = raw_value.lower()
        if lowered in {"true", "false"}:
            payload[key] = lowered == "true"
            continue
        if lowered in {"null", "none"}:
            payload[key] = None
            continue
        try:
            if "." in raw_value:
                payload[key] = float(raw_value)
            else:
                payload[key] = int(raw_value)
            continue
        except ValueError:
            pass

        if (raw_value.startswith('"') and raw_value.endswith('"')) or (
            raw_value.startswith("'") and raw_value.endswith("'")
        ):
            payload[key] = raw_value[1:-1]
        else:
            payload[key] = raw_value

    return payload or None


def parse_structured_response(text: str) -> tuple[str, str, bool, str]:
    payload = extract_json_object(text)
    if not payload:
        return "", "", False, "non_json_output"
    reasoning = str(payload.get("reasoning", "")).strip()
    final_answer = str(payload.get("final_answer", "")).strip()
    if not reasoning:
        return reasoning, final_answer, False, "missing_reasoning_field"
    if not final_answer:
        return reasoning, final_answer, False, "missing_final_answer_field"
    return reasoning, final_answer, True, "structured_json"


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def _coerce_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _normalize_cwe_label(value: str) -> str:
    cleaned = normalize_answer(value).replace("_", "-").replace(" ", "-")
    cleaned = VULNERABILITY_TYPE_ALIASES.get(cleaned, cleaned)
    if cleaned.startswith("cwe-"):
        return cleaned
    if cleaned.startswith("cwe"):
        suffix = cleaned[3:].lstrip("-")
        return f"cwe-{suffix}" if suffix else "none"
    return cleaned


def vulnerability_type_matches(predicted: str | None, gold: str | None) -> bool:
    predicted_label = _normalize_cwe_label(predicted or "none")
    gold_label = _normalize_cwe_label(gold or "none")
    if predicted_label == gold_label:
        return True
    for equivalent_group in CWE_EQUIVALENCE_GROUPS:
        if predicted_label in equivalent_group and gold_label in equivalent_group:
            return True
    return False


def security_label_correct(
    predicted_has_vulnerability: bool | None,
    predicted_vulnerability_type: str | None,
    gold_has_vulnerability: bool | None,
    gold_vulnerability_type: str | None,
) -> bool:
    if predicted_has_vulnerability is None or gold_has_vulnerability is None:
        return False
    if predicted_has_vulnerability != gold_has_vulnerability:
        return False
    if not gold_has_vulnerability:
        return True
    return vulnerability_type_matches(predicted_vulnerability_type, gold_vulnerability_type)


def security_presence_correct(
    predicted_has_vulnerability: bool | None,
    gold_has_vulnerability: bool | None,
) -> bool:
    if predicted_has_vulnerability is None or gold_has_vulnerability is None:
        return False
    return predicted_has_vulnerability == gold_has_vulnerability


def family_root_label(value: str | None) -> str:
    normalized = _normalize_cwe_label(value or "none")
    if normalized in {"", "none"}:
        return "none"
    return FAMILY_ROOT_BY_CWE.get(normalized, normalized)


def security_family_label_correct(
    predicted_has_vulnerability: bool | None,
    predicted_vulnerability_type: str | None,
    gold_has_vulnerability: bool | None,
    gold_vulnerability_type: str | None,
) -> bool:
    if predicted_has_vulnerability is None or gold_has_vulnerability is None:
        return False
    if predicted_has_vulnerability != gold_has_vulnerability:
        return False
    if not gold_has_vulnerability:
        return True
    return family_root_label(predicted_vulnerability_type) == family_root_label(gold_vulnerability_type)


def _normalize_severity(value: str) -> str:
    cleaned = normalize_answer(value)
    allowed = {"critical", "high", "medium", "low", "info", "none", "unknown"}
    return cleaned if cleaned in allowed else "unknown"


def _normalize_fix_choice(value: str) -> str:
    return normalize_answer(value)


def parse_security_structured_response(
    text: str,
) -> tuple[dict[str, Any], bool, str]:
    payload = extract_json_object(text)
    parse_style = "structured_json"
    if not payload:
        payload = extract_security_kv_payload(text)
        parse_style = "structured_kv"
    if not payload:
        payload = extract_security_pair_payload(text)
        parse_style = "structured_pairs"
    if not payload:
        return {}, False, "non_json_output"

    raw_evidence = payload.get("evidence", [])
    if isinstance(raw_evidence, str):
        raw_evidence = [{"file_path": "snippet", "snippet": raw_evidence.strip()}] if raw_evidence.strip() else []
    elif isinstance(raw_evidence, dict):
        raw_evidence = [raw_evidence]

    parsed: dict[str, Any] = {
        "has_vulnerability": _coerce_bool(payload.get("has_vulnerability")),
        "vulnerability_type": _normalize_cwe_label(
            str(
                payload.get(
                    "vulnerability_type",
                    payload.get("vuln_type", payload.get("cwe", "none")),
                )
            )
        ),
        "severity": _normalize_severity(str(payload.get("severity", "unknown"))),
        "explanation": str(
            payload.get(
                "explanation",
                payload.get("explaination", payload.get("rationale", payload.get("reason", ""))),
            )
        ).strip(),
        "fix_principle": str(
            payload.get("fix_principle", payload.get("remediation", payload.get("fix", "")))
        ).strip(),
        "fix_choice": _normalize_fix_choice(str(payload.get("fix_choice", ""))),
        "confidence": _coerce_float(payload.get("confidence")),
        "evidence": raw_evidence,
    }

    if parsed["has_vulnerability"] is None:
        return parsed, False, "missing_has_vulnerability_field"
    if not isinstance(parsed["evidence"], list):
        return parsed, False, "invalid_evidence_field"
    if not parsed["explanation"]:
        return parsed, False, "missing_explanation_field"
    if parsed["has_vulnerability"] and not parsed["vulnerability_type"]:
        return parsed, False, "missing_vulnerability_type_field"
    return parsed, True, parse_style


def security_parse_confidence(
    raw_text: str,
    parsed: dict[str, Any],
    parse_style: str,
) -> tuple[float, list[str], bool]:
    if parse_style not in {"structured_json", "structured_kv", "structured_pairs"}:
        return 0.0, ["non_structured_output"], True

    reasons: list[str] = []
    score = 1.0

    explanation = str(parsed.get("explanation", "")).strip()
    fix_principle = str(parsed.get("fix_principle", "")).strip()
    vulnerability_type = str(parsed.get("vulnerability_type", "")).strip()
    evidence = parsed.get("evidence", [])
    confidence = parsed.get("confidence")

    if not explanation:
        return 0.0, ["missing_explanation"], True
    if parsed.get("has_vulnerability") and not vulnerability_type:
        return 0.0, ["missing_vulnerability_type"], True
    if not isinstance(evidence, list):
        return 0.0, ["invalid_evidence_field"], True

    if parsed.get("has_vulnerability") and not evidence:
        score -= 0.25
        reasons.append("missing_evidence")
    if explanation and len(explanation.split()) > 40:
        score -= 0.1
        reasons.append("verbose_explanation")
    if fix_principle and len(fix_principle.split()) > 30:
        score -= 0.1
        reasons.append("verbose_fix_principle")
    if isinstance(confidence, float) and not 0.0 <= confidence <= 1.0:
        score -= 0.25
        reasons.append("confidence_out_of_range")
    if "```" in raw_text:
        score -= 0.15
        reasons.append("markdown_fence_in_output")
    if raw_text.strip().count("{") > 2:
        score -= 0.1
        reasons.append("multiple_json_objects")
    if parse_style == "structured_kv":
        score -= 0.15
        reasons.append("kv_block_output")
    if parse_style == "structured_pairs":
        score -= 0.2
        reasons.append("pair_block_output")

    return max(0.0, round(score, 4)), reasons, False


def extract_numeric_answer(text: str) -> str:
    normalized = normalize_answer(text)
    matches = NUMERIC_PATTERN.findall(normalized)
    if not matches:
        return normalized
    if "=" in normalized:
        rhs = normalized.rsplit("=", 1)[-1]
        rhs_matches = NUMERIC_PATTERN.findall(rhs)
        if rhs_matches:
            return rhs_matches[-1]
    return matches[-1]


def parse_confidence(raw_text: str, reasoning: str, final_answer: str, parsed_answer: str) -> tuple[float, list[str]]:
    if not final_answer or not parsed_answer:
        return 0.0, ["missing_answer"]

    normalized_answer = normalize_answer(final_answer)
    answer_numbers = NUMERIC_PATTERN.findall(normalized_answer)
    reasons: list[str] = []
    score = 1.0

    if "final answer:" not in raw_text.lower():
        score -= 0.2
        reasons.append("no_explicit_final_answer_marker")
    if "=" in normalized_answer:
        score -= 0.3
        reasons.append("equation_in_answer")
    if len(answer_numbers) > 1:
        score -= 0.25
        reasons.append("multiple_numbers_in_answer")
    if "final answer" in reasoning.lower():
        score -= 0.15
        reasons.append("answer_embedded_in_reasoning")
    if len(final_answer.split()) > 6:
        score -= 0.15
        reasons.append("verbose_answer_span")
    if "\\(" in final_answer or "\\)" in final_answer:
        score -= 0.1
        reasons.append("latex_wrapped_answer")

    return max(0.0, round(score, 4)), reasons


def structured_parse_confidence(
    raw_text: str,
    reasoning: str,
    final_answer: str,
    parsed_answer: str,
    parse_style: str,
) -> tuple[float, list[str], bool]:
    if parse_style == "structured_json" and reasoning and final_answer and parsed_answer:
        score = 1.0
        reasons: list[str] = []
        normalized_answer = normalize_answer(final_answer)
        answer_numbers = NUMERIC_PATTERN.findall(normalized_answer)
        if "=" in normalized_answer:
            score -= 0.2
            reasons.append("equation_in_answer")
        if len(answer_numbers) > 1:
            score -= 0.15
            reasons.append("multiple_numbers_in_answer")
        if len(final_answer.split()) > 6:
            score -= 0.1
            reasons.append("verbose_answer_span")
        if "\\(" in final_answer or "\\)" in final_answer:
            score -= 0.1
            reasons.append("latex_wrapped_answer")
        return max(0.0, round(score, 4)), reasons, False

    confidence, reasons = parse_confidence(raw_text, reasoning, final_answer, parsed_answer)
    hard_fail = not bool(reasoning and final_answer and parsed_answer)
    return confidence, reasons, hard_fail


def token_count(text: str) -> int:
    return len(text.split())


def repeated_ngram_ratio(text: str, ngram_size: int = 3) -> float:
    tokens = text.lower().split()
    if len(tokens) < ngram_size:
        return 0.0
    ngrams = [tuple(tokens[idx:idx + ngram_size]) for idx in range(len(tokens) - ngram_size + 1)]
    counts = Counter(ngrams)
    repeated = sum(count - 1 for count in counts.values() if count > 1)
    return repeated / max(1, len(ngrams))


def safe_mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def length_penalty(reasoning: str, max_reasoning_tokens: int) -> float:
    excess = max(0, token_count(reasoning) - max_reasoning_tokens)
    return math.tanh(excess / max(1, max_reasoning_tokens))
