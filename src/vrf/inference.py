from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vrf.schemas import EvidenceSpan, SecureCodeGenerationRecord, SecureCodeSample
from vrf.task_profiles import system_prompt_for_task
from vrf.text_utils import (
    extract_json_object,
    parse_security_structured_response,
    security_label_correct,
    security_parse_confidence,
    token_count,
)


CODE_MARKER_PATTERN = re.compile(r"\n\n(code|diff):\n", re.IGNORECASE)
SECURITY_FOCUS_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bos\.system\b",
        r"\bsubprocess\b",
        r"\binnerhtml\b",
        r"\bdangerouslysetinnerhtml\b",
        r"\bselect\b.+\bfrom\b",
        r"\binsert\b.+\binto\b",
        r"\bupdate\b.+\bset\b",
        r"\bdelete\b.+\bfrom\b",
        r"\bpassword\b",
        r"\btoken\b",
        r"\bauth\b",
        r"\bcsrf\b",
        r"\bxss\b",
        r"\bsql\b",
        r"\bcommand\b",
        r"\bshell\b",
        r"\bserialize\b",
        r"\bdeserialize\b",
        r"\bpickle\b",
        r"\byaml\.load\b",
        r"\bmd5\b",
        r"\bsha1\b",
        r"\bcrypto\b",
        r"\bhttp\.redirect\b",
        r"\bsetheader\b",
        r"\bunsafe\b",
    ]
]
FOCUS_GROUPS: list[tuple[str, list[re.Pattern[str]]]] = [
    (
        "command_execution",
        [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [r"\beval\s*\(", r"\bexec\s*\(", r"\bos\.system\b", r"\bsubprocess\b", r"\bshell\b", r"\bcommand\b"]
        ],
    ),
    (
        "database_query",
        [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [r"\bselect\b.+\bfrom\b", r"\binsert\b.+\binto\b", r"\bupdate\b.+\bset\b", r"\bdelete\b.+\bfrom\b", r"\bsql\b"]
        ],
    ),
    (
        "web_output",
        [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [r"\binnerhtml\b", r"\bdangerouslysetinnerhtml\b", r"\bsetheader\b", r"\bhttp\.redirect\b", r"\bcsrf\b", r"\bauth\b"]
        ],
    ),
    (
        "deserialization_and_crypto",
        [
            re.compile(pattern, re.IGNORECASE)
            for pattern in [r"\bserialize\b", r"\bdeserialize\b", r"\bpickle\b", r"\byaml\.load\b", r"\bmd5\b", r"\bsha1\b", r"\bcrypto\b", r"\btoken\b", r"\bpassword\b"]
        ],
    ),
]
STRUCTURE_HINT_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"^\s*(def|class)\s+\w+",
        r"^\s*(func|type)\s+\w+",
        r"^\s*(public|private|protected)?\s*(static\s+)?\w[\w<>\[\]]*\s+\w+\s*\(",
        r"^\s*router\.",
        r"^\s*http\.",
        r"^\s*if\s+",
        r"^\s*switch\s+",
        r"^\s*case\s+",
    ]
]


def _select_focus_lines(lines: list[str], window: int = 2, max_matches: int = 18) -> list[str]:
    focus_indexes: set[int] = set()
    for idx, line in enumerate(lines):
        if any(pattern.search(line) for pattern in SECURITY_FOCUS_PATTERNS):
            start = max(0, idx - window)
            end = min(len(lines), idx + window + 1)
            focus_indexes.update(range(start, end))
            if len(focus_indexes) >= max_matches * (window * 2 + 1):
                break
    return [lines[idx] for idx in sorted(focus_indexes)]


def _nearest_structure_start(lines: list[str], idx: int, lookback: int = 80) -> int:
    lower = max(0, idx - lookback)
    for candidate in range(idx, lower - 1, -1):
        if any(pattern.search(lines[candidate]) for pattern in STRUCTURE_HINT_PATTERNS):
            return candidate
    return max(0, idx - 12)


def _structure_end(lines: list[str], start: int, hint_idx: int, lookahead: int = 120) -> int:
    upper = min(len(lines), max(start + 24, hint_idx + lookahead))
    brace_depth = 0
    seen_open = False

    for idx in range(start, upper):
        line = lines[idx]
        brace_depth += line.count("{")
        if line.count("{") > 0:
            seen_open = True
        brace_depth -= line.count("}")

        if idx > start + 8 and any(pattern.search(line) for pattern in STRUCTURE_HINT_PATTERNS):
            return idx
        if seen_open and brace_depth <= 0 and idx >= hint_idx + 4:
            return idx + 1
    return upper


def _expand_span_to_enclosing_block(
    lines: list[str],
    start: int,
    end: int,
    max_block_lines: int = 40,
) -> tuple[int, int]:
    hint_idx = start
    block_start = _nearest_structure_start(lines, hint_idx)
    block_end = _structure_end(lines, block_start, hint_idx)

    merged_start = min(start, block_start)
    merged_end = max(end, block_end)
    if merged_end - merged_start > max_block_lines:
        center = (start + end) // 2
        half = max_block_lines // 2
        merged_start = max(0, center - half)
        merged_end = min(len(lines), merged_start + max_block_lines)
    return merged_start, merged_end


def _focus_spans(
    lines: list[str],
    window: int = 6,
    max_focus_matches: int = 10,
    max_structure_matches: int = 6,
) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    focus_hits = 0
    structure_hits = 0

    for idx, line in enumerate(lines):
        if focus_hits < max_focus_matches and any(pattern.search(line) for pattern in SECURITY_FOCUS_PATTERNS):
            raw_start = max(0, idx - window)
            raw_end = min(len(lines), idx + window + 1)
            spans.append(_expand_span_to_enclosing_block(lines, raw_start, raw_end))
            focus_hits += 1
            continue
        if structure_hits < max_structure_matches and any(pattern.search(line) for pattern in STRUCTURE_HINT_PATTERNS):
            spans.append((idx, min(len(lines), idx + 8)))
            structure_hits += 1

    if not spans:
        return [(0, min(len(lines), 40))]

    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if not merged or start > merged[-1][1] + 2:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return merged[:8]


def _render_focus_windows(lines: list[str], spans: list[tuple[int, int]]) -> str:
    windows: list[str] = []
    for window_idx, (start, end) in enumerate(spans, start=1):
        rendered_lines = [f"{line_no + 1}: {lines[line_no]}" for line_no in range(start, end)]
        windows.append(f"Window {window_idx} (lines {start + 1}-{end}):\n" + "\n".join(rendered_lines).strip())
    return "\n\n".join(windows)


def _group_focus_spans(lines: list[str], max_per_group: int = 2) -> list[tuple[str, tuple[int, int]]]:
    grouped: list[tuple[str, tuple[int, int]]] = []
    for group_name, patterns in FOCUS_GROUPS:
        hits = 0
        for idx, line in enumerate(lines):
            if any(pattern.search(line) for pattern in patterns):
                raw_start = max(0, idx - 6)
                raw_end = min(len(lines), idx + 7)
                grouped.append((group_name, _expand_span_to_enclosing_block(lines, raw_start, raw_end)))
                hits += 1
                if hits >= max_per_group:
                    break
    return grouped


def _render_grouped_focus_windows(lines: list[str], grouped_spans: list[tuple[str, tuple[int, int]]]) -> str:
    if not grouped_spans:
        return ""
    rendered: list[str] = []
    for idx, (group_name, (start, end)) in enumerate(grouped_spans, start=1):
        rendered_lines = [f"{line_no + 1}: {lines[line_no]}" for line_no in range(start, end)]
        rendered.append(
            f"Hotspot {idx} [{group_name}] (lines {start + 1}-{end}):\n" + "\n".join(rendered_lines).strip()
        )
    return "\n\n".join(rendered)


def compress_secure_code_prompt(prompt: str, max_chars: int | None) -> str:
    if not max_chars or len(prompt) <= max_chars:
        return prompt

    marker_match = CODE_MARKER_PATTERN.search(prompt)
    if not marker_match:
        head = max_chars // 2
        tail = max_chars - head
        return (
            prompt[:head]
            + "\n\n[... TRUNCATED FOR MODEL CONTEXT BUDGET ...]\n\n"
            + prompt[-tail:]
        )

    marker = marker_match.group(1).lower()
    prefix = prompt[:marker_match.end()]
    body = prompt[marker_match.end():]
    body_lines = body.splitlines()
    prologue_block = "\n".join(f"{idx + 1}: {line}" for idx, line in enumerate(body_lines[:8])).strip()
    focus_spans = _focus_spans(body_lines)
    focus_block = _render_focus_windows(body_lines, focus_spans).strip()
    grouped_focus_block = _render_grouped_focus_windows(body_lines, _group_focus_spans(body_lines)).strip()

    sections = [
        prefix.rstrip(),
        "The following content is a bounded analysis snippet. It is not a completion target.",
        f"BEGIN {marker.upper()} SNIPPET",
        "[Windowed snippet selection for long-file analysis]",
    ]
    if prologue_block:
        sections.append("File prologue:\n" + prologue_block)

    suffix_sections = [
        f"END {marker.upper()} SNIPPET",
        "Analyze only the bounded snippet above. You are not a code completion model. "
        "Return exactly one JSON object and do not continue or rewrite the source code.",
    ]

    focus_parts: list[str] = []
    if grouped_focus_block:
        focus_parts.append("Candidate security hotspots:\n" + grouped_focus_block)
    if focus_block:
        focus_parts.append("Relevant windows:\n" + focus_block)
    focus_section = "\n\n".join(focus_parts).strip()
    prefix_text = "\n\n".join(section for section in sections if section)
    suffix_text = "\n\n".join(section for section in suffix_sections if section)

    if focus_section:
        compressed = "\n\n".join([prefix_text, focus_section, suffix_text])
    else:
        compressed = "\n\n".join([prefix_text, suffix_text])
    if len(compressed) <= max_chars:
        return compressed

    marker_text = "\n\n[... TRUNCATED FOR MODEL CONTEXT BUDGET ...]\n\n"
    available_focus_chars = max_chars - len(prefix_text) - len(suffix_text) - len(marker_text) - 4
    if available_focus_chars > 120 and focus_section:
        trimmed_focus = truncate_text_block(focus_section, available_focus_chars)
        return "\n\n".join([prefix_text, trimmed_focus, suffix_text])

    available_prefix_chars = max_chars - len(suffix_text) - len(marker_text) - 2
    if available_prefix_chars > 0:
        trimmed_prefix = truncate_text_block(prefix_text, available_prefix_chars)
        return "\n\n".join([trimmed_prefix, suffix_text])
    return truncate_text_block(compressed, max_chars)


def truncate_text_block(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    head = max_chars // 2
    tail = max_chars - head - 48
    return text[:head] + "\n\n[... TRUNCATED ...]\n\n" + text[-max(0, tail):]

@dataclass(slots=True)
class BackendConfig:
    type: str
    model_name: str
    temperature: float = 0.0
    max_new_tokens: int = 128
    device: str | None = None
    device_map: str | None = None
    torch_dtype: str | None = None
    system_prompt: str | None = None
    enable_second_pass: bool = False
    extraction_max_new_tokens: int = 32
    extraction_system_prompt: str | None = None
    second_pass_confidence_threshold: float = 0.75
    output_format: str = "structured_json"
    response_prefix: str | None = None
    extraction_response_prefix: str | None = None
    local_files_only: bool = False
    max_input_tokens: int | None = 1536
    max_prompt_chars: int | None = 12000
    second_pass_retry_on_hard_fail: bool = True
    enable_safe_verifier: bool = False
    safe_verifier_confidence_threshold: float = 0.82
    safe_verifier_parse_threshold: float = 0.85
    verifier_max_new_tokens: int = 96
    verifier_system_prompt: str | None = None
    verifier_response_prefix: str | None = None


class InferenceBackend(ABC):
    def __init__(self, config: BackendConfig):
        self.config = config

    @abstractmethod
    def generate_text(self, prompt: str, system_prompt: str | None = None) -> str:
        raise NotImplementedError

    def extract_answer_text(
        self,
        question: str,
        model_response: str,
        system_prompt: str | None = None,
    ) -> str | None:
        return None

    def verify_safe_prediction_text(
        self,
        question: str,
        model_response: str,
        system_prompt: str | None = None,
    ) -> str | None:
        return None

    @property
    def model_version(self) -> str:
        return self.config.model_name

    @property
    def backend_type(self) -> str:
        return self.config.type


class MockInferenceBackend(InferenceBackend):
    def generate_text(self, prompt: str, system_prompt: str | None = None) -> str:
        prompt_lower = prompt.lower()
        if any(keyword in prompt_lower for keyword in ["eval(", "exec(", "system(", "os.system", "subprocess"]):
            payload = {
                "has_vulnerability": True,
                "vulnerability_type": "cwe-78",
                "severity": "high",
                "evidence": [
                    {
                        "file_path": "snippet.py",
                        "line_start": 1,
                        "line_end": 1,
                        "snippet": "Potential unsafe command execution sink detected.",
                    }
                ],
                "explanation": "User-controlled data appears to reach an execution sink without sanitization.",
                "fix_principle": "Avoid direct execution of untrusted input and use allowlisted commands.",
                "confidence": 0.86,
                "fix_choice": "",
            }
        elif "candidate a" in prompt_lower and "candidate b" in prompt_lower:
            payload = {
                "has_vulnerability": True,
                "vulnerability_type": "cwe-20",
                "severity": "medium",
                "evidence": [],
                "explanation": "Candidate B preserves validation and reduces insecure behavior compared with the weaker option.",
                "fix_principle": "Prefer the patch that adds validation and least privilege checks.",
                "confidence": 0.74,
                "fix_choice": "candidate_b",
            }
        else:
            payload = {
                "has_vulnerability": False,
                "vulnerability_type": "none",
                "severity": "none",
                "evidence": [],
                "explanation": "No clear security weakness is evident from the provided snippet alone.",
                "fix_principle": "Keep validating inputs and minimizing attack surface.",
                "confidence": 0.55,
                "fix_choice": "",
            }
        return json.dumps(payload)


class HuggingFaceInferenceBackend(InferenceBackend):
    def __init__(self, config: BackendConfig):
        super().__init__(config)
        try:
            import torch
            from peft import AutoPeftModelForCausalLM
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError("transformers is required for the huggingface backend") from exc
        self._torch = torch
        model_kwargs: dict[str, Any] = {}

        dtype_value = None
        if config.torch_dtype:
            dtype_value = getattr(torch, config.torch_dtype, None)
            if dtype_value is None:
                raise ValueError(f"Unsupported torch dtype: {config.torch_dtype}")
        elif torch.cuda.is_available():
            dtype_value = torch.float16
        if dtype_value is not None:
            model_kwargs["dtype"] = dtype_value

        if config.device_map:
            model_kwargs["device_map"] = config.device_map
        elif torch.cuda.is_available():
            model_kwargs["device_map"] = "auto"
        pretrained_kwargs: dict[str, Any] = {}
        if config.local_files_only:
            pretrained_kwargs["local_files_only"] = True
        try:
            self._tokenizer = AutoTokenizer.from_pretrained(config.model_name, **pretrained_kwargs)
        except ValueError:
            self._tokenizer = AutoTokenizer.from_pretrained(
                config.model_name,
                use_fast=False,
                **pretrained_kwargs,
            )
        adapter_config_path = Path(config.model_name) / "adapter_config.json"
        if adapter_config_path.exists():
            self._model = AutoPeftModelForCausalLM.from_pretrained(config.model_name, **model_kwargs, **pretrained_kwargs)
            self._model = self._model.merge_and_unload()
        else:
            self._model = AutoModelForCausalLM.from_pretrained(config.model_name, **model_kwargs, **pretrained_kwargs)
        if self._tokenizer.pad_token is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token

    def _truncate_prompt_text(self, prompt: str) -> str:
        return compress_secure_code_prompt(prompt, self.config.max_prompt_chars)

    def _render_prompt(self, prompt: str, system_prompt: str | None) -> str:
        prompt = self._truncate_prompt_text(prompt)
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        if getattr(self._tokenizer, "chat_template", None):
            return self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )
        return prompt if not system_prompt else f"{system_prompt}\n\n{prompt}"

    def _generate(
        self,
        prompt: str,
        system_prompt: str | None,
        max_new_tokens: int,
        response_prefix: str | None = None,
    ) -> str:
        final_prompt = self._render_prompt(prompt, system_prompt)
        if response_prefix:
            final_prompt = final_prompt.rstrip() + "\n" + response_prefix
        tokenizer_kwargs: dict[str, Any] = {"return_tensors": "pt"}
        if self.config.max_input_tokens:
            tokenizer_kwargs["truncation"] = True
            tokenizer_kwargs["max_length"] = self.config.max_input_tokens
        encoded = self._tokenizer(final_prompt, **tokenizer_kwargs)
        model_device = next(self._model.parameters()).device
        encoded = {key: value.to(model_device) for key, value in encoded.items()}

        generate_kwargs: dict[str, Any] = {
            "max_new_tokens": max_new_tokens,
            "do_sample": self.config.temperature > 0,
            "pad_token_id": self._tokenizer.pad_token_id,
            "eos_token_id": self._tokenizer.eos_token_id,
        }
        if self.config.temperature > 0:
            generate_kwargs["temperature"] = max(self.config.temperature, 1e-5)

        output_tokens = self._model.generate(
            **encoded,
            **generate_kwargs,
        )
        generated_only = output_tokens[0][encoded["input_ids"].shape[-1]:]
        decoded = self._tokenizer.decode(generated_only, skip_special_tokens=True).strip()
        if response_prefix:
            return response_prefix + decoded
        return decoded

    def _response_prefix_for_prompt(self, prompt: str, configured_prefix: str | None) -> str | None:
        if not configured_prefix:
            return None
        if ("code:\n" in prompt or "diff:\n" in prompt) and len(prompt) > 4000:
            return None
        return configured_prefix

    def generate_text(self, prompt: str, system_prompt: str | None = None) -> str:
        response_prefix = None
        if self.config.output_format == "structured_json":
            response_prefix = self._response_prefix_for_prompt(prompt, self.config.response_prefix)
        effective_system_prompt = system_prompt or self.config.system_prompt
        return self._generate(prompt, effective_system_prompt, self.config.max_new_tokens, response_prefix=response_prefix)

    def extract_answer_text(
        self,
        question: str,
        model_response: str,
        system_prompt: str | None = None,
    ) -> str | None:
        bounded_response = truncate_text_block(model_response.strip(), 2400)
        extraction_prompt = (
            "The previous response did not reliably follow the output protocol.\n"
            "Reanalyze the original task and return one JSON object only.\n"
            "Do not continue the source code. Do not add commentary outside JSON.\n"
            "Required fields: "
            "{\"has_vulnerability\": true/false, \"vulnerability_type\": \"...\", "
            "\"severity\": \"...\", \"evidence\": [], \"explanation\": \"...\", "
            "\"fix_principle\": \"...\", \"confidence\": 0.0, \"fix_choice\": \"...\"}.\n\n"
            f"Original task:\n{question}\n\n"
            "Previous incomplete model response (may contain useful clues, but do not copy formatting mistakes):\n"
            f"{bounded_response}"
        )
        effective_system_prompt = system_prompt or self.config.extraction_system_prompt or (
            "You are a structured security extraction module. Return JSON only."
        )
        result = self._generate(
            extraction_prompt,
            effective_system_prompt,
            self.config.extraction_max_new_tokens,
            response_prefix=self._response_prefix_for_prompt(extraction_prompt, self.config.extraction_response_prefix),
        )
        payload = extract_json_object(result)
        if payload:
            return result
        return result

    def verify_safe_prediction_text(
        self,
        question: str,
        model_response: str,
        system_prompt: str | None = None,
    ) -> str | None:
        bounded_response = truncate_text_block(model_response.strip(), 2200)
        verifier_prompt = (
            "Re-audit the previous secure-code analysis because safe predictions can hide false negatives.\n"
            "Review the original task again and return one JSON object only.\n"
            "If the code appears safe, keep has_vulnerability=false.\n"
            "If there is a plausible overlooked weakness, set has_vulnerability=true and name the most likely vulnerability family or CWE.\n"
            "Be concise and structured. Do not continue the source code.\n"
            "Required fields: "
            "{\"has_vulnerability\": true/false, \"vulnerability_type\": \"...\", "
            "\"severity\": \"...\", \"evidence\": [], \"explanation\": \"...\", "
            "\"fix_principle\": \"...\", \"confidence\": 0.0, \"fix_choice\": \"...\"}.\n\n"
            f"Original task:\n{question}\n\n"
            "Previous model response to audit:\n"
            f"{bounded_response}"
        )
        effective_system_prompt = system_prompt or self.config.verifier_system_prompt or (
            "You are a defensive secure-code verifier. Return JSON only."
        )
        result = self._generate(
            verifier_prompt,
            effective_system_prompt,
            self.config.verifier_max_new_tokens,
            response_prefix=self._response_prefix_for_prompt(verifier_prompt, self.config.verifier_response_prefix),
        )
        payload = extract_json_object(result)
        if payload:
            return result
        return result


def build_backend(raw_config: dict[str, Any]) -> InferenceBackend:
    config = BackendConfig(**raw_config)
    if config.type == "mock":
        return MockInferenceBackend(config)
    if config.type == "huggingface":
        return HuggingFaceInferenceBackend(config)
    raise ValueError(f"Unsupported backend type: {config.type}")


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


def run_generation(backend: InferenceBackend, sample: SecureCodeSample) -> SecureCodeGenerationRecord:
    task_system_prompt = backend.config.system_prompt or system_prompt_for_task(sample.task_type)
    start = time.perf_counter()
    text = backend.generate_text(sample.prompt, system_prompt=task_system_prompt)
    latency_ms = (time.perf_counter() - start) * 1000
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
                if (
                    not verifier_hard_fail
                    and _coerce_verifier_override(verifier_payload)
                ):
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
