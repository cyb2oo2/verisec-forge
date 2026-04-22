from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vrf.generation import build_generation_record_from_text
from vrf.prompting import compress_secure_code_prompt, truncate_text_block
from vrf.schemas import SecureCodeGenerationRecord, SecureCodeSample
from vrf.task_profiles import system_prompt_for_task
from vrf.text_utils import (
    extract_json_object,
)

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

    def generate_text_batch(
        self,
        prompts: list[str],
        system_prompts: list[str | None] | None = None,
    ) -> list[str]:
        outputs: list[str] = []
        for idx, prompt in enumerate(prompts):
            system_prompt = None if system_prompts is None else system_prompts[idx]
            outputs.append(self.generate_text(prompt, system_prompt=system_prompt))
        return outputs

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
            from huggingface_hub import snapshot_download
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
        model_source = config.model_name
        if config.local_files_only:
            pretrained_kwargs["local_files_only"] = True
            model_path = Path(config.model_name)
            if not model_path.exists():
                try:
                    model_source = snapshot_download(config.model_name, local_files_only=True)
                except Exception:
                    model_source = config.model_name
        try:
            self._tokenizer = AutoTokenizer.from_pretrained(model_source, **pretrained_kwargs)
        except ValueError:
            self._tokenizer = AutoTokenizer.from_pretrained(
                model_source,
                use_fast=False,
                **pretrained_kwargs,
            )
        adapter_config_path = Path(config.model_name) / "adapter_config.json"
        if adapter_config_path.exists():
            self._model = AutoPeftModelForCausalLM.from_pretrained(config.model_name, **model_kwargs, **pretrained_kwargs)
            self._model = self._model.merge_and_unload()
        else:
            self._model = AutoModelForCausalLM.from_pretrained(model_source, **model_kwargs, **pretrained_kwargs)
        if self._tokenizer.pad_token is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token
        self._tokenizer.padding_side = "left"

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

    def _generate_batch(
        self,
        prompts: list[str],
        system_prompts: list[str | None],
        max_new_tokens: int,
        response_prefixes: list[str | None] | None = None,
    ) -> list[str]:
        rendered_prompts: list[str] = []
        for idx, prompt in enumerate(prompts):
            rendered = self._render_prompt(prompt, system_prompts[idx])
            response_prefix = None if response_prefixes is None else response_prefixes[idx]
            if response_prefix:
                rendered = rendered.rstrip() + "\n" + response_prefix
            rendered_prompts.append(rendered)

        tokenizer_kwargs: dict[str, Any] = {"return_tensors": "pt", "padding": True}
        if self.config.max_input_tokens:
            tokenizer_kwargs["truncation"] = True
            tokenizer_kwargs["max_length"] = self.config.max_input_tokens
        encoded = self._tokenizer(rendered_prompts, **tokenizer_kwargs)
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

        output_tokens = self._model.generate(**encoded, **generate_kwargs)
        input_lengths = encoded["attention_mask"].sum(dim=1).tolist()

        outputs: list[str] = []
        for idx, input_length in enumerate(input_lengths):
            generated_only = output_tokens[idx][input_length:]
            decoded = self._tokenizer.decode(generated_only, skip_special_tokens=True).strip()
            response_prefix = None if response_prefixes is None else response_prefixes[idx]
            outputs.append((response_prefix + decoded) if response_prefix else decoded)
        return outputs

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

    def generate_text_batch(
        self,
        prompts: list[str],
        system_prompts: list[str | None] | None = None,
    ) -> list[str]:
        effective_system_prompts = [
            (system_prompts[idx] if system_prompts is not None else None) or self.config.system_prompt
            for idx in range(len(prompts))
        ]
        response_prefixes = [
            self._response_prefix_for_prompt(prompt, self.config.response_prefix)
            if self.config.output_format == "structured_json"
            else None
            for prompt in prompts
        ]
        return self._generate_batch(
            prompts,
            effective_system_prompts,
            self.config.max_new_tokens,
            response_prefixes=response_prefixes,
        )

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


def run_generation(backend: InferenceBackend, sample: SecureCodeSample) -> SecureCodeGenerationRecord:
    task_system_prompt = backend.config.system_prompt or system_prompt_for_task(sample.task_type)
    start = time.perf_counter()
    text = backend.generate_text(sample.prompt, system_prompt=task_system_prompt)
    latency_ms = (time.perf_counter() - start) * 1000
    return build_generation_record_from_text(backend, sample, text, latency_ms=latency_ms)


def run_generation_batch(
    backend: InferenceBackend,
    samples: list[SecureCodeSample],
) -> list[SecureCodeGenerationRecord]:
    if not samples:
        return []
    system_prompts = [backend.config.system_prompt or system_prompt_for_task(sample.task_type) for sample in samples]
    start = time.perf_counter()
    texts = backend.generate_text_batch([sample.prompt for sample in samples], system_prompts=system_prompts)
    batch_latency_ms = (time.perf_counter() - start) * 1000
    per_sample_latency_ms = batch_latency_ms / max(1, len(samples))
    return [
        build_generation_record_from_text(
            backend,
            sample,
            text,
            latency_ms=per_sample_latency_ms,
        )
        for sample, text in zip(samples, texts, strict=True)
    ]
