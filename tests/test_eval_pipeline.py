from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from vrf.analysis import build_failure_analysis
from vrf.evaluation import evaluate_run
from vrf.inference import (
    BackendConfig,
    HuggingFaceInferenceBackend,
    InferenceBackend,
    compress_secure_code_prompt,
    run_generation,
)
from vrf.pipelines import run_baseline
from vrf.schemas import SecureCodeSample
from vrf.text_utils import (
    family_root_label,
    parse_security_structured_response,
    security_family_label_correct,
    security_label_correct,
    security_presence_correct,
)


def test_secure_baseline_eval_and_analysis() -> None:
    tmp_path = Path(".tmp_test_runs") / f"run-{uuid4().hex}"
    tmp_path.mkdir(parents=True, exist_ok=True)
    baseline_config = {
        "dataset_path": "data/processed/eval_secure_code_sample.jsonl",
        "output_path": str(tmp_path / "baseline_generations.jsonl"),
        "tracker_path": str(tmp_path / "experiments.jsonl"),
        "backend": {
            "type": "mock",
            "model_name": "mock-test",
            "temperature": 0.0,
            "max_new_tokens": 128,
        },
    }
    baseline_config_path = tmp_path / "baseline.json"
    baseline_config_path.write_text(json.dumps(baseline_config), encoding="utf-8")

    eval_config = {
        "dataset_path": "data/processed/eval_secure_code_sample.jsonl",
        "generations_path": baseline_config["output_path"],
        "report_json_path": str(tmp_path / "eval_report.json"),
        "report_csv_path": str(tmp_path / "eval_report.csv"),
        "tracker_path": str(tmp_path / "experiments.jsonl"),
    }
    analysis_config = {
        "dataset_path": "data/processed/eval_secure_code_sample.jsonl",
        "generations_path": baseline_config["output_path"],
        "analysis_output_path": str(tmp_path / "analysis.json"),
    }

    baseline_metrics = run_baseline(str(baseline_config_path))
    report = evaluate_run(eval_config, "tmp_eval.json")
    analysis = build_failure_analysis(analysis_config)

    assert baseline_metrics["num_examples"] == 3
    assert report["summary"]["label_accuracy"] >= 0.6
    assert "failure_buckets" in analysis


def test_parse_security_structured_response_accepts_aliases_and_string_evidence() -> None:
    text = (
        '{"has_vulnerability": true, "vuln_type": "shell_exec", "severity": "high", '
        '"evidence": "uses os.system on untrusted input", "explanation": "unsafe execution"}'
    )
    payload, ok, parse_style = parse_security_structured_response(text)
    assert ok is True
    assert payload["vulnerability_type"] == "shell-exec"
    assert isinstance(payload["evidence"], list)
    assert payload["evidence"][0]["snippet"] == "uses os.system on untrusted input"
    assert parse_style == "structured_json"


def test_security_label_correct_accepts_equivalent_cwe_family() -> None:
    assert security_label_correct(True, "buffer-overflow", True, "cwe-787") is True
    assert security_label_correct(True, "cwe-120", True, "cwe-787") is True


def test_security_label_correct_keeps_safe_examples_simple() -> None:
    assert security_label_correct(False, "cwe-78", False, "none") is True
    assert security_label_correct(True, "cwe-78", False, "none") is False


def test_security_presence_and_family_label_metrics_cover_coarser_success() -> None:
    assert security_presence_correct(True, True) is True
    assert security_presence_correct(False, True) is False
    assert family_root_label("cwe-125") == "cwe-119"
    assert security_family_label_correct(True, "cwe-119", True, "cwe-125") is True
    assert security_family_label_correct(True, "cwe-264", True, "cwe-284") is True


def test_parse_security_structured_response_uses_first_json_object() -> None:
    text = (
        '{"has_vulnerability": true, "vulnerability_type": "cwe-89", "severity": "high", '
        '"evidence": [], "explanation": "sql injection"}'
        ', {"has_vulnerability": false}'
    )
    payload, ok, _ = parse_security_structured_response(text)
    assert ok is True
    assert payload["has_vulnerability"] is True
    assert payload["vulnerability_type"] == "cwe-89"


def test_parse_security_structured_response_accepts_kv_blocks() -> None:
    text = (
        "has_vulnerability: true\n"
        "vulnerability_type: cwe-78\n"
        "severity: high\n"
        "evidence:\n"
        "- os.system(user_input)\n"
        "explanation: User input reaches a command execution sink.\n"
        "fix_principle: Avoid executing untrusted input directly.\n"
        "confidence: 0.82\n"
    )
    payload, ok, parse_style = parse_security_structured_response(text)
    assert ok is True
    assert parse_style == "structured_kv"
    assert payload["has_vulnerability"] is True
    assert payload["vulnerability_type"] == "cwe-78"
    assert payload["confidence"] == 0.82
    assert payload["evidence"][0]["snippet"] == "os.system(user_input)"


def test_parse_security_structured_response_accepts_jsonish_objects() -> None:
    text = (
        "{has_vulnerability: false, vulnerability_type: 'cwe-78', severity: 'none', "
        "evidence: [], explanation: \"No clear security weakness is evident from the provided snippet alone.\", "
        "fix_principle: 'Preserve safe coding practices and input validation.', confidence: 0.75, and fix_choice: \"\"}"
    )
    payload, ok, parse_style = parse_security_structured_response(text)
    assert ok is True
    assert parse_style == "structured_json"
    assert payload["has_vulnerability"] is False
    assert payload["vulnerability_type"] == "cwe-78"
    assert payload["confidence"] == 0.75


def test_parse_security_structured_response_accepts_pair_blocks() -> None:
    text = (
        '{{"has_vulnerability", false}, {"vulnerability_type", "cwe-259"}, {"severity", "none"}, '
        '{"explaination", "No clear security weakness is evident from the snippet alone."}, '
        '{"fix_principle", "preserve_safe_defaults"}, '
        '{"confidence", 0.75}, {"fix_choice", null}}'
    )
    payload, ok, parse_style = parse_security_structured_response(text)
    assert ok is True
    assert parse_style == "structured_pairs"
    assert payload["has_vulnerability"] is False
    assert payload["vulnerability_type"] == "cwe-259"
    assert payload["confidence"] == 0.75


def test_run_generation_second_pass_rescues_secure_output() -> None:
    class FallbackBackend(InferenceBackend):
        def generate_text(self, prompt: str, system_prompt: str | None = None) -> str:
            return "analysis: likely command execution risk"

        def extract_answer_text(
            self,
            question: str,
            model_response: str,
            system_prompt: str | None = None,
        ) -> str | None:
            return (
                '{"has_vulnerability": true, "vulnerability_type": "cwe-78", "severity": "high", '
                '"evidence": [], "explanation": "user input reaches execution sink", '
                '"fix_principle": "avoid direct execution", "confidence": 0.91, "fix_choice": ""}'
            )

    backend = FallbackBackend(BackendConfig(type="mock", model_name="fallback-test", enable_second_pass=True))
    sample = SecureCodeSample(
        id="sec-x",
        task_type="weakness_identification",
        language="python",
        prompt="Analyze code",
        code="os.system(cmd)",
        has_vulnerability=True,
        vulnerability_type="cwe-78",
    )
    generation = run_generation(backend, sample)
    assert generation.parse_method == "second_pass_model"
    assert generation.format_ok is True
    assert generation.predicted_vulnerability_type == "cwe-78"


def test_run_generation_safe_verifier_can_flip_low_confidence_safe_prediction() -> None:
    class VerifierBackend(InferenceBackend):
        def generate_text(self, prompt: str, system_prompt: str | None = None) -> str:
            return (
                '{"has_vulnerability": false, "vulnerability_type": "none", "severity": "none", '
                '"evidence": [], "explanation": "No clear security weakness is evident from the provided snippet alone.", '
                '"fix_principle": "Preserve safe coding practices.", "confidence": 0.75, "fix_choice": ""}'
            )

        def verify_safe_prediction_text(
            self,
            question: str,
            model_response: str,
            system_prompt: str | None = None,
        ) -> str | None:
            return (
                '{"has_vulnerability": true, "vulnerability_type": "cwe-78", "severity": "high", '
                '"evidence": [], "explanation": "User input appears to reach a command execution sink.", '
                '"fix_principle": "Avoid direct execution of untrusted input.", "confidence": 0.9, "fix_choice": ""}'
            )

    backend = VerifierBackend(
        BackendConfig(
            type="mock",
            model_name="verifier-test",
            enable_safe_verifier=True,
            safe_verifier_confidence_threshold=0.8,
            safe_verifier_parse_threshold=0.9,
        )
    )
    sample = SecureCodeSample(
        id="sec-verifier",
        task_type="weakness_identification",
        language="python",
        prompt="Analyze code",
        code="os.system(cmd)",
        has_vulnerability=True,
        vulnerability_type="cwe-78",
    )
    generation = run_generation(backend, sample)
    assert generation.verifier_used is True
    assert generation.verifier_overrode is True
    assert generation.parse_method == "safe_verifier"
    assert generation.has_vulnerability is True
    assert generation.predicted_vulnerability_type == "cwe-78"


def test_compress_secure_code_prompt_keeps_focus_and_instruction() -> None:
    prompt = (
        "Analyze the following python code for defensive security issues and return JSON only.\n\n"
        "code:\n"
        + "\n".join([f"line {idx}" for idx in range(120)])
        + "\nos.system(user_input)\n"
        + "\n".join([f"tail {idx}" for idx in range(120)])
    )
    compressed = compress_secure_code_prompt(prompt, 1200)
    assert "Candidate security hotspots:" in compressed
    assert "os.system(user_input)" in compressed
    assert "Hotspot 1" in compressed or "Window 1" in compressed
    assert "File prologue:" in compressed
    assert "BEGIN CODE SNIPPET" in compressed
    assert "END CODE SNIPPET" in compressed
    assert "not a code completion model" in compressed
    assert len(compressed) <= 1200


def test_long_code_prompt_disables_forced_response_prefix() -> None:
    backend = object.__new__(HuggingFaceInferenceBackend)
    backend.config = BackendConfig(type="huggingface", model_name="stub", response_prefix="{")
    short_prompt = "Analyze this code:\n\ncode:\nprint('ok')"
    long_prompt = "Analyze this code:\n\ncode:\n" + ("line\n" * 5000)

    assert backend._response_prefix_for_prompt(short_prompt, "{") == "{"
    assert backend._response_prefix_for_prompt(long_prompt, "{") is None
