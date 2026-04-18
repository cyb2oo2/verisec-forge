# VeriSec Forge

VeriSec Forge is a reproducible research system for structured secure-code reasoning, post-training, and auto-benchmarking. The project focuses on defensive analysis rather than exploit generation: given code, the model must decide whether a security weakness is present, assign a structured vulnerability label, explain the judgment, and stay inside a machine-checkable output contract.

The repo is built around a tight benchmark-and-training loop:

- real secure-code benchmark data
- JSON-first generation and parser-aware recovery
- automated evaluation and failure taxonomy
- `Base -> SFT -> DPO` style post-training
- reportable, reproducible experiment artifacts

## One-line project goal

Train and evaluate open-weight models to produce trustworthy, structured secure-code judgments, while separating true reasoning failure from parser noise, explanation drift, and calibration mistakes.

## Current scope

- Domain: defensive secure-code reasoning
- Primary task: weakness identification on code snippets
- Secondary task: secure fix ranking
- Deployment target: local or single-node API serving
- Training budget: single consumer GPU with PEFT-first recipes
- Product shape: research benchmark plus post-training platform, not a general assistant

## Research questions

1. Can structured post-training improve secure-code reasoning correctness and stability?
2. Are model explanations actually supported by code evidence?
3. How much apparent benchmark failure is caused by formatting and parsing noise rather than true semantic failure?
4. Do larger zero-shot models become more trustworthy, or just more security-fluent?

## Core output contract

The primary secure-code task returns structured JSON shaped like:

```json
{
  "has_vulnerability": true,
  "vulnerability_type": "cwe-79",
  "severity": "medium",
  "evidence": [
    {
      "file_path": "src/app.py",
      "line_start": 18,
      "line_end": 20,
      "snippet": "render(user_input)"
    }
  ],
  "explanation": "Unsanitized user-controlled data reaches an HTML sink.",
  "fix_principle": "Validate and encode untrusted input before rendering.",
  "confidence": 0.82,
  "fix_choice": ""
}
```

In practice, the stack also supports tolerant parsing and second-pass recovery for JSON-like outputs so we can measure model reasoning separately from protocol breakage.

## What is implemented

- Unified schemas for secure-code samples, structured generations, eval rows, and experiment tracking
- JSON-first prompting, schema-first parsing, tolerant parsing, and second-pass extraction
- CLI baseline runner and FastAPI serving entrypoints
- Secure-code evaluator with metrics for:
  - `label_accuracy`
  - `format_pass_rate`
  - `invalid_output_rate`
  - `high_confidence_error_rate`
  - `evidence_support_rate`
  - `explanation_support_rate`
- Failure analysis that separates:
  - `label_failure`
  - `format_failure`
  - `evidence_failure`
  - `explanation_failure`
  - `high_confidence_error`
- SFT and DPO training entrypoints for secure-code tasks
- Real benchmark artifacts, reports, and analysis summaries

## Real benchmark status

The main current benchmark is a balanced `PrimeVul eval244` split with:

- `122 vulnerable`
- `122 safe`

This is the current anchor benchmark for model comparison and failure analysis.

## Current best result

The strongest model in the repo right now is:

- `Qwen2.5-0.5B-Instruct`
- balanced `PrimeVul` SFT
- completion-only loss
- tolerant parser

Checkpoint:
- [checkpoints/sft_secure_code_primevul_qwen05b_balanced_lossfix](D:/code/start/checkpoints/sft_secure_code_primevul_qwen05b_balanced_lossfix)

On balanced `PrimeVul eval244`, it currently reaches:

- `label_accuracy = 0.4795`
- `format_pass_rate = 0.8279`
- `invalid_output_rate = 0.1598`
- `high_confidence_error_rate = 0.0287`

This is currently stronger and more trustworthy than every DPO variant explored so far.

## Current comparison snapshot

| Model | Label Accuracy | Format Pass Rate | Invalid Output Rate | High-Confidence Error Rate | Avg Tokens |
| --- | ---: | ---: | ---: | ---: | ---: |
| Base 0.5B | 0.4098 | 0.5410 | 0.2131 | 0.1639 | 41.8443 |
| SFT 0.5B | 0.4795 | 0.8279 | 0.1598 | 0.0287 | 35.9918 |
| Base 1.5B | 0.0697 | 0.8484 | 0.1311 | 0.1066 | 95.4426 |
| Hard DPO v2 | 0.2090 | 0.3033 | 0.6926 | 0.0205 | 57.6475 |
| Calibrated LoRA-only DPO v1 | 0.3648 | 0.6598 | 0.2910 | 0.0082 | 34.6475 |
| Label-focused LoRA-only DPO v1 | 0.2418 | 0.4549 | 0.2541 | 0.0738 | 30.0738 |

Key readout:

- `SFT 0.5B` is the current best model.
- `Base 1.5B` is much more security-fluent in tone, but badly over-detects vulnerabilities.
- The DPO runs explored so far do not beat the SFT anchor and often destabilize the output protocol.

See:
- [reports/SECURE_CODE_RESEARCH_SUMMARY.md](D:/code/start/reports/SECURE_CODE_RESEARCH_SUMMARY.md)
- [reports/TECHNICAL_REPORT.md](D:/code/start/reports/TECHNICAL_REPORT.md)
- [reports/training_comparison.md](D:/code/start/reports/training_comparison.md)

## Repo layout

- [src/vrf](D:/code/start/src/vrf): core inference, parsing, evaluation, analysis, training, and serving code
- [configs](D:/code/start/configs): runnable experiment configs
- [data/processed](D:/code/start/data/processed): normalized benchmark slices and training datasets
- [checkpoints](D:/code/start/checkpoints): trained adapters and model artifacts
- [reports](D:/code/start/reports): experiment summaries and research notes
- [analysis](D:/code/start/analysis): failure-analysis outputs
- [scripts](D:/code/start/scripts): data preparation and reporting utilities

## What gets versioned

The GitHub-ready repo is intended to track:

- source code
- configs
- small benchmark slices
- research reports

Large raw datasets, derived training corpora, outputs, and checkpoints are kept
out of version control by default. See [data/README.md](D:/code/start/data/README.md).

## Quick start

### 1. Install

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
```

### 2. Run a mock secure-code baseline

```powershell
vrf baseline --config configs\baseline_secure_code_mock.json
vrf evaluate --config configs\eval_secure_code_mock.json
vrf analyze --config configs\analysis_secure_code_mock.json
```

### 3. Run the real PrimeVul 0.5B baseline on eval244

```powershell
vrf baseline --config configs\baseline_secure_code_primevul_qwen05b_eval244.json
vrf evaluate --config configs\eval_secure_code_primevul_qwen05b_eval244.json
vrf analyze --config configs\analysis_secure_code_primevul_qwen05b_eval244.json
```

### 4. Run the current best SFT checkpoint on eval244

```powershell
vrf baseline --config configs\baseline_sft_secure_code_primevul_qwen05b_balanced_lossfix_eval244.json
vrf evaluate --config configs\eval_sft_secure_code_primevul_qwen05b_balanced_lossfix_eval244.json
vrf analyze --config configs\analysis_sft_secure_code_primevul_qwen05b_balanced_lossfix_eval244.json
```

## Training entrypoints

Representative training configs:

- SFT:
  - [configs/sft_secure_code_primevul_qwen05b_balanced_lossfix.json](D:/code/start/configs/sft_secure_code_primevul_qwen05b_balanced_lossfix.json)
- DPO:
  - [configs/dpo_secure_code_primevul_qwen05b_calibrated_lora_v1.json](D:/code/start/configs/dpo_secure_code_primevul_qwen05b_calibrated_lora_v1.json)
  - [configs/dpo_secure_code_primevul_qwen05b_label_focused_lora_v1.json](D:/code/start/configs/dpo_secure_code_primevul_qwen05b_label_focused_lora_v1.json)

## Environment notes

- The repo currently runs on Windows with CLI, FastAPI, Hugging Face, and TRL-based training entrypoints.
- `vLLM` is still the preferred Linux GPU serving path, but the active local workflow uses the FastAPI plus Hugging Face route.
- The secure-code benchmark and report pipeline is fully local once the datasets are downloaded and normalized.
