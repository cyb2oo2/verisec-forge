# Project Charter

## Title

VeriSec Forge

## Subtitle

Verifiable Post-Training and Auto-Benchmarking for Secure Code Reasoning

## Mission

Build a reproducible, extensible, and deployable research system for defensive secure code reasoning. The system should turn a small open-weight model into a more reliable security analysis model through staged post-training, structured evaluation, benchmark curation, failure analysis, and API serving.

## Core questions

- Can structured post-training improve secure code reasoning quality and stability?
- Can the model localize evidence that truly supports its vulnerability judgment?
- Can we separate benchmark noise caused by parsing and formatting issues from real reasoning failure?

## v1 Scope

- Domain: secure code reasoning
- Task A: security weakness identification and evidence localization
- Task B: secure fix candidate ranking
- Model scale: `0.5B` to `1.5B` active focus, PEFT-first
- Training stages: baseline, SFT, DPO, reward modeling, mini-GRPO
- Outputs: offline metrics, failure reports, benchmark artifacts, and a callable API

## Current anchor benchmark

- Dataset: `PrimeVul`
- Current balanced evaluation slice: `eval244`
- Current strongest model: `0.5B + balanced PrimeVul + completion-only SFT + tolerant parser`

## Current working conclusions

- `completion-only` SFT is the strongest secure-code training recipe in the repo so far
- larger zero-shot secure-code models can sound more expert while being less calibrated
- current DPO variants do not yet beat the SFT anchor and can easily destabilize the output protocol

## Primary structured output

- `has_vulnerability`
- `vulnerability_type`
- `severity`
- `evidence`
- `explanation`
- `fix_principle`
- `confidence`

## Non-goals

- Offensive exploitation workflows
- General chat product
- Multimodal inputs in v1
- RAG
- Multi-agent orchestration
- Heavy frontend work
