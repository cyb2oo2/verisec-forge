# Experiment Workflows

This document explains how to navigate and extend the main experiment flows in `VeriSec Forge`.

## Repository Philosophy

The repository supports two complementary styles of work:

- **benchmark-facing work**, where we evaluate or analyze an existing run
- **training-facing work**, where we produce a new checkpoint or experimental branch

To keep those flows manageable, the repo now prefers:

- shared run specs over ad hoc config triplets when possible
- manifest-driven summaries over hardcoded report lists
- shared training helpers over stage-specific tokenizer and prompt code

## Common Evaluation Flow

The default offline experiment loop looks like this:

1. `baseline`
2. `evaluate`
3. `analyze`

CLI examples:

```powershell
vrf baseline --config configs\baseline_secure_code_mock.json
vrf evaluate --config configs\eval_secure_code_mock.json
vrf analyze --config configs\analysis_secure_code_mock.json
```

Internally this maps to:

- [D:\code\start\src\vrf\pipelines.py](D:/code/start/src/vrf/pipelines.py)
- [D:\code\start\src\vrf\run_specs.py](D:/code/start/src/vrf/run_specs.py)

## Run-Spec Driven Config Materialization

When a benchmark line needs aligned evaluation and analysis configs, prefer a run-artifact spec instead of hand-maintaining separate payloads.

Use:

- [D:\code\start\src\vrf\run_specs.py](D:/code/start/src/vrf/run_specs.py)
- [D:\code\start\scripts\materialize_run_configs.py](D:/code/start/scripts/materialize_run_configs.py)

This helps reduce “config explosion” when new experiments are added.

## Summary and Results Navigation

Curated experiment summaries now use manifests and shared renderers:

- [D:\code\start\src\vrf\research_summary.py](D:/code/start/src/vrf/research_summary.py)
- [D:\code\start\configs\research_runs](D:/code/start/configs/research_runs)
- [D:\code\start\scripts\build_secure_code_research_summary.py](D:/code/start/scripts/build_secure_code_research_summary.py)

Results navigation now also has a dedicated index:

- [D:\code\start\configs\report_index.json](D:/code/start/configs/report_index.json)
- [D:\code\start\scripts\build_report_index.py](D:/code/start/scripts/build_report_index.py)
- [D:\code\start\reports\RESULTS_INDEX.md](D:/code/start/reports/RESULTS_INDEX.md)

## Training Workflow

The training entrypoints remain stage-specific:

- `train-sft`
- `train-dpo`
- `train-reward`
- `train-grpo`

But their common bootstrap logic now lives in:

- [D:\code\start\src\vrf\training_common.py](D:/code/start/src/vrf/training_common.py)

This shared layer is responsible for:

- loading configs and datasets
- local snapshot resolution
- tokenizer setup
- prompt rendering for instruction-style training
- tracker logging

That means new training stages should reuse `training_common.py` rather than reintroducing stage-local copies of the same setup logic.

## When Adding a New Benchmark Line

Recommended sequence:

1. Add or prepare data under [D:\code\start\data](D:/code/start/data)
2. Define baseline / checkpoint outputs
3. Materialize aligned eval and analysis configs with `run_specs.py`
4. Add the benchmark to curated summaries only after results stabilize
5. Add or update tests if you introduced new orchestration logic

## When Adding a New Report Script

Prefer this order:

1. Reuse an existing shared module if one exists
2. Add a manifest if the script is selecting among artifacts
3. Keep the script thin and push logic into `src/vrf`
4. Add a smoke or focused test in [D:\code\start\tests](D:/code/start/tests)

## Current Recommended Reading Order

For a new collaborator:

1. [D:\code\start\README.md](D:/code/start/README.md)
2. [D:\code\start\docs\ARCHITECTURE.md](D:/code/start/docs/ARCHITECTURE.md)
3. [D:\code\start\reports\RESULTS_INDEX.md](D:/code/start/reports/RESULTS_INDEX.md)
4. [D:\code\start\reports\SECURE_CODE_RESEARCH_SUMMARY.md](D:/code/start/reports/SECURE_CODE_RESEARCH_SUMMARY.md)
5. [D:\code\start\reports\TECHNICAL_REPORT.md](D:/code/start/reports/TECHNICAL_REPORT.md)

This order gives a fast path from “what is this repo?” to “how is it organized?” to “what are the current results?”.
