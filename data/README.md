# Data Layout

This repository is designed to publish code, configs, and key reports without
checking large raw datasets, processed training corpora, or model checkpoints
into GitHub.

## Not tracked by default

- `data/raw/`
- large normalized corpora in `data/processed/`
- derived training datasets for SFT / DPO / verifier runs

## Kept in-repo

The small benchmark slices below are intentionally left trackable so the repo
still includes compact evaluation fixtures:

- `data/processed/eval_secure_code_sample.jsonl`
- `data/processed/secure_code_primevul_eval_balanced_244.jsonl`
- `data/processed/secure_code_primevul_holdout_eval_balanced_1000.jsonl`

## Regeneration

Use the scripts in [scripts](D:/code/start/scripts) to recreate local data:

- `scripts/download_primevul.py`
- `scripts/prepare_primevul.py`
- `scripts/build_primevul_holdout_eval.py`
- `scripts/prepare_secure_code_sft.py`
- `scripts/prepare_secure_code_dpo.py`
- `scripts/build_failure_driven_verifier_sft.py`

The project documentation in [reports/TECHNICAL_REPORT.md](D:/code/start/reports/TECHNICAL_REPORT.md)
and [reports/SECURE_CODE_RESEARCH_SUMMARY.md](D:/code/start/reports/SECURE_CODE_RESEARCH_SUMMARY.md)
describes which datasets and benchmark slices were used for the reported
results.
