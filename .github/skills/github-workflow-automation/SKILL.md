---
name: github-workflow-automation
description: >-
  Author, debug, and optimize GitHub Actions for a research repo without
  breaking the deliberate CI boundary (no training / no GPU / smoke only). Use
  when a workflow fails, is slow, needs caching, or a new job is proposed.
  Triggers: GitHub Actions, workflow, CI, YAML, runner, matrix, cache, job
  failing, pipeline, pytest in CI, secrets, permissions.
---

# GitHub Workflow Automation

Keep CI fast, green, and **inside the project's intentional boundary**: CI does
not train models, run GPU inference, or turn the 30-pair external smoke into a
benchmark (`docs/CI_TESTING_STRATEGY.md`). Automation serves reproducibility
checks, not heavy compute.

## When to Use

- A workflow in `.github/workflows/` is failing, flaky, or slow.
- Adding a job (docs build, AI review, extra smoke) or a matrix leg.
- Adding dependency caching, concurrency control, or path filters.
- Reviewing permissions/secrets on a workflow.

## Instructions

### 1. Know the existing contract first
- `ci.yml` runs `research-smoke` on ubuntu + windows: install `.[dev]`, whitespace
  check, five focused smoke tests, and a reproducibility-manifest `--check-only`.
  New workflows must not silently expand this into training/GPU work.

### 2. Debug a failure methodically
- Reproduce locally with the **exact** command from the workflow before touching
  YAML. Most failures are environment/order, not the runner.
- Read the failing step's log top-to-bottom; check the OS leg (Windows vs Linux
  path separators, shell defaults) — this repo runs both.
- Confirm optional extras: smoke jobs use `.[dev]` only; anything needing
  `.[train]`/`.[serve]` should not be in the fresh-clone smoke path.

### 3. Optimize deliberately
- Add `actions/setup-python` caching or `actions/cache` keyed on
  `pyproject.toml`. Add `concurrency` to cancel superseded PR runs. Use `paths:`
  filters so a docs-only change doesn't run the full matrix.
- Prefer `fail-fast: false` for cross-OS matrices so one leg's failure still
  surfaces the other's result (matches existing `ci.yml`).

### 4. Security hygiene
- Least-privilege `permissions:` per workflow. Never echo secrets. Pin actions to
  a major version (`@v4`) consistent with the repo. Untrusted PR code must not
  get write tokens or secret access (use `pull_request`, not
  `pull_request_target`, for code review jobs).

### 5. Keep YAML reviewable
- One job = one clear purpose. Name steps. Use `>-` folded blocks for long
  commands, mirroring `ci.yml`'s style.

## Best Practices & Guardrails

- **Do** reproduce locally before editing YAML.
- **Do** keep training/GPU out of CI; smoke and checks only.
- **Do** scope `permissions:` to the minimum per workflow.
- **Don't** use `pull_request_target` with untrusted checkout + secrets.
- **Don't** add a job that makes the fresh-clone smoke depend on `.[train]`.

## Examples

**Add caching + concurrency to a Python job**
```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
jobs:
  smoke:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip
      - run: python -m pip install -e ".[dev]"
```

**Path filter so docs changes skip the heavy matrix**
```yaml
on:
  pull_request:
    paths-ignore: ["**/*.md", "docs/**", "paper/**"]
```

## Dependencies / Tools

- GitHub Actions; `actions/checkout@v4`, `actions/setup-python@v5`, `actions/cache`
- `gh` CLI for inspecting runs locally
- `docs/CI_TESTING_STRATEGY.md` (the authoritative CI boundary)
- Related skills: [[reproducibility-check]], [[code-review-scientific]]
