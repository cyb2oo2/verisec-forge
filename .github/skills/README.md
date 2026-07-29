# Agent Skills Catalog

Version-controlled **agent skills** for VeriSec Forge research workflows.
Each subdirectory is one skill. Agents (GitHub Copilot, Claude Code, Cursor,
and similar) should load the matching `SKILL.md` when the user task matches the
skill description / triggers.

Canonical guide: How to add skills: ## Layout

```text
.github/skills/
  <skill-name>/
    SKILL.md           # required: YAML frontmatter + instructions
    examples/          # optional
    references/        # optional
    templates/         # optional
```

## Required skills

| Skill | Description |
| --- | --- |
| [research-experiment-manager](research-experiment-manager/SKILL.md) | Experiments, seeds, registry, claim-bounded results |
| [scientific-paper-assistant](scientific-paper-assistant/SKILL.md) | Paper drafting with anchored, bounded claims |
| [data-processing-pipeline](data-processing-pipeline/SKILL.md) | Reproducible preprocessing and de-confounding |
| [model-training-workflow](model-training-workflow/SKILL.md) | Training, checkpoints, VRAM-safe evaluation |
| [visualization-and-plotting](visualization-and-plotting/SKILL.md) | Publication figures (CI, SVG, colorblind-safe) |
| [document-handling](document-handling/SKILL.md) | PDF / Word / Excel / LaTeX handling |
| [github-workflow-automation](github-workflow-automation/SKILL.md) | Actions authoring within the smoke-only CI boundary |
| [reproducibility-check](reproducibility-check/SKILL.md) | Manifests, seeds, fresh-clone verification |
| [literature-review-helper](literature-review-helper/SKILL.md) | Structured paper notes and honest positioning |
| [code-review-scientific](code-review-scientific/SKILL.md) | Scientific PR review (rigor, stats, claims) |

## Frontmatter contract

Every `SKILL.md` must start with:

```yaml
---
name: skill-directory-name
description: >-
  What it does and when to use it (include trigger keywords).
---
```

Required body sections (names may vary slightly but content must exist):

1. When to Use  
2. Instructions (step-by-step)  
3. Best Practices & Guardrails  
4. Examples  
5. Dependencies / Tools  

Catalog integrity is validated by `scripts/check_skill_catalog.py`.

## Discovery tips for agents

- Match user intent to `description` trigger keywords first.
- Prefer **one primary skill** per turn; chain skills for multi-phase work.
- Always re-check `docs/RESULT_STATUS_LEDGER.md` if the skill touches `src/`, `scripts/`, or research claims.
- Never let a skill override claim boundaries or the CI smoke contract.
