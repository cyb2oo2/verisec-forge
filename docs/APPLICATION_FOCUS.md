# Application Focus

> **CORRECTED — WITHDRAWN RESULTS.**
> This document previously presented PrimeVul detector results as evidence of learned
> secure-patch reasoning. That interpretation was withdrawn after adversarial
> structural-control analysis. Under the closed-world pair constraint the fine-tuned
> detector reaches balanced accuracy `0.8596`; a **semantics-free character-level diff
> structural control** reaches `0.8588` on the same evaluation population. The difference
> is `+0.0008`, with a pair-group clustered 95% CI spanning zero (`[-0.0202, +0.0222]`)
> and a non-significant group-level sign test (19 vs 18, `p=1.0`).
> **This experiment does not establish semantic secure-patch reasoning beyond diff structure.**
> Current status: [Result Status Ledger](RESULT_STATUS_LEDGER.md).

## What this project actually contributes

The project demonstrated that apparently strong vulnerability-detection performance can
collapse or be reproduced by structural shortcuts under stricter paired evaluation.
Adversarial controls showed that character-level diff structure nearly matched the
fine-tuned detector, preventing an unsupported semantic-learning claim.

Concretely:

- A same-source detector scoring `0.9524` falls to `0.4961` under paired evaluation.
- A semantics-free control reading only net added-minus-removed **characters** reaches
  `0.8627` unconstrained — above the fine-tuned detector's `0.8136` — and `0.8588` under
  the pair constraint against the detector's `0.8596`.
- The detector is `0.2584` accurate on rows where that control errs, i.e. below chance:
  it follows the structural shortcut into its errors rather than correcting them.
- Two circular evaluations were identified and withdrawn: an evidence metric whose target
  was derived from the decision it was meant to validate, and a human-confirmation step
  anchored to the pipeline's own proposals.

The contribution is the identification and measurement of shortcut-driven performance,
not a successful semantic vulnerability detector.



This repository has been pruned for a PhD application review standard comparable to top security and ML systems groups such as Stanford Security Lab, MIT CSAIL, Berkeley systems/AI groups, CMU CyLab, and UIUC security/ML groups. The bar is not "many experiments"; the bar is a coherent research question, strong controls, reproducible evidence, and honest limitations.

## Keep This Narrative

**One-line thesis:** secure-code models should be judged under paired vulnerable/fixed patch conditions, because single-row vulnerability detection can look strong while using dataset shortcuts.

The project should be presented through four claims:

1. Same-source vulnerability detection is artifact-sensitive, so paired controls are necessary.
2. Paired diff representation plus pair-coupled decoding gives a stronger and more faithful secure-patch reasoning system.
3. Source-aware expert routing improves external generalization, but only under a closed-world, bounded claim.
4. Evidence localization is valuable as decision-coupled audit and failure triage, not yet as human-gold explanation.

## Lead With These Results

| Result | Why It Matters |
| --- | --- |
| Same-source PrimeVul accuracy `0.9524` versus paired negative controls near chance | Shows why the benchmark problem is real rather than cosmetic. |
| ~~Diff-only paired training mean BA `0.8287`~~ **WITHDRAWN** | Matched by a semantics-free character-level diff control; no semantic advantage established. |
| ~~Pair-coupled five-split mean BA `0.8572`, delta `+0.0348`~~ **WITHDRAWN** | Constrained-vs-unconstrained comparison over overlapping splits; superseded. Corrected: `0.8596` vs control `0.8588`, difference `+0.0008`, CI `[-0.0202, +0.0222]`. Historical note: uses pair structure without gold labels. |
| Time/project/CVE/external dataset checks | Prevents the result from looking like one split overfit. |
| Learned closed-world router BA `0.8664` with claim-boundary stress tests | A compact source-specialization story with guardrails. |
| ~~Predicted-side evidence top-1 `0.6555`; side-correct `0.7610`, side-wrong `0.0632`~~ **WITHDRAWN (circular target)** | Historical note: Turns explanation quality into a measurable coupled failure mode. |

## What Not To Emphasize

Do not lead with old CodeXGLUE experiments, DPO/SFT sweeps, generic verifier attempts, or broad vulnerability-scanner framing. Those branches were useful exploration, but they dilute the application signal. They also invite the wrong review question: "Is this a product?" The stronger question is: "Does this applicant know how to turn an observed benchmark failure into a controlled research program?"

## Recommended Pitch Shape

Use this order in statements, emails, and interviews:

1. "I found that high secure-code detection accuracy can collapse under paired vulnerable/fixed evaluation."
2. "I built paired-diff controls to separate real patch reasoning from shortcut use."
3. "I improved the system with pair-coupled decoding and validated it across splits and external datasets."
4. ~~"I then connected decisions to evidence localization, showing how wrong side decisions poison explanations."~~ **WITHDRAWN — the metric was circular; do not use this line.**
5. "The next PhD step is learning contrastive patch representations and independently adjudicated evidence, not just scaling a detector."

## Strongest Fit

The project is strongest for groups interested in:

- AI for security and secure software engineering
- trustworthy ML evaluation
- benchmark design and shortcut diagnosis
- program repair / patch understanding
- ML systems for code intelligence
- evidence-aware model auditing

It is less ideal if framed as:

- a finished vulnerability scanner
- a leaderboard chase
- a generic LLM fine-tuning project
- a broad survey of secure-code datasets

## Next Research Step

The clean PhD continuation is to replace heuristic and shallow side-correction layers with a learned contrastive patch model:

- train on paired vulnerable/fixed diff windows
- evaluate side choice, evidence localization, and confidence jointly
- add independent human adjudication for evidence spans
- test open-set source shift separately from closed-world source routing

That direction grows directly out of the current evidence without overclaiming the artifact.
