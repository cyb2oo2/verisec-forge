> 当前入口已切换至 [源码修复 v3](P1_SOURCE_REPAIR.md)。以下 v1/v2 设计保留作历史记录，旧 12-cell 接收器和标签不得套用到 v3。

> 当前决策：288 道标签题可由标题正则全部解出，因此该对照只做接口检查。三来源能力差距分析暂停，先修复源码完整性和函数配对；已完成 36 对 AI 探索性诊断，详见 [当前报告](../reports/scientific_review_2026_09_07/REVIEW.md)。此前的主终点与人工要求仅作历史计划。

> 2026-09-09 修订：按用户决定取消人工标注与裁决门槛，改用 [AI 标注模板 v1](P1_AI_ANNOTATION_TEMPLATE.md)。下文涉及人工流程的要求已被此修订替代；来源、输入可见性和模型运行协议要求仍有效。最终标签为 AI 暂定标签，不能作为 human gold。默认一轮 36 个独立上下文；未决样本保留，暂定 A/B 子集规则见模板。

# P1: candidate binding and security judgment

Status: design v1; candidate preparation only, **not a frozen confirmatory experiment**.
Current findings remain in the [scientific review](../reports/scientific_review_2026_09_07/REVIEW.md).

## Question and interpretation

Can a model correctly map an explicitly named neutral tag to a displayed candidate,
while failing to identify the more vulnerable code? Tag lookup is a deliberately
simple positive control for instruction following and response-side binding. It
does not match the difficulty of security judgment and does not by itself measure
code identity tracking. A performance difference cannot establish a causal internal
mechanism, prove semantic blindness, or attribute a deficit to one processing stage.

Use complete candidate code, not split-view or truncated excerpts. The same code
body appears in all tasks. Cross code order (2) with tag assignment (2). For each
cell ask the security question and each of two neutral-tag questions: 12 prompts
per pair. Tags are reassigned independently of vulnerable identity. Benchmark
security labels are provisional until human review; binding labels are constructed.
Presentation variants are repeated measurements, not independent samples.

## Sample and exposure

Prepare at most 12 pairs per source from the three current local source pools.
Sort by SHA256 of `p1-v1::dataset::pair_key`, without reading model predictions.
Exclude the prior 600-pair audit, repository-basename aliases of its projects,
whitespace-normalized identical candidate code, empty/identical pairs and unknown
projects. Allow at most one pair per project across the selected sources. Report
shortfalls without relaxing rules or replacing pairs based on outcomes.

This establishes only conservative separation from that audit. It does not establish
training disjointness, pretraining disjointness, near-clone disjointness, or an unseen
source. Before any model execution, identify exact checkpoints and every known
training/validation/tuning input, resolve repository aliases, audit project and code
overlap, and document unknown exposure. A failed or unknown exposure check blocks
the independent-evaluation claim. This is a small diagnostic pilot, not a powered
confirmatory test or a source-generalization estimate.

## Human review and freeze gates

Give only `review_r1.json` and `review_r2.json` to two independent reviewers.
They contain randomized code orientation/order and blank fields. Do not distribute
PRIVATE keys/provenance or model predictions. Code itself may reveal provenance;
packet metadata masking does not guarantee perfect blinding. AI must not fill the
human fields. Reviewers judge vulnerability, context sufficiency, root cause and
minimal evidence lines using the existing human annotation protocol. Adjudicate
disagreements with a third reviewer; retain initial judgments and exclusions.

Before inference, freeze the eligible set, all exclusions, adjudicated gold,
checkpoint and tokenizer hashes, exact prompt bytes, decoding/parser settings,
and analysis implementation hashes in a dated manifest. Verify **all code and the
question** fit the exact input limit; no silent truncation or post-result filtering.
If a pair fails visibility, exclude all 12 prompts and report attrition by source.
No automatic substitutions. Human labels, runtime validation and model identity
are currently missing, so the builder deliberately reports NOT_FROZEN.

## Analysis contract for the pilot

Primary descriptive quantities: per-source mean pair-level security accuracy
(four cells per pair), binding accuracy (eight cells), and their paired difference.
Also report the equally weighted source mean; do not pool unequal source sizes
without labeling the weighting. Invalid/abstaining outputs count incorrect in the
full denominator; report forced-answer coverage separately. No repair projection
in the primary analysis. Secondary diagnostics: code-order consistency, security
invariance to tag reassignment, binding accuracy for each tag and position.

Use source-stratified pair-cluster bootstrap (2,000 iterations, fixed seed 42),
keeping all 12 cells together and recomputing both task means and the difference
in every draw. With at most 12 projects per source, intervals are exploratory and
may be unstable. No success threshold, significance-driven continuation, model
selection or sample-size adaptation based on these pilot outputs. A future
confirmatory study needs a separately justified sample size and untouched data.

## Local preparation

```powershell
.venv/Scripts/python.exe scripts/build_binding_semantics_p1.py
```

The builder writes an ignored local annotation bundle and a tracked preflight
summary. It refuses to overwrite an existing bundle to preserve human work.
It runs no model, downloads nothing and grants no inference authorization.
Construction checks certify factorial integrity, not human annotation completion
or scientific readiness.


## v2 selection amendment (before new predictions)

The v1 pool could not meet its quotas after known exposure and length filtering.
The v2 builder expands to local complete source pools, applies those exclusions
before selection, and retains 12 pairs per source. PrimeVul uses only unambiguous
two-row project/commit/CVE groups. No model outcomes were used to alter selection.
The original bundle remains intact. Known local input separation and lexical
clone screening passed; historical training attestation and foundation pretraining
exposure remain incomplete. Final sample freeze awaits human adjudication.

Use `scripts/trace_p1_lineage_and_select.py` for v2 construction (refuses overwrite)
and `scripts/check_p1_review_bundle.py` for integrity/readiness checks. Reviewer
assignments and procedures are in [the handoff](P1_BLIND_REVIEW_HANDOFF.md).
The chosen checkpoint family is SEQ_CLS, so the final model scoring contract must
explicitly address task transfer and A/B mapping before inference; a positive
control failure cannot be interpreted as a security-specific deficit.
