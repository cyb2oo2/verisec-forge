> 已停用（2026-09-09）：用户决定以 [AI 标注流程](P1_AI_ANNOTATION_TEMPLATE.md) 替代人工盲审。以下仅为历史交接记录，不再要求指定 R1/R2/R3。

# P1 人工盲审交接

当前批次：`binding_semantics_p1_v2`，36 对，三个来源各 12 对。v1 是筛选审计材料，不再分配给审查者。当前人员尚待指定，以下是分工，不代表已联系或已有人开始审查。

| 角色 | 收到的材料 | 任务 |
| --- | --- | --- |
| R1 独立审查者 | 本说明、`review_r1.json` | 独立完成 36 对 |
| R2 独立审查者 | 本说明、`review_r2.json` | 独立完成 36 对；提交前不与 R1 讨论 |
| R3 裁决者 | R1、R2 均提交后，接收冲突案例和各自理由 | 记录裁决及依据，保留两份原始判断 |

本地材料目录：`data/annotation/binding_semantics_p1_v2/`。只把对应 review 文件交给相应审查者；不共享整个目录。其中 PRIVATE 文件、模型提示包、来源追溯记录及基准答案不发给独立审查者。两个包的顺序和 A/B 方向不同，不能按行号或字母直接比较。

每例完整代码在 `candidate_A`、`candidate_B`。不得修改 case_id 和候选代码。填写：

- `vulnerable_side`：A、B、neither、unclear。
- `context_sufficient`：yes、no、unclear；缺少调用约定、外部定义等应明确说明。
- `root_cause`：安全问题的具体原因；不能确认时写明原因，不猜基准答案。
- `minimal_evidence_lines`：从各候选第一行开始计数，以 `A:3-8; B:4-9` 等形式标明，并解释必要上下文。
- `reviewer_identity`、`reviewed_at`：真实审查者姓名/代号与实际完成时间。

不得用 AI 生成的标签代填人工判断。可以记录“无法判断”，这不算失败。初轮只依据给出的代码审查；不搜索来源或查基准答案。若必须查外部上下文，在初轮提交后单独进入裁决阶段，并记录解除盲法的情况。代码注释本身可能泄露来源，材料隐去元数据不等于完全盲法。

两份包完成后，先核对候选哈希与身份，再按 PRIVATE_provenance 中的方向映射比较判断。侧别或上下文充分性分歧交 R3；不得用 benchmark 标签自动裁决。当前尚未实现自动裁决导入，执行时须保留原始提交副本，不能覆盖初始记录。

```powershell
.venv/Scripts/python.exe scripts/check_p1_review_bundle.py
```

此命令检查材料完整性、已填字段和词法近重复筛查。`PASS_FOR_HUMAN_REVIEW` 仅表示材料可交付，既不证明人工标注完成，也不授权模型运行。最终实验冻结还需要审查裁决、分类输出协议和检查点历史缺口说明。
