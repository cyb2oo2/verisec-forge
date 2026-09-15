# P1 v3 源码修复与当前入口

当前状态：v3 标注后完成 context-v1 本地上下文补充。诊断账本现为 13 对暂定单侧（12 个案例簇）、2 对 both、17 对 unclear；主要诊断分母保持 32 对 / 27 个原始案例簇。不同条目的可见上下文不等，不能将账本覆盖数当作统一条件模型分数。原 v3 的 12/2/18 结果及字节保持不变。

## 已替换的构建规则

- PatchEval 不再 zip 两个函数列表。按文件路径、解析出的函数名和节点类型唯一匹配；匿名、歧义、跨文件和语法残缺条目隔离。函数改名/移动不会凭相似度自动匹配。新全量数据为 1,006 对，使用 `patcheval-v2-` ID，旧预测无法按旧 ID 加入。
- DeltaSecommits 不再通过分号/括号插入换行伪造完整代码；这还会改变字符串和注释。现有 C/C++ 快照经单函数检查仅 17 对通过，1,617 个快照被拒绝。拒绝包含残缺、多函数、歧义等情况，不意味着每个被拒样本都语法错误。
- 对已选 DeltaSecommits 案例，从 GitHub 固定提交及唯一父提交获取原始文件；基于提交补丁行号选取完整的同名改动函数。保留下载 URL、提交、文件哈希、函数内容及源行号。合并提交、无法唯一解析或缺失源码的案例隔离。

语法使用可选 `source-audit` 依赖。Tree-sitter 0.26.0 在本机大文件遍历时发生原生崩溃，已固定到验证通过的 0.25.2；语言包版本也已固定。用法依据 [官方 Python 接口](https://github.com/tree-sitter/py-tree-sitter)。解析通过不等于编译通过、函数对应关系的语义证明或漏洞标签正确。

## 当前候选与边界

原 36 案例中保留 27 个，得到 32 个函数对：PrimeVul 10、PatchEval 10、DeltaSecommits 12（来自 7 个案例）。另 9 个案例隔离，不补数。多函数来自同一案例时仍属同一统计簇；不得把 32 当作 32 个独立漏洞。

仅生成安全判断任务的 64 条双方向提示；14 条超过旧的 1,024-token 上限，最大 2,968。未截断，也未修改模型运行长度。4,096 的原始文本长度可容纳性不代表加入完整聊天模板与输出预算后一定可运行；必须按实际模型重新测量。

v3 中 before/after 表示来源顺序，不自动代表漏洞/安全；保留的 PrimeVul 输入仍是原 A/B 方向。32 条 AI 新标注请求随机化展示方向，私有映射记录原案例和函数单元。旧 AI 标签不转移，旧模型预测不复用。

恢复后的函数已与枚举的本地训练/验证和旧审查数据重新检查，无项目或词法近重复命中；预训练暴露仍未知。提交补丁可能省略部分文件或上下文，因此恢复的函数只是可核实的改动子集，不保证覆盖整个漏洞修复。

## 可复现命令

```powershell
.venv/Scripts/python.exe -m pip install -e ".[source-audit]"
.venv/Scripts/python.exe scripts/rebuild_p1_sources.py
.venv/Scripts/python.exe scripts/verify_p1_repaired_sources.py
.venv/Scripts/python.exe scripts/prepare_repaired_annotations.py
.venv/Scripts/python.exe scripts/build_p1_ai_annotation.py --source-cases data/annotation/p1_reannotation_inputs_v3/cases.json --output data/annotation/p1_ai_source_v3 --manifest reports/scientific_review_2026_09_07/p1/ai_source_v3_preparation.json
```

重建入口拒绝覆盖已有产物。已构建的工作区只需执行 verify。恢复使用本地数据集缓存，原始 Git 文件缺少缓存时做只读下载；不会下载模型或训练。新标注响应应使用：

```powershell
.venv/Scripts/python.exe scripts/validate_p1_ai_annotations.py --responses NEW_RESPONSES.jsonl --manifest reports/scientific_review_2026_09_07/p1/ai_source_v3_preparation.json
```

旧 `accept_p1_ai_run.py` 对应 v2 的 12-cell 标签方案，**不适用于 v3**，不能为使导入成功而改 ID。v3 先完成源码判定与新标注，再固定新的安全任务读出和分析方案；不恢复原标签查询能力差距主张。

## v3 标注接收与下一步

context-v1 已对原队列全部 18 对完成本地缓存可用性核查，其中 9 对（5 个案例）取得固定提交的部分辅助上下文，另 9 对在 v3 缓存中缺少固定版本完整文件引用，未重新标注。libming 一对据零位宽路径改为暂定 A；其他仍未决。libreport 的三函数联动说明刷新位置改变不能按局部增删直接判漏洞，尚未证明安全影响。

新证据包为 `data/annotation/p1_context_v1/packets.json`，每条绑定原始 A/B、上下文文件字节哈希、固定提交、方向和行号。`recover_p1_local_context.py --check` 可只读核验；`review_p1_local_context.py` 只序列化本助手判断，不调用外部模型。后续队列为 `context_v1_remaining_queue.json`，含 17 对 / 13 个案例，需要恢复未覆盖的固定版本文件、类型和依赖实现。保留上下文版本边界，不重写原标签。

实际判断记录在 `reports/scientific_review_2026_09_07/p1/assistant_annotation_decisions_source_v3.json`；结构化响应与真实执行说明位于 `data/annotation/p1_assistant_source_v3/`。精确服务模型版本不可取得，未伪造提供商调用日志。所有标签均是 AI 暂定判断，验证器只证明覆盖率、输入字节、方向及证据范围一致，不能证明漏洞判断正确。

`materialize_p1_assistant_annotations.py --source-v3` 只序列化助手已经写出的判断，不调用模型。新的 `accept_p1_repaired_annotations.py` 验证 v3 输入、来源顺序、原始判断与响应一致性，拒绝遗漏、重复、旧标签继承和方向漂移。`ai_source_v3_acceptance.json` 保留每条判断及来源簇；其中 before/after 仅表示来源字段顺序，不自动表示修改前后安全性。

`prepare_p1_context_queue.py` 将 18 个未决函数对归并为后续上下文恢复队列，优先读取对应版本的缓存完整文件、辅助函数和调用方。无法补齐仍保留 unclear；不通过基准标签或提交方向倒推答案，不要求人工盲审。补充上下文后的判断必须另建版本，不覆盖本轮记录。

以上三个产物生成命令均拒绝覆盖。已有结果可只读复查：

```powershell
.venv/Scripts/python.exe scripts/validate_p1_ai_annotations.py --responses data/annotation/p1_assistant_source_v3/responses.jsonl --manifest reports/scientific_review_2026_09_07/p1/ai_source_v3_preparation.json
.venv/Scripts/python.exe -m pytest tests/test_repaired_annotation.py -q
```
