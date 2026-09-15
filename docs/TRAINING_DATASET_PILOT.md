# 可试训的弱监督数据版本

当前发布入口为 `configs/research_patcheval_training_pilot_v1.json`，数据清单为 `reports/scientific_review_2026_09_07/p1/training_pilot_v1_release.json`。

| 分割 | 函数对 | 双方向训练格式行数 | 项目数 | CVE 数 |
| --- | ---: | ---: | ---: | ---: |
| train | 571 | 1,142 | 245 | 402 |
| validation | 134 | 268 | 120 | 122 |
| test | 133 | 266 | 119 | 125 |
| 总计 | 838 | 1,676 | 484 | 649 |

双方向行数不是独立样本数。来源为本地已有的 [ByteDance/PatchEval](https://huggingface.co/datasets/ByteDance/PatchEval) 缓存，原始字节及配对源文件通过已有重建清单核验；本次没有下载新模型或运行训练。数据卡标注 Apache-2.0，原项目代码的权利来源另行保留，不能把数据卡授权等同于所有上游代码统一授权。

## “可以训练”的准确含义

这是以公开数据集漏洞／修复方向为监督的小规模训练试验，不是 838 对经 AI 逐例确认的金标准。学习目标为配对代码的相对漏洞侧；上游修复方向只是该目标的带噪声代理标签。AI 自报置信度没有参与给未审样本背书。原 P1 的 13 对暂定单侧标签、2 对双侧风险与 17 对未决仍属于另一套诊断账本，没有混入训练。

构建前设定最低规模为 train 400 对、validation/test 各 60 对，并要求项目数；这些是工程试训门槛，不是统计功效保证或模型效果保证。发布版通过规模、哈希、实际分词、输入覆盖、方向与分割隔离检查。训练动态显存需求未实测，尚无训练效果。

## 已执行的筛选

1. 以修复构建器的 1,006 对为候选，重新检查函数完整性。额外拒绝 58 对函数外残余代码，避免仅凭语法树“含一个函数”就判定完整输入。
2. 只删除解析器识别出的注释，保留字符串；不把项目、CVE、补丁描述或漏洞侧标签放入模型文本。注释移除后的代码必须有变化。完整双方向输入最长 3,983 tokens，不截断。
3. 20 对精确重复、10 对长度超限、27 对原 P1 项目、1 对 P1 词法近重复、1 对去注释后无差异被排除。原 36 案例的项目均被保护，不只保护最后 32 个函数。
4. 按项目、CVE 及任一侧代码五元 token 集合 Jaccard ≥ 0.8 的关系取传递组件，然后分割。该词法规则无法证明排除语义克隆、项目别名或基础模型预训练暴露。
5. 在 train 内按固定哈希选择 12 对，由当前助手查看代码与差异。发现修复疑点、共享前缀风险和调用上下文缺口；保守隔离这些样本所属的全部 12 个组件，共 51 对。这里没有证明 51 对全部标签错误，也没有证明其余样本正确。原始候选清单和审查证据保留，验证／测试分割没有重分配。

## 使用与复查

只读检查，不加载模型权重：

```powershell
.venv/Scripts/python.exe scripts/verify_training_pilot.py
.venv/Scripts/python.exe scripts/train_joint_side_choice_classifier.py --config configs/research_patcheval_training_pilot_v1.json --validate-data-only
```

真正启动一次小规模训练时使用同一 config 并去掉 `--validate-data-only`。该命令会执行训练，本轮没有运行。初始化为基础 Qwen2.5-Coder-1.5B-Instruct 加新分类头/LoRA，不加载历史研究适配器。分类头直接编码完整代码对，不使用旧标签查询任务或聊天生成输出；0 表示 A，1 表示 B。验证集供开发，test 不用于挑选训练超参数。

入口在权重加载前验证数据清单、文件哈希、分割路径及实际 tokenizer 的逐条 token ID，禁止旧 checkpoint 初始化与静默截断。兼容保留旧实验配置的行为。后续结果只能报告为上游弱标签一致率及交换一致性；不能自动改称真实漏洞识别准确率。

构建脚本为 `build_training_pilot_dataset.py`，审查隔离发布脚本为 `finalize_training_pilot.py`；两者拒绝覆盖已有版本。AI 审查记录见 `training_pilot_v1_ai_audit.json`，完整机器清单绑定本地输入与派生文件。当前 artifacts 中部分文件被 Git 忽略，因此本地检查通过不等于 fresh clone 已可复现。
