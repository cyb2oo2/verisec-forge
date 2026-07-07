# References

This file tracks external related-work citations for the Markdown paper draft.
It is not yet a final bibliography.

## Secure-Code Vulnerability and Patch Benchmarks

- [RELATED: primevul] Yangruibo Ding, Yanjun Fu, Omniyyah Ibrahim,
  Chawin Sitawarin, Xinyun Chen, Basel Alomair, David Wagner, Baishakhi
  Ray, and Yizheng Chen. "Vulnerability Detection with Code Language Models:
  How Far Are We?" arXiv:2403.18624, 2024.
  https://arxiv.org/abs/2403.18624
- [RELATED: diversevul] Yizheng Chen, Zhoujie Ding, Lamya Alowain,
  Xinyun Chen, and David Wagner. "DiverseVul: A New Vulnerable Source Code
  Dataset for Deep Learning Based Vulnerability Detection." arXiv:2304.00409,
  2023. https://arxiv.org/abs/2304.00409
- [RELATED: codexglue] Shuai Lu, Daya Guo, Shuo Ren, Junjie Huang,
  Alexey Svyatkovskiy, Ambrosio Blanco, Colin Clement, Dawn Drain,
  Daxin Jiang, Duyu Tang, Ge Li, Lidong Zhou, Linjun Shou, Long Zhou,
  Michele Tufano, Ming Gong, Ming Zhou, Nan Duan, Neel Sundaresan,
  Shao Kun Deng, Shengyu Fu, and Shujie Liu. "CodeXGLUE: A Machine Learning
  Benchmark Dataset for Code Understanding and Generation." arXiv:2102.04664,
  2021. https://arxiv.org/abs/2102.04664

## Code Model Evaluation Beyond Pointwise Accuracy

- [RELATED: codebert] Zhangyin Feng, Daya Guo, Duyu Tang, Nan Duan,
  Xiaocheng Feng, Ming Gong, Linjun Shou, Bing Qin, Ting Liu, Daxin Jiang,
  and Ming Zhou. "CodeBERT: A Pre-Trained Model for Programming and Natural
  Languages." arXiv:2002.08155, 2020.
  https://arxiv.org/abs/2002.08155
- [RELATED: codexglue] See CodeXGLUE above for the broader code
  understanding and generation benchmark context.

## Robustness, Counterfactual, and Consistency Evaluation

- [RELATED: checklist] Marco Tulio Ribeiro, Tongshuang Wu, Carlos Guestrin,
  and Sameer Singh. "Beyond Accuracy: Behavioral Testing of NLP Models with
  CheckList." ACL, 2020. https://aclanthology.org/2020.acl-main.442/
- [RELATED: counterfactual-augmentation] S. Chandra Mouli, Yangze Zhou,
  and Bruno Ribeiro. "Bias Challenges in Counterfactual Data Augmentation."
  arXiv:2209.05104, 2022. https://arxiv.org/abs/2209.05104

## Evidence Localization and Explanation Faithfulness

- [RELATED: eraser] Jay DeYoung, Sarthak Jain, Nazneen Fatema Rajani,
  Eric Lehman, Caiming Xiong, Richard Socher, and Byron C. Wallace. "ERASER:
  A Benchmark to Evaluate Rationalized NLP Models." arXiv:1911.03429, 2019.
  https://arxiv.org/abs/1911.03429
- [RELATED: attention-not-explanation] Sarthak Jain and Byron C. Wallace.
  "Attention is not Explanation." arXiv:1902.10186, 2019.
  https://arxiv.org/abs/1902.10186
- [RELATED: attention-not-not-explanation] Sarah Wiegreffe and Yuval Pinter.
  "Attention is not not Explanation." arXiv:1908.04626, 2019.
  https://arxiv.org/abs/1908.04626

## Citation Gaps (to resolve before submission)

The following datasets and models are used or named in the draft but do not yet
have a verified bibliography entry. They are listed here explicitly rather than
cited with fabricated details; each is marked `citation needed` and should be
filled from the primary source before external submission. This is a working-
draft gap, not a claim gap.

- `citation needed` — **CrossVul** (external vulnerability/patch source used for
  the confound and repair-transfer analyses; §6.4, §8). Cite the CrossVul
  dataset paper.
- `citation needed` — **DeltaSecommits** (a paired-diff source in the
  VeriPatch-RR construction; §4). Cite the DeltaSecommits source.
- `citation needed` — **PatchEval** (a paired-diff source in the VeriPatch-RR
  construction; §4). Cite the PatchEval source.
- `citation needed` — **Qwen2.5-Coder-1.5B-Instruct** (the decoder classifier
  backbone). Cite the Qwen2.5-Coder technical report.
- `citation needed` — **Qwen2.5-0.5B-Instruct** (the generative-judge
  replication slot; §6.2). Cite the Qwen2.5 technical report.
- `citation needed` — **distilgpt2** (the low-canonical non-Qwen decoder
  replication slot; §6.2). Cite DistilGPT-2 / DistilBERT distillation work.

Datasets/models that already have a verified entry above: PrimeVul, DiverseVul,
CodeXGLUE, CodeBERT.
