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

## External Vulnerability/Patch Sources (CrossVul, DeltaSecommits, PatchEval)

- [RELATED: crossvul] Georgios Nikitopoulos, Konstantina Dritsa, Panos
  Louridas, and Dimitris Mitropoulos. "CrossVul: A Cross-Language
  Vulnerability Dataset with Commit Data." Proceedings of the 29th ACM Joint
  Meeting on European Software Engineering Conference and Symposium on the
  Foundations of Software Engineering (ESEC/FSE), 2021.
  https://doi.org/10.1145/3468264.3473122
- [RELATED: patcheval] Zichao Wei, Jun Zeng, Ming Wen, Zeliang Yu, Kai Cheng,
  Yiding Zhu, Jingyi Guo, Shiqi Zhou, Le Yin, Xiaodong Su, and Zhechao Ma.
  "PatchEval: A New Benchmark for Evaluating LLMs on Patching Real-World
  Vulnerabilities." arXiv:2511.11019, 2025.
  https://arxiv.org/abs/2511.11019
- [RELATED: deltasecommits] DeltaSecommits dataset (Hugging Face:
  `rufimelo/DeltaSecommits`, MIT license): 2,493 paired vulnerable/secure C
  code samples across 25 CWE categories, curated from single-commit
  security-fixing commits linked to OSV/NVD vulnerability records.
  https://huggingface.co/datasets/rufimelo/DeltaSecommits. The dataset card
  states it is associated with Rui Melo et al., "Do Language Models Prefer
  Vulnerable Code? A Probabilistic Study of Insecure Code Preference" (ICST
  2026); a complete author list and a DOI/arXiv identifier for that paper
  could not be independently verified as of this citation pass, so only the
  dataset itself — the actual external source used in this repository — is
  cited with verified details rather than an unverified full paper citation.

## Model Backbones (Qwen2.5-Coder, Qwen2.5, distilgpt2)

- [RELATED: qwen25-coder] Binyuan Hui, Jian Yang, Zeyu Cui, Jiaxi Yang,
  Dayiheng Liu, Lei Zhang, Tianyu Liu, Jiajun Zhang, Bowen Yu, Keming Lu, Kai
  Dang, Yang Fan, Yichang Zhang, An Yang, Rui Men, Fei Huang, Bo Zheng, Yibo
  Miao, Shanghaoran Quan, Yunlong Feng, Xingzhang Ren, Xuancheng Ren, Jingren
  Zhou, and Junyang Lin. "Qwen2.5-Coder Technical Report." arXiv:2409.12186,
  2024. https://arxiv.org/abs/2409.12186 — backbone for the
  `Qwen/Qwen2.5-Coder-1.5B-Instruct` decoder classifier used throughout
  Sections 4-8.
- [RELATED: qwen25] An Yang, Baosong Yang, Beichen Zhang, Binyuan Hui, Bo
  Zheng, Bowen Yu, Chengyuan Li, Dayiheng Liu, Fei Huang, Haoran Wei, Huan
  Lin, Jian Yang, Jianhong Tu, Jianwei Zhang, Jianxin Yang, Jiaxi Yang,
  Jingren Zhou, Junyang Lin, Kai Dang, Keming Lu, Keqin Bao, Kexin Yang, Le
  Yu, Mei Li, Mingfeng Xue, Pei Zhang, Qin Zhu, Rui Men, Runji Lin, Tianhao
  Li, Tianyi Tang, Tingyu Xia, Xingzhang Ren, Xuancheng Ren, Yang Fan, Yang
  Su, Yichang Zhang, Yu Wan, Yuqiong Liu, Zeyu Cui, Zhenru Zhang, and Zihan
  Qiu. "Qwen2.5 Technical Report." arXiv:2412.15115, 2024.
  https://arxiv.org/abs/2412.15115 — backbone for the
  `Qwen/Qwen2.5-0.5B-Instruct` generative-judge replication slot (§6.2).
- [RELATED: distilgpt2] Victor Sanh, Lysandre Debut, Julien Chaumond, and
  Thomas Wolf. "DistilBERT, a Distilled Version of BERT: Smaller, Faster,
  Cheaper and Lighter." arXiv:1910.01108, 2019.
  https://arxiv.org/abs/1910.01108 — distilgpt2 (the low-canonical
  non-Qwen decoder replication slot, §6.2) is trained with the same
  distillation procedure described in this paper (per its Hugging Face model
  card); there is no separate distilgpt2-specific paper.

Datasets/models with a verified entry above: PrimeVul, DiverseVul, CodeXGLUE,
CodeBERT, CrossVul, PatchEval, DeltaSecommits, Qwen2.5-Coder, Qwen2.5,
distilgpt2. No citation gaps remain as of this pass.
