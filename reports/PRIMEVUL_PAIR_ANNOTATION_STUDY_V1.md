# PrimeVul Pair Annotation Study — Author Audit n=50

**Status:** `scaffold_ready_annotation_pending`  
**Study id:** `primevul_pair_study_author50_v1`  
**Seed:** `20260720` · **Mode:** single author · **n:** 50

## 1. Purpose

Stratified **single-author** human audit of 50 patch pairs for evidence-coupled qualitative review: vulnerable side, minimal evidence, context sufficiency, confidence.

## 2. Paper claim boundary (required wording)

> The human pair audit is a stratified 50-pair single-author annotation under blinded packet presentation (metadata scrubbed; sides randomized). It supports qualitative evidence-coupled error analysis and author-facing case review. It is not independent dual-rater gold, does not report inter-annotator Cohen's κ, is not a prevalence estimate for PrimeVul, is not AI pilot labeling, and must not be promoted as a model-quality benchmark or replacement for the pair-coupled decoding mainline metrics.

| Claim | Allowed? |
| --- | --- |
| Author-labeled stratified audit (n=50) | Yes, with limitations |
| Dual independent gold / Cohen’s κ | **No** (not collected) |
| AI pilot as human gold | **No** |
| Prevalence of vulnerabilities in PrimeVul | **No** |
| Replacement for pair-coupled BA mainline | **No** |
| Same as 30-row evidence-localization rounds | **No** (distinct track) |

**Human labels ≠ AI pilot.**

## 3. Protocol and guide

- `docs/HUMAN_PATCH_PAIR_ANNOTATION_PROTOCOL.md`
- `docs/PAIR_ANNOTATION_ANNOTATOR_GUIDE.md`

Blinding: randomized order and A/B sides; Project/CVE/CWE scrubbed from packet diffs; private mapping not for use during labeling.

## 4. Sampling

| Item | Value |
| --- | ---: |
| Seed | 20260720 |
| Candidate pair groups | 827 |
| Materialized pairs | **50** |
| model_error | 10 |
| low_margin | 10 |
| high_confidence | 10 |
| large_patch | 10 |
| control | 10 |

Machine summary: `reports/secure_code_primevul_pair_annotation_study_v1.json`  
Live status: `reports/secure_code_primevul_pair_annotation_status_v1.json`

## 5. Completion

| Metric | Value |
| --- | ---: |
| Author complete | 0 / 50 (until labels filled) |
| Publishable gate (50/50) | not met |
| Inter-annotator κ | **n/a** |

```powershell
.\.venv\Scripts\python.exe scripts\check_pair_annotation_study_status.py
```

## 6. Artifacts (local)

| File | Role |
| --- | --- |
| `data/annotation/primevul_pair_study_v1/annotator_packet.jsonl` | Blinded packet |
| `data/annotation/primevul_pair_study_v1/annotator_answers.csv` | Empty answer template |
| `data/annotation/primevul_pair_study_v1/private_case_mapping.jsonl` | Staff-only mapping |

## 7. Limitations

- Single author (possible system familiarity bias; no second rater)  
- n=50 audit sample, not population inference  
- Free-text root cause / spans are qualitative  
- Packets not public until license/privacy gate  

## 8. Non-claims

- Not dual-rater reliability  
- Not AI adjudication gold  
- Not open-set model ranking  
- Not a substitute for retained PrimeVul pair-coupled statistics  

## Next step (author)

1. Label `annotator_answers.csv` (or review sheet)  
2. `validate_pair_annotation_answers.py` + `check_pair_annotation_study_status.py`  
3. Update this report’s completion table from status JSON  
