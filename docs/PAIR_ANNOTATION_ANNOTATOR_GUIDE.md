# Pair Annotation Annotator Guide (Single Author, n=50)

Operational guide for the **stratified 50-pair single-author** blinded study  
(`primevul_pair_study_author50_v1`, seed `20260720`).

Protocol: `docs/HUMAN_PATCH_PAIR_ANNOTATION_PROTOCOL.md`

## What you get

| File | Role |
| --- | --- |
| `annotator_packet.jsonl` | Blinded cases (or exported `annotator_review.md`) |
| `annotator_answers.csv` | **Fill this** empty template |

Do **not** open `private_case_mapping.jsonl` while labeling (holds gold / strata).

Do **not** use model scores, AI draft labels, or web CVE lookup while labeling.

## Task

For each `pair-00N` you see Side A and Side B (code/diff). Choose which side is the **vulnerable** version (candidate-identity), with a short root cause and minimal evidence spans.

## Fields (`annotator_answers.csv`)

| Field | Values |
| --- | --- |
| `vulnerable_side` | `A` \| `B` \| `neither` \| `unclear` |
| `root_cause` | short free text |
| `minimal_evidence_lines` | e.g. `A:12-15;B:8` |
| `context_sufficient` | `yes` \| `no` \| `unclear` |
| `confidence` | `1`–`5` |
| `notes` | optional |
| `reviewed_at` | optional ISO date |

`annotator_id` is pre-filled as `author`.

### Context sufficiency

- `yes` — enough to decide with a security rationale  
- `no` — need more surrounding context  
- `unclear` — borderline; prefer over guessing  

## Workflow

### Recommended: Streamlit single-case UI

```powershell
.\.venv\Scripts\python.exe -m pip install streamlit
.\.venv\Scripts\python.exe -m streamlit run scripts\annotation_tool.py
```

Opens a local browser UI: one pair at a time, Side A / Side B side-by-side, form fields, progress bar, Save / Previous / Next (writes `annotator_answers.csv`).

### Alternative: Markdown sheet + CSV

1. Export a readable sheet (optional):

```powershell
.\.venv\Scripts\python.exe scripts\export_pair_annotation_review_sheets.py
```

2. Label all 50 cases in `annotator_answers.csv`.  
3. Validate:

```powershell
.\.venv\Scripts\python.exe scripts\validate_pair_annotation_answers.py
.\.venv\Scripts\python.exe scripts\check_pair_annotation_study_status.py
```

4. Prefer finishing all 50; partial progress is OK (`partial` status).

## Quality tips (single author)

- Read **both** sides before labeling.  
- Prefer `unclear` / `context_sufficient=no` over forced certainty.  
- Do not “match” known model errors from memory if you recognize a project after scrubbing failure—if identity leaks, skip external lookup and note it.  
- Optionally pass once for labels, then a short second pass only for empty fields (not for harmonizing with model gold).

## What this study is / is not

| Is | Is not |
| --- | --- |
| Stratified high-value **author audit** (n=50) | Dual independent rater gold |
| Support for qualitative evidence-coupled review | Inter-annotator Cohen’s κ study |
| Distinct from AI pilot labels | Prevalence estimate for PrimeVul |
| Distinct from 30-row localization rounds | Model-quality headline benchmark |

**Human labels ≠ AI pilot.** Single-author labels are weaker than dual independent annotation and must be reported as such in the paper.
