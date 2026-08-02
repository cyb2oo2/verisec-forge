---
name: literature-review-helper
description: >-
  Summarize papers, extract methods/claims/limitations, position related work,
  and manage citations honestly. Use when reading/summarizing a paper, building a
  related-work section, comparing baselines, or organizing references. Triggers:
  literature, related work, survey, summarize paper, baseline, prior work,
  citation, bibtex, positioning, "how does this compare to".
---

# Literature Review Helper

Turn external papers into structured, citable notes and honest positioning for
VeriSec Forge — without fabricating references, overclaiming novelty, or
misrepresenting prior work.

## When to Use

- Summarizing a paper into a reusable note.
- Building or revising a related-work / positioning section.
- Comparing the project's baselines and claims to prior work.
- Organizing a `.bib` and de-duplicating citation keys.

## Instructions

### 1. Structured note per paper
- Use `templates/paper_note.md`: bibliographic key, problem, method, datasets,
  headline claims **with their reported bounds**, limitations, and one line on
  relevance to VeriSec Forge (shortcut controls, paired-diff, evidence audit).

### 2. Extract claims faithfully
- Record what the paper actually shows, including its scope limits. Do not
  inflate a paper's result to make a sharper contrast, and do not strawman a
  baseline.

### 3. Position honestly
- Frame this project's contribution against real prior work: shortcut-aware
  paired evaluation vs. same-source leaderboard accuracy; pair-coupled decoding
  vs. single-row prediction; evidence localization as diagnostic vs. solved
  explanation. Concede where prior work is stronger.

### 4. Citations
- One `.bib`, stable keys (e.g. `firstauthorYEARkeyword`). Every claim about
  another paper cites a verifiable entry. If you cannot verify a reference (DOI,
  venue, authors), mark it `TODO-verify` — never fabricate.

### 5. Feed the paper surface
- Related-work text flows into `paper/` via [[scientific-paper-assistant]]; keep
  the same anchoring discipline (numbers cite sources).

## Best Practices & Guardrails

- **Do** capture each cited result's own confidence bounds / dataset.
- **Do** state where prior work outperforms or subsumes this project.
- **Don't** fabricate papers, authors, venues, or DOIs.
- **Don't** cite a paper you have only seen summarized second-hand as if read.
- **Don't** claim novelty without checking the obvious prior baselines.

## Examples

**Positioning sentence (honest contrast)**
> Unlike same-source detection that reports high headline accuracy
> (`0.9524` here too), we evaluate under paired vulnerable/fixed controls, where
> metadata-only, candidate-only, and counterpart-only baselines stay near chance
> (`~0.50`), isolating artifact sensitivity rather than rewarding it.

## Dependencies / Tools

- A single `.bib`; a reference manager export is fine as input
- Optional: `pdfplumber`/`pymupdf` to read source PDFs (see [[document-handling]])
- `templates/paper_note.md`
- Related skills: [[scientific-paper-assistant]], [[document-handling]]
