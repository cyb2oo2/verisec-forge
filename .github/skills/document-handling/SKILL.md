---
name: document-handling
description: >-
  Read, generate, and convert research documents: PDF, Word (.docx), Excel/CSV,
  and LaTeX. Use when extracting text/tables from a PDF, producing a report
  document, converting between formats, or inspecting a rendered paper PDF.
  Triggers: PDF, docx, Word, Excel, xlsx, CSV, LaTeX, pandoc, extract table,
  convert document, rendered PDF, spreadsheet.
---

# Document Handling

Work with the document formats a research project accumulates — extracting data
from PDFs, emitting shareable reports, and inspecting rendered paper builds —
while keeping everything reproducible and text-diffable where possible.

## When to Use

- Extracting text, tables, or figures from a PDF (papers, references, exports).
- Converting between Markdown / LaTeX / PDF / DOCX / HTML.
- Reading or writing tabular data (CSV/Excel) as an analysis input/output.
- Inspecting a freshly rendered paper PDF against a checklist.

## Instructions

### 1. Prefer text-native formats in-repo
- Source of truth stays Markdown/LaTeX/JSON/CSV (diffable, reviewable). Treat
  PDF/DOCX/XLSX as **inputs or exports**, not as the canonical store.

### 2. Extracting from PDF
- Use `pdfplumber` / `pymupdf (fitz)` for text+tables; `pdftotext` for quick text.
- Verify extracted tables against the source visually — PDF table extraction is
  error-prone. Never treat scraped numbers as authoritative without a check.

### 3. Excel / CSV as data
- Read with `pandas` (`read_csv`, `read_excel`). Keep the canonical artifact as
  CSV/JSONL in-repo; generate XLSX only for human sharing (e.g. the review sheets
  produced by `scripts/export_pair_annotation_review_sheets.py`).

### 4. Generating documents
- Markdown → PDF/DOCX/HTML via `pandoc` or latexmk. Keep the generating command
  in a script or Makefile target so the output is reproducible, not hand-run.

### 5. Rendered-PDF inspection
- After a LaTeX build, walk the rendered-PDF inspection checklist the repo added
  (see recent `paper:` commits): figures present, tables aligned, no overfull
  boxes hiding content, numbers match the anchor map.

## Best Practices & Guardrails

- **Do** keep a reproducible generation command for any exported document.
- **Do** sanity-check every number extracted from a PDF against its source.
- **Don't** make a binary (PDF/DOCX/XLSX) the single source of truth for data.
- **Don't** commit large generated binaries when a script can rebuild them.
- **Don't** trust OCR/table-extraction output blind.

## Examples

**Extract tables from a PDF**
```python
import pdfplumber
with pdfplumber.open("references/some_paper.pdf") as pdf:
    for page in pdf.pages:
        for table in page.extract_tables():
            ...  # validate against the visual before using
```

**Reproducible Markdown → PDF**
```bash
pandoc paper/draft_v0.md -o build/draft_v0.pdf --pdf-engine=xelatex
```

## Dependencies / Tools

- PDF: `pdfplumber`, `pymupdf`, or `pdftotext`
- Office: `pandas` + `openpyxl` (xlsx), `python-docx`
- Conversion: `pandoc`, `latexmk`/`xelatex`
- Related skills: [[scientific-paper-assistant]], [[literature-review-helper]], [[visualization-and-plotting]]
