"""Example: extract tables from a PDF and write CSV (validate visually!).

Dependency: pip install pdfplumber
Never treat extracted numbers as authoritative without a source check.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path


def main(pdf_path: str, out_csv: str) -> None:
    try:
        import pdfplumber
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("Install pdfplumber: pip install pdfplumber") from exc

    rows: list[list[str]] = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            for table in page.extract_tables() or []:
                for row in table:
                    rows.append([(c or "").strip() for c in row])

    out = Path(out_csv)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out}. Validate against the PDF before use.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: extract-pdf-table.py <input.pdf> <output.csv>")
    main(sys.argv[1], sys.argv[2])
