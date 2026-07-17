# Weasyprint PDF Build Path Validation Report

## 1. Purpose

This validates whether `paper/workshop_build_notes.md`'s recommended
provisional toolchain (`markdown` + `weasyprint`) actually works in this
project's current development environment, moving from "documented as
recommended" to "known to work or known to fail, with the exact reason
recorded." **This is not final SaTML formatting validation and not page-fit
validation** — those remain out of scope, exactly as the build notes and
the earlier `paper/workshop_build_smoke_report.md` already state.

## 2. Install Attempt

- **Command used:**
  ```
  .venv/Scripts/python.exe -m pip install markdown weasyprint
  ```
  (equivalent to the documented `pip install markdown weasyprint`, run
  against this project's own virtual environment).
- **Result: install succeeded.** `pip` reported
  `Successfully installed Pillow-12.3.0 Pyphen-0.17.2 brotli-1.2.0
  cffi-2.1.0 cssselect2-0.9.0 fonttools-4.63.0 markdown-3.10.2
  pycparser-3.0 pydyf-0.12.1 tinycss2-1.5.1 tinyhtml5-2.1.0 weasyprint-69.0
  webencodings-0.5.1 zopfli-0.4.3`, exit code `0`.
- **However, a successful `pip install` did not mean weasyprint actually
  imports.** A direct import check afterward —
  `.venv/Scripts/python.exe -c "import markdown; import weasyprint"` —
  failed with:
  ```
  OSError: cannot load library 'libgobject-2.0-0': error 0x7e.
  Additionally, ctypes.util.find_library() did not manage to locate a
  library called 'libgobject-2.0-0'
  ```
  followed by weasyprint's own printed guidance pointing to
  https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation
  and `#troubleshooting`. This is exactly the Windows native-library gap
  `paper/workshop_build_notes.md`'s "Windows caveat" already warned about
  (Pango/GObject/cairo/gdk-pixbuf are not installed by `pip` alone) — the
  warning was accurate, not theoretical.
- **No dependency file was changed.** `pyproject.toml` has no diff; the
  packages installed only into this environment's `.venv`, which is
  git-ignored. `git status` after the install/build attempts shows no
  tracked-file changes from the install itself.

## 3. Build Attempt

**`--check-only` output** (after the install above):

```
Input: D:\code\start\paper\workshop_draft_v1.md
Structural summary (not a page-fit claim): {'body_words': 1556, 'numbered_sections': 7, 'figure_placeholders': 3, 'table_placeholders': 2}
[...]
OSError: cannot load library 'libgobject-2.0-0': error 0x7e. [...]
```

Exit code: `1`.

**This is a genuine finding, not just an install-gap confirmation:**
`--check-only` is documented (`paper/workshop_build_notes.md`) to "succeed
when the input file exists and never require a PDF engine." That promise
did not hold here — the script's `weasyprint_path_available` probe
(`scripts/build_workshop_draft_pdf.py`) only catches `ImportError`, but
weasyprint's native-library failure raises `OSError` instead, so the probe
raises uncaught and `--check-only` exits `1` with a raw traceback rather
than gracefully reporting "weasyprint not importable" and continuing to
exit `0` as designed. This is a real gap in the script surfaced by actually
running it with weasyprint installed-but-broken — a state the script was
not previously tested against, since prior validation
(`paper/workshop_build_smoke_report.md`) only observed the
weasyprint-not-installed-at-all state (a clean `ImportError`).

**Full build** (no `--check-only`): same `OSError` traceback, exit code
`1`.

**Whether a PDF was produced:** No. `build/` does not exist after either
run — confirmed by listing it directly.

**Whether any generated artifact was committed:** No — none was produced,
and `build/` remains git-ignored per `.gitignore` regardless.

## 4. Interpretation

- **Is the weasyprint path currently usable? No, not in this environment
  as-is.** The Python package layer installs cleanly via `pip`, but the
  native system libraries weasyprint depends on for text/font layout
  (Pango, GObject, and related GTK-stack libraries) are not present on this
  Windows machine, and installing them requires a separate,
  documented-but-not-yet-executed step
  (https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows).
- **Is the build output generic?** Not applicable — no PDF was produced to
  evaluate.
- **Was page fit validated?** No.
- **Was SaTML formatting validated?** No.
- **What remains blocked:** producing an actual local PDF via this
  toolchain, until the native GTK-stack libraries are installed
  separately from the Python packages. Separately, and independent of
  whether that install happens: `--check-only`'s own reliability guarantee
  ("never requires a PDF engine, always succeeds when the input exists")
  has a real gap for the specific case of "weasyprint installed but its
  native libraries are broken," which should be fixed regardless of
  whether anyone completes the native-library install, since a broken
  partial install is a realistic state for future contributors to land in.

## 5. Recommended Next PR

**Recommendation: `paper: harden weasyprint install instructions`.**

Per the decision rule this report was given (PDF generation failed →
harden install instructions), this is the correct branch of that choice —
PDF generation did not succeed in this environment. Concretely, that PR
should cover two things this validation surfaced, not just the general
"install failed" outcome:

1. Expand `paper/workshop_build_notes.md`'s Windows caveat from a link
   into concrete, verified install steps for the GTK-stack native
   libraries (e.g., the MSYS2-based path WeasyPrint's own docs
   recommend), since this report confirms the current one-line caveat and
   external link, while accurate, were not sufficient to get a working
   install on the first attempt.
2. Fix `scripts/build_workshop_draft_pdf.py`'s `--check-only` path to
   catch `OSError` (and any other exception weasyprint's native-library
   probe can raise) alongside `ImportError`, so `--check-only` keeps its
   documented promise of always succeeding when the input file exists,
   even when weasyprint is installed but its native libraries are broken
   — a state this validation showed is real, not hypothetical.

**Alternatives considered and not chosen:**

- `paper: add rendered PDF inspection checklist` — the decision rule's
  other branch, for when PDF generation *succeeds*. Not applicable here;
  there is no rendered PDF to inspect.
- `paper: prepare anonymization checklist` — premature. SaTML 2027's
  anonymity policy is still unpublished (`paper/workshop_draft_v1.md`
  "Open Submission Requirements"), and the build path itself is not yet
  producing output to anonymize.
- `paper: wait for SaTML 2027 formatting requirements` — not chosen
  because it is not an action, and there is real, concrete, actionable
  work available right now (the two items above) that does not depend on
  SaTML 2027's CFP publishing.
