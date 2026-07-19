# Workshop Draft Build Notes

This documents `scripts/build_workshop_draft_pdf.py`, a lightweight,
**provisional and format-neutral** build path for rendering
`paper/workshop_draft_v1.md` to a local draft PDF. It exists so the project
can start checking approximate page length, figure/table placement risk,
citation rendering, and references formatting — it does not produce a
SaTML-formatted submission PDF, and it should not be mistaken for one.

## How to Run the Build

Check the input and report tool availability without requiring a PDF
engine. `--check-only` succeeds when the input file exists and never
requires a PDF engine; it never builds a PDF:

```powershell
.\.venv\Scripts\python.exe scripts\build_workshop_draft_pdf.py --check-only
```

Attempt an actual PDF build (requires one of the tools below to be
installed; fails clearly and exits non-zero if neither is available):

```powershell
.\.venv\Scripts\python.exe scripts\build_workshop_draft_pdf.py
```

Override the input/output paths if needed:

```powershell
.\.venv\Scripts\python.exe scripts\build_workshop_draft_pdf.py --input paper\workshop_draft_v1.md --output build\workshop_draft_v1.pdf
```

## Required Tools

`paper/workshop_build_smoke_report.md` recorded the original clean
environment, where neither supported toolchain was installed. Then
`paper/workshop_weasyprint_validation_report.md` recorded the next, more
specific state: `pip install markdown weasyprint` succeeded, but importing
`weasyprint` failed with `OSError: cannot load library 'libgobject-2.0-0'`
because the required Windows native libraries were missing. That second
state is realistic and now explicitly supported by the build script: the
probe reports it clearly instead of crashing `--check-only`.

### Recommended provisional toolchain: markdown + weasyprint

This is the preferred default for this repository: a Python-first path that
fits the project's existing pip-based dependency convention
(`pyproject.toml`'s `[dev]` extras), unlike pandoc, which requires a
separate system-level binary and its own PDF engine outside that
convention.

This does **not** mean `pip install` alone is always enough on Windows.
WeasyPrint itself depends on native rendering libraries such as Pango,
GObject/GLib, cairo, gdk-pixbuf, HarfBuzz, and fontconfig. A successful
Python package install can still fail at import time with errors such as
`cannot load library 'libgobject-2.0-0'`, `cannot load library
'gobject-2.0-0'`, or Pango/GObject-related DLL errors.

#### Step 1: install the Python packages

```bash
pip install markdown weasyprint
```

This is a local, on-demand install for whoever runs the build — it is
**not** added to `pyproject.toml` as a project dependency (see "Why Not a
Project Dependency" below).

#### Step 2: on Windows, install WeasyPrint's native dependencies

For the Python-library route used by this repository's script, follow
WeasyPrint's official Windows guidance:

1. Install MSYS2 with its default options.
2. Open the MSYS2 shell.
3. Run:
   ```bash
   pacman -S mingw-w64-x86_64-pango
   ```
4. Close the MSYS2 shell.
5. If Python still cannot find the DLLs, set the DLL search path before
   running the build. In `cmd.exe`, WeasyPrint documents this form:
   ```cmd
   set WEASYPRINT_DLL_DIRECTORIES=C:\msys64\mingw64\bin
   ```
   In PowerShell, the equivalent for the current session is:
   ```powershell
   $env:WEASYPRINT_DLL_DIRECTORIES = "C:\msys64\mingw64\bin"
   ```
6. Verify that the folder actually contains the needed `.dll` files before
   treating this as fixed.

Reference: WeasyPrint's Windows and missing-library guidance at
`https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows`
and `https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#missing-library`.

#### Step 3: verify the import before running the build

Do this before expecting the PDF build to work:

```bash
python -c "import markdown; import weasyprint"
```

Optional additional check:

```bash
python -m weasyprint --info
```

If this import check fails with `libgobject-2.0-0`, Pango, GObject, cairo,
or another native-library error, the Python packages are installed but the
native Windows layer is still not usable. The build script will report that
state; it will not fabricate a PDF.

#### Step 4: run the repo build commands

```bash
python scripts/build_workshop_draft_pdf.py --check-only
python scripts/build_workshop_draft_pdf.py
```

Expected output path for a successful build:

```text
build/workshop_draft_v1.pdf
```

Expected failure mode when dependencies are missing or broken: the script
reports a specific message such as `markdown/weasyprint not installed: ...`
or `markdown/weasyprint not usable: OSError: cannot load library ...`, then
exits non-zero for the full build. `--check-only` still exits `0` when the
input file exists, because it is only an environment/reporting check and
never builds a PDF.

- **The output is generic, not SaTML-formatted**: no two-column layout, no
  specific font, no citation-style bibliography — see "Current
  Limitations" below.
- **The generated PDF stays under `build/`, which is git-ignored, and is
  not committed to this repository** under any circumstance.

#### Known unresolved local prerequisite (as of PR #85)

`paper/workshop_weasyprint_msys2_install_report.md` (PR #85) attempted to
follow Steps 2-3 above on this repository's tested Windows contributor
machine, to actually run the `pacman -S mingw-w64-x86_64-pango` install.
The result:

- **MSYS2 was not installed** on that machine — no `C:\msys64` directory,
  no MSYS2 installation under `Program Files`.
- **`pacman` was unavailable** as a result — it is not on `PATH`, and it
  is not bundled with Git Bash's own MinGW/MSYS runtime either, despite
  sharing tooling ancestry with MSYS2.
- Because of that, **`pacman -S mingw-w64-x86_64-pango` could not be
  run** on that machine — there was nothing to invoke it with.
- The `libgobject-2.0-0` load failure documented in Step 3 above
  **remains unresolved on that machine** as a direct consequence: the
  Python packages (`markdown`, `weasyprint`) install cleanly via `pip`,
  but importing `weasyprint` still fails with the same
  `OSError: cannot load library 'libgobject-2.0-0'` seen before any
  install attempt.
- **Installing MSYS2 itself is a manual, system-level action outside
  this repository** — it requires a separate installer from
  `https://www.msys2.org/` run by whoever has permission to install
  system software on that machine. No script in this repository
  attempts or can attempt that installation.
- Once MSYS2 is installed manually on a given machine, the documented
  `pacman -S mingw-w64-x86_64-pango` command (Step 2) and the import
  verification command (Step 3, `python -c "import markdown; import
  weasyprint"`) should be retried on that machine to confirm the fix
  actually resolves the `libgobject-2.0-0` failure there.
- **No PDF has been produced via this toolchain on the tested machine
  yet.** No page fit and no SaTML formatting have been validated — both
  remain out of scope regardless of whether this native-library
  prerequisite is resolved, per "Why This Is Provisional" below.

This is a local, per-machine prerequisite gap, not a defect in
`scripts/build_workshop_draft_pdf.py` or in this documentation: the
hardened script correctly detects and reports the missing native
library (see `paper/workshop_weasyprint_hardening_validation_report.md`)
rather than crashing, and the steps above are the documented fix — they
simply have not yet been executable on the one machine tested so far.

**Why not a project dependency:** adding `weasyprint` to `pyproject.toml`
would make it a required install for every contributor and CI run, for a
provisional, single-purpose build script that most contributors will never
invoke. Documenting the install command, without lock-in, is the safer
default until this build path is something more than provisional (e.g.,
once SaTML 2027's actual requirements are published and a real submission
build is being prepared).

### Optional alternative: pandoc

Not the default. Use only if you already have pandoc installed, or prefer
its output for some other reason.

- `pandoc` must be on `PATH`, and it must in turn be able to find a PDF
  engine itself (a LaTeX distribution, `wkhtmltopdf`, or `weasyprint`).
  Install from https://pandoc.org/installing.html.
- The script tries pandoc first internally (see
  `scripts/build_workshop_draft_pdf.py`), purely as an implementation
  detail of the fallback chain — this does not change which toolchain is
  *recommended* for a contributor deciding what to install. If only
  weasyprint is installed (the recommended path), the script skips pandoc
  automatically and uses weasyprint with no extra configuration needed.

## Expected Output

`build/workshop_draft_v1.pdf` (or the path passed via `--output`). The
`build/` directory is git-ignored — **generated PDFs are not committed to
this repository**, since they are large, environment-dependent (different
pandoc/PDF-engine versions can produce different output), and not something
this repository has an existing convention of tracking (unlike the
deterministic, small, hand-reviewable SVG figures generated by
`scripts/build_paper_mechanism_figures.py`, which are committed).

`--check-only` also prints a structural summary — approximate body word
count, section count, and figure/table placeholder count — as a rough
mechanical signal only. **This is not a page-fit claim.** The qualitative
page-length judgment belongs in `paper/workshop_draft_v0_readiness_audit.md`
Section 7, not this script; the structural summary is an input a human (or
that audit) can use, not a substitute for the judgment itself.

## Current Limitations

- A successful `pip install markdown weasyprint` is not enough on Windows if
  the native GTK/Pango/GObject stack is missing. This exact failure mode is
  recorded in `paper/workshop_weasyprint_validation_report.md` and is now
  handled gracefully by the script's tool-availability probe. On the
  tested Windows contributor machine, MSYS2/pacman was unavailable, so
  the documented native-library fix could not yet be executed; see
  `paper/workshop_weasyprint_msys2_install_report.md`.
- Neither build path attempts any venue-specific formatting: no two-column
  layout, no specific font, no specific margin, no citation-style
  bibliography rendering matching a particular template. The output is a
  generic single-flow PDF suitable only for rough page-count and
  layout-risk estimation.
- The script does not currently render `[RESULT: ...]` / `[RELATED: ...]`
  anchors as formatted citations or a bibliography — they appear as literal
  bracketed text in the rendered PDF. This is acceptable for the rough
  estimation purpose this build path serves, but is a known gap before any
  real typesetting pass.
- Figure and table placeholders (`[Figure N here]`, `[Table N here]`)
  render as literal text, not as actual figures or tables — this script
  does not regenerate, embed, or lay out `paper/figures/*.svg` or the
  Markdown tables from `paper/draft_v0.md`. Placement risk can only be
  estimated from the placeholder's position in the text flow, not from an
  actual rendered figure.

## Why This Is Provisional

SaTML 2027's full submission requirements — page limit, column format,
font, and submission template — are not yet published as of
`docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md`'s research date. Building
against an unpublished, unconfirmed format would risk optimizing the draft
for the wrong page budget or the wrong layout. This build path deliberately
targets a generic, format-neutral rendering instead — good enough to catch
gross problems (a draft several times over any plausible length, a citation
that fails to resolve visually, a table that renders badly) without
pretending to validate fit against a specific venue's rules that do not yet
exist publicly.

## What Must Be Re-Checked Once SaTML 2027 Requirements Are Published

Per `paper/workshop_draft_v1.md`'s own "Open Submission Requirements"
section and `docs/CURRENT_WORKSHOP_TARGET_SHORTLIST.md`, once SaTML 2027's
CFP is published at `https://satml.org/call-for-papers/`:

- Confirm the actual page limit and re-run the build to check real fit
  against it (this build path only supports a rough, format-neutral
  estimate today).
- Confirm the required document format/template (LaTeX class, column
  layout, font) and, if one is mandated, replace this generic build path
  with one that uses it — this script does not currently support any
  specific venue template.
- Confirm the citation/bibliography style required and update how
  `[RESULT: ...]` / `[RELATED: ...]` anchors render, if a formatted
  bibliography is required rather than the current internal anchor
  convention.
- Confirm the anonymity policy and, if double-blind, ensure the build path
  is re-run against an anonymized version of the draft, not
  `paper/workshop_draft_v1.md` directly.
- Confirm the AI-use disclosure formatting requirement and ensure
  `docs/AI_USE_DISCLOSURE_DRAFT.md` is adapted to match, if a specific
  format or section placement is mandated.

None of the above is done in this PR. This build path is a rough,
provisional tool for catching gross length and rendering problems early —
not a substitute for checking SaTML 2027's actual requirements before
submission.