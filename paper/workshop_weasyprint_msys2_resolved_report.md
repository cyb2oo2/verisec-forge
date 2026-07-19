# Weasyprint MSYS2 Blocker Resolution Report

## 1. Purpose

`paper/workshop_weasyprint_msys2_install_report.md` (PR #85) found that
MSYS2 and `pacman` were unavailable on the tested Windows contributor
machine, so the documented `pacman -S mingw-w64-x86_64-pango` step could
not be run, and the `libgobject-2.0-0` blocker remained unresolved. This
report records what happened after MSYS2 was installed manually on that
same machine (a human, system-level action, outside anything this
repository's scripts do) and the documented native-library step was
retried. **This is not page-fit validation, not SaTML formatting
validation, and not final PDF submission preparation** — those remain
out of scope, exactly as every prior build-path report in this series
states.

## 2. Baseline (Carried Forward from PR #85)

Before this task, per `paper/workshop_weasyprint_msys2_install_report.md`:
MSYS2 was not installed, `pacman` was unavailable, `libgobject-2.0-0`
could not be loaded, and no PDF had ever been produced by this build
path. This report does not re-run that pre-MSYS2 baseline — MSYS2 was
already installed on the machine by the time this task started — it
picks up directly at the native-library install step.

## 3. Native-Library Install

**MSYS2 installation:** performed manually by the repository owner
before this task began (a system-level installer from
`https://www.msys2.org/`, outside anything this task or its scripts
did). Confirmed present at `C:\msys64` with `pacman.exe` at
`C:\msys64\usr\bin\pacman.exe`.

**Command run** (per `paper/workshop_build_notes.md` Step 2):

```bash
C:\msys64\usr\bin\pacman.exe -S --noconfirm mingw-w64-x86_64-pango
```

(the `--noconfirm` flag was added only to make the install
non-interactive for this task; the package and command are exactly as
documented.)

**Result:** succeeded. `pacman` resolved and installed
`mingw-w64-x86_64-pango` and its dependency chain (`glib2`, `harfbuzz`,
`freetype`, `fontconfig`, `cairo`, `fribidi`, `libthai`, `libdatrie`,
and others), finishing with `Running post-transaction hooks... Updating
fontconfig cache...` and no errors.

**Verification the DLLs exist:**

```
C:\msys64\mingw64\bin\libgobject-2.0-0.dll
C:\msys64\mingw64\bin\libpango-1.0-0.dll
C:\msys64\mingw64\bin\libpangocairo-1.0-0.dll
C:\msys64\mingw64\bin\libpangoft2-1.0-0.dll
C:\msys64\mingw64\bin\libpangowin32-1.0-0.dll
```

All present after the `pacman` install.

## 4. Post-Install Validation

**Reinstall the Python packages** (`pip install markdown weasyprint`):
succeeded, same versions as all prior reports in this series.

**Import result** (`import markdown; import weasyprint`):

```
IMPORT OK
```

Exit code `0` — **this is the first time in this report series that this
import has succeeded.**

**`python -m weasyprint --info` result:**

```
System: Windows
Machine: AMD64
Version: 10.0.26200
Release: 11

WeasyPrint version: 69.0
Python version: 3.13.14
Pydyf version: 0.12.1
Pango version: 15701
```

Exit code `0`. WeasyPrint can now report its own diagnostic info,
confirming it located a working Pango.

**A finding not anticipated by `paper/workshop_build_notes.md`'s Step
5:** `WEASYPRINT_DLL_DIRECTORIES` did **not** need to be set manually.
Inspecting `weasyprint/text/ffi.py` (installed package, version 69.0)
shows it already defaults that environment variable to
`C:\\msys64\\mingw64\\bin;C:\\Program Files\\GTK3-Runtime Win64\\bin`
when unset — exactly MSYS2's standard default install location. Since
MSYS2 was installed with its default options (as
`paper/workshop_build_notes.md` Step 2.1 instructs), weasyprint found
the DLLs automatically with no manual environment configuration. Step 5
("if Python still cannot find the DLLs, set the DLL search path...")
remains correct and necessary for a non-default MSYS2 install location,
but was not needed here. Confirmed by re-running the import check in a
fresh shell with `WEASYPRINT_DLL_DIRECTORIES` unset and unexported:
import still succeeded.

**`--check-only` result:**

```
Input: D:\code\start\paper\workshop_draft_v1.md
Structural summary (not a page-fit claim): {'body_words': 1556, 'numbered_sections': 7, 'figure_placeholders': 3, 'table_placeholders': 2}
pandoc on PATH: False
markdown+weasyprint importable: True
check-only: no PDF was built.
```

Exit code `0`. `markdown+weasyprint importable: True` for the first time
in this series — previously always `False`.

**Full build result:**

```
Input: D:\code\start\paper\workshop_draft_v1.md
Structural summary (not a page-fit claim): {'body_words': 1556, 'numbered_sections': 7, 'figure_placeholders': 3, 'table_placeholders': 2}
pandoc on PATH: False
markdown+weasyprint importable: True
pandoc not found on PATH
built via markdown+weasyprint: D:\code\start\build\workshop_draft_v1.pdf
```

Exit code `0`. **A PDF was produced — the first successful full build in
this report series.**

**Whether `build/workshop_draft_v1.pdf` was produced:** Yes. Confirmed
via `file build/workshop_draft_v1.pdf` → `PDF document, version 1.7`,
and the raw file header starts with the `%PDF-1.7` magic bytes. File
size: 51,397 bytes.

**Whether `build/` remains git-ignored:** Yes — `git check-ignore -v
build/workshop_draft_v1.pdf` confirms it matches `.gitignore:16:build/`.

**Whether any generated PDF was committed:** No. `git status` shows no
change under `build/` at any point; the directory and file remain
untracked and ignored.

Packages installed for this validation (`markdown`, `weasyprint`, and
their pip dependencies) were uninstalled afterward, restoring the
Python-package layer to the same not-importable baseline used
throughout this report series — confirmed via a repeat
`ModuleNotFoundError` on `import markdown`. The MSYS2 installation and
the `mingw-w64-x86_64-pango` system package were **not** uninstalled:
they are the repository owner's own system-level software, installed
deliberately and outside this repository's control, not a per-test
artifact this task's cleanup convention applies to.

## 5. Interpretation

- **Did MSYS2/Pango resolve the `libgobject-2.0-0` blocker? Yes.** This
  is a direct, reproduced confirmation: the same import that failed with
  `OSError: cannot load library 'libgobject-2.0-0'` in
  `paper/workshop_weasyprint_validation_report.md`,
  `paper/workshop_weasyprint_hardening_validation_report.md`, and
  `paper/workshop_weasyprint_msys2_install_report.md` now succeeds
  cleanly on this same machine, after and only after installing MSYS2
  and running `pacman -S mingw-w64-x86_64-pango`.
- **Is the `markdown + weasyprint` build path now usable on this
  machine? Yes.** Both `--check-only` and the full build now report
  `markdown+weasyprint importable: True`, and the full build produces an
  actual PDF file.
- **Was page fit validated?** No — out of scope, as stated in Section 1.
  The structural summary the script prints is explicitly labeled "not a
  page-fit claim," and this report does not characterize the PDF's
  layout, length, or formatting.
- **Was SaTML formatting validated?** No — out of scope, as stated in
  Section 1. The output remains the generic, non-venue-specific
  rendering `paper/workshop_build_notes.md` documents; nothing here
  confirms it matches SaTML 2027's (still-unpublished) requirements.
- **What remains blocked:** nothing at the native-library level on this
  machine. What is genuinely still open is everything downstream of "a
  PDF can be produced": actually inspecting the rendered output for
  gross problems (the stated purpose of this build path per
  `paper/workshop_build_notes.md`'s "Why This Is Provisional" section),
  which has not been done — this report only confirms the build
  succeeds, not what the output looks like.

## 6. Recommended Next PR

**Recommendation: `paper: add rendered PDF inspection checklist`.**

Per the decision rule this report inherits from
`paper/workshop_weasyprint_msys2_install_report.md`'s own Section 6:
"If PDF generation succeeds, recommend: `paper: add rendered PDF
inspection checklist`." That condition is now met — a real PDF exists
at `build/workshop_draft_v1.pdf` for the first time in this series. The
next PR should define what a human should actually look at when
opening that PDF (gross length, figure/table placeholder placement,
citation anchor rendering, obvious layout breakage) without claiming
page fit or SaTML formatting compliance, consistent with this build
path's documented, provisional purpose.

**Alternatives considered and not chosen:**

- `paper: document unresolved MSYS2/weasyprint blocker` — not
  applicable; the blocker is resolved on this machine, not unresolved.
- `paper: document unavailable MSYS2 install path` — already done (PR
  #86); this report supersedes that state for this machine, it does not
  repeat it. (`paper/workshop_build_notes.md`'s "Known unresolved local
  prerequisite" section is updated in this same PR to reflect the
  resolution.)
