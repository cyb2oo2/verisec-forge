# Weasyprint MSYS2 Native-Library Install Report

## 1. Purpose

This attempts to resolve the remaining native-library blocker recorded in
`paper/workshop_weasyprint_validation_report.md` and re-confirmed in
`paper/workshop_weasyprint_hardening_validation_report.md`: the
`markdown` + `weasyprint` Python packages install cleanly via `pip`, but
importing `weasyprint` fails with `OSError: cannot load library
'libgobject-2.0-0'` because the Windows native GTK-stack libraries
(Pango, GObject) are missing. `paper/workshop_build_notes.md` documents a
concrete MSYS2-based fix for this; this report determines whether that
fix is actually executable and effective on this machine. **This is not
page-fit validation, not SaTML formatting validation, and not final PDF
submission preparation** — those remain out of scope, exactly as every
prior build-path report in this series already states.

## 2. Baseline Before Install

Before any install attempt in this task, `markdown` and `weasyprint` were
not importable at all (uninstalled at the end of the prior validation
task's cleanup, per `paper/workshop_weasyprint_hardening_validation_report.md`):

```
.venv/Scripts/python.exe -c "import markdown"
```
```
ModuleNotFoundError: No module named 'markdown'
```

```
.venv/Scripts/python.exe -c "import weasyprint"
```
```
ModuleNotFoundError: No module named 'weasyprint'
```

**`--check-only`** (baseline, nothing installed):

```
Input: D:\code\start\paper\workshop_draft_v1.md
Structural summary (not a page-fit claim): {'body_words': 1556, 'numbered_sections': 7, 'figure_placeholders': 3, 'table_placeholders': 2}
pandoc on PATH: False
markdown+weasyprint importable: False
markdown+weasyprint probe: markdown/weasyprint not installed: ModuleNotFoundError: No module named 'markdown'
No PDF build tool is currently available in this environment. This is a documented, expected state -- see paper/workshop_build_notes.md for install options. --check-only succeeds when the input exists and never fails only because a PDF engine is absent or broken.
check-only: no PDF was built.
```

Exit code `0`.

**Full build** (baseline): same tool-availability messages, then

```
FAILED: no PDF was produced. Neither pandoc (with a discoverable PDF engine) nor the markdown+weasyprint Python path is available and usable in this environment. See paper/workshop_build_notes.md for install options. This script does not fabricate a success result when no PDF exists.
```

Exit code `1`. `build/` did not exist before or after this run.

## 3. Native-Library Install Attempt

**Commands attempted** (checking for the prerequisite before running
`pacman -S mingw-w64-x86_64-pango`, per
`paper/workshop_build_notes.md` Step 2):

```bash
which pacman
where pacman
ls -d /c/msys64
ls -d "C:/msys64"
find "/c/Program Files" -maxdepth 2 -iname "*msys*"
find "/c/Program Files (x86)" -maxdepth 2 -iname "*msys*"
ls /usr/bin/pacman*
ls /mingw64/bin/pacman*
```

**Shell/environment used:** Git Bash (Git for Windows' own MinGW/MSYS
runtime, the shell this task's commands run in), checked both for a
system MSYS2 installation and for `pacman` inside Git Bash's own
`/usr/bin` and `/mingw64/bin`.

**Whether MSYS2 was available:** No. No `C:\msys64` directory (or any
`*msys*`-named directory under `Program Files` / `Program Files (x86)`)
exists on this machine.

**Whether `pacman` was available:** No. `which pacman` and `where
pacman` both failed to locate it; it is not present in Git Bash's own
`/usr/bin` or `/mingw64/bin` either — Git for Windows' bundled MinGW/MSYS
runtime does not ship a package manager, despite sharing tooling
ancestry with MSYS2.

**Whether `mingw-w64-x86_64-pango` installed:** Not attempted —
`pacman -S mingw-w64-x86_64-pango` requires `pacman`, which is not
present. Running it would only produce a "command not found" error, not
a meaningful signal.

**Exact blocker:** MSYS2 itself is not installed on this machine, and no
`pacman` binary is reachable from the shell. `paper/workshop_build_notes.md`'s
documented fix requires installing MSYS2 first (its own separate
installer from `https://www.msys2.org/`), which this task deliberately
did not do: installing new system-level software is outside what this
task's scope covers on its own, and the task instructions explicitly say
not to fake the install or substitute an unrelated package manager. This
blocker is recorded as-is rather than worked around.

## 4. Post-Install Validation

Since the native-library install step itself was blocked (no MSYS2, no
`pacman`), "post-install" here means: re-run the same checks after
confirming the native-library route could not be attempted, using a
fresh `pip install markdown weasyprint` to reproduce the exact
pip-package-installed-but-native-library-missing state (matching the
methodology of the two prior validation reports), so the requested
`python -m weasyprint --info` and full-build commands have something to
run against.

**Reinstall** (`pip install markdown weasyprint`): succeeded, same
versions as both prior reports
(`Pillow-12.3.0 Pyphen-0.17.2 brotli-1.2.0 cffi-2.1.0 cssselect2-0.9.0
fonttools-4.63.0 markdown-3.10.2 pycparser-3.0 pydyf-0.12.1
tinycss2-1.5.1 tinyhtml5-2.1.0 weasyprint-69.0 webencodings-0.5.1
zopfli-0.4.3`), exit code `0`.

**Import result** (`import markdown; import weasyprint`):

```
OSError: cannot load library 'libgobject-2.0-0': error 0x7e.
Additionally, ctypes.util.find_library() did not manage to locate a
library called 'libgobject-2.0-0'
```

Exit code `1` — identical to both prior reports. No change.

**`python -m weasyprint --info` result:** same `OSError: cannot load
library 'libgobject-2.0-0'` traceback, exit code `1`. WeasyPrint cannot
even report its own diagnostic info without the native libraries loading
first.

**`--check-only` result:** exit code `0`. The hardened probe from PR #82
correctly catches the `OSError` and reports
`markdown/weasyprint not usable: OSError: cannot load library
'libgobject-2.0-0'...` instead of crashing — consistent with
`paper/workshop_weasyprint_hardening_validation_report.md`'s finding
that the hardening fix works, independent of whether the native-library
gap itself is resolved.

**Full build result:** exit code `1`, clean failure message listing both
`pandoc not found on PATH` and the `libgobject-2.0-0` `OSError`, no raw
traceback. No PDF was produced.

**Whether `build/workshop_draft_v1.pdf` was produced:** No. `build/`
does not exist after either the baseline or the post-attempt runs.

**Whether `build/` remains git-ignored:** Yes — unaffected, since no
`.gitignore` changes were made and no file was ever created under
`build/` to test against.

**Whether any generated PDF was committed:** No — none was generated to
commit, and `git status` shows no tracked-file changes from any install
or build command run in this task.

Packages installed for this reproduction step (`markdown`, `weasyprint`,
and their dependencies) were uninstalled afterward, restoring the
environment to the same not-importable baseline recorded in Section 2 —
confirmed via a repeat `ModuleNotFoundError` on both `import markdown`
and `import weasyprint`.

## 5. Interpretation

- **Did MSYS2/Pango resolve the `libgobject-2.0-0` blocker? No — it was
  never attempted, because MSYS2 itself is not installed on this
  machine and no `pacman` binary is reachable.** This is a distinct
  finding from the two prior reports, which found the *Python* packages
  install cleanly but native libraries are missing; this report adds
  that the *documented remediation path itself* has an unmet
  prerequisite (MSYS2) on this specific machine.
- **Is the `markdown + weasyprint` build path now usable on this
  machine? No, unchanged from both prior reports.** The `libgobject-2.0-0`
  load failure persists identically.
- **Was page fit validated?** No — out of scope, as stated in Section 1.
- **Was SaTML formatting validated?** No — out of scope, as stated in
  Section 1.
- **What remains blocked:** two things, in order. First, installing
  MSYS2 itself (a separate, system-level installer from
  `https://www.msys2.org/`) on this machine — not attempted here, since
  installing new system software is outside this task's scope and the
  task instructions direct against faking or substituting it. Second,
  once MSYS2 is installed, running `pacman -S mingw-w64-x86_64-pango`
  and verifying the resulting DLLs are discoverable (per
  `paper/workshop_build_notes.md` Steps 2–3) remains untested until the
  first step is done by whoever has the ability to install system-level
  software on this machine.

## 6. Recommended Next PR

**Recommendation: `paper: document unavailable MSYS2 install path`.**

Per the decision rule this report was given, this is the correct branch:
MSYS2/`pacman` is unavailable in this environment, so no PDF-generation
or environment-setup-failure PR applies. The next PR should record, in
`paper/workshop_build_notes.md`, that the documented MSYS2 route has an
unmet prerequisite on at least one contributor machine (this one) and
that installing MSYS2 itself is a manual, system-level step outside any
script this repository can run — not attempt the MSYS2 install itself
(that remains a human, system-level action) and not attempt any
alternative package manager as a substitute without the same kind of
justification and official-documentation citation this report's own
Section 3 required of itself.

**Alternatives considered and not chosen:**

- `paper: add rendered PDF inspection checklist` — the right choice only
  once a PDF actually exists to inspect. Not applicable; no PDF was
  produced, and the underlying native-library gap is unresolved.
- `paper: document unresolved MSYS2/weasyprint blocker` — the correct
  choice if MSYS2 *were* available but the `pacman` install or the
  resulting library-loading step failed. Not applicable here, since the
  actual blocker is one step earlier: MSYS2 itself was never installed
  on this machine, not that its install failed.
