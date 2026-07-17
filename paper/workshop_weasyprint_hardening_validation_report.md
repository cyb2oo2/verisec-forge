# Weasyprint Hardening Validation Report

## 1. Purpose

This validates whether `paper: harden weasyprint install instructions`
(merged as PR #82) actually changed the observed behavior of
`scripts/build_workshop_draft_pdf.py`, by re-running the same
install/build steps `paper/workshop_weasyprint_validation_report.md`
performed against the earlier, unhardened script. **This is not final
SaTML formatting validation and not page-fit validation** — those remain
out of scope, exactly as the build notes and both earlier validation
reports already state.

## 2. Environment State Before Test

Before this test, `markdown` and `weasyprint` were not importable in this
project's `.venv` (they were installed then uninstalled during PR #81's
validation, per `paper/workshop_weasyprint_validation_report.md`'s own
cleanup):

```
.venv/Scripts/python.exe -c "import markdown, weasyprint"
```

```
ModuleNotFoundError: No module named 'markdown'
```

`pyproject.toml` has no `weasyprint` or `markdown` dependency entry —
confirmed by inspection; PR #82 did not add one, matching its own
description.

## 3. Commands Run and Recorded Output

**Step 1 — reinstall the packages** (`pip install markdown weasyprint`,
matching PR #81's validation exactly):

```
Successfully installed Pillow-12.3.0 Pyphen-0.17.2 brotli-1.2.0
cffi-2.1.0 cssselect2-0.9.0 fonttools-4.63.0 markdown-3.10.2
pycparser-3.0 pydyf-0.12.1 tinycss2-1.5.1 tinyhtml5-2.1.0 weasyprint-69.0
webencodings-0.5.1 zopfli-0.4.3
```

Exit code `0` — same versions as PR #81's validation.

**Step 2 — direct import check** (`import markdown; import weasyprint`):

```
OSError: cannot load library 'libgobject-2.0-0': error 0x7e.
Additionally, ctypes.util.find_library() did not manage to locate a
library called 'libgobject-2.0-0'
```

Exit code `1`. **This is the same environment gap PR #81's validation
found**: the Python packages install cleanly, but the Windows native
GTK-stack libraries (Pango/GObject) weasyprint depends on are still not
present on this machine. The MSYS2/pango system-level install PR #82
documented was not attempted here, per this task's scope (record the
expected state, don't force the heavier install).

**Step 3 — `--check-only`** (with weasyprint installed but its native
libraries broken — the exact state that crashed the pre-hardening
script):

```
Input: D:\code\start\paper\workshop_draft_v1.md
Structural summary (not a page-fit claim): {'body_words': 1556, 'numbered_sections': 7, 'figure_placeholders': 3, 'table_placeholders': 2}
pandoc on PATH: False
markdown+weasyprint importable: False
markdown+weasyprint probe: markdown/weasyprint not usable: OSError: cannot load library 'libgobject-2.0-0': error 0x7e.  Additionally, ctypes.util.find_library() did not manage to locate a library called 'libgobject-2.0-0'
No PDF build tool is currently available in this environment. This is a documented, expected state -- see paper/workshop_build_notes.md for install options. --check-only succeeds when the input exists and never fails only because a PDF engine is absent or broken.
check-only: no PDF was built.
```

Exit code `0`.

**Step 4 — full build** (no `--check-only`):

```
Input: D:\code\start\paper\workshop_draft_v1.md
Structural summary (not a page-fit claim): {'body_words': 1556, 'numbered_sections': 7, 'figure_placeholders': 3, 'table_placeholders': 2}
pandoc not found on PATH
markdown/weasyprint not usable: OSError: cannot load library 'libgobject-2.0-0': error 0x7e.  Additionally, ctypes.util.find_library() did not manage to locate a library called 'libgobject-2.0-0'

FAILED: no PDF was produced. Neither pandoc (with a discoverable PDF engine) nor the markdown+weasyprint Python path is available and usable in this environment. See paper/workshop_build_notes.md for install options. This script does not fabricate a success result when no PDF exists.
Failure details:
- pandoc not found on PATH
- markdown/weasyprint not usable: OSError: cannot load library 'libgobject-2.0-0': error 0x7e.  Additionally, ctypes.util.find_library() did not manage to locate a library called 'libgobject-2.0-0'
```

Exit code `1` — correct: no PDF engine actually worked, so a non-zero
exit and no fabricated success is the right outcome for the full build
(unlike `--check-only`, the full build is documented to fail when no
engine is usable).

**Whether a PDF was produced:** No. `build/` does not exist after either
run — confirmed by directly listing it.

**Whether anything generated was committed:** No — nothing was
generated to commit, and `git status` shows no tracked-file changes from
either run.

## 4. Interpretation

- **Did the hardening fix work? Yes.** Before PR #82, this exact
  environment state (weasyprint installed, native libraries broken)
  crashed `--check-only` with an uncaught `OSError` traceback and exit
  code `1`, violating its documented "always succeeds when the input
  exists" promise. After PR #82, the same state produces a clean,
  specific message (`markdown/weasyprint not usable: OSError: cannot
  load library 'libgobject-2.0-0'...`) and exits `0`. This is the
  concrete, reproduced proof the hardening works — not an inference from
  reading the diff.
- **Was a PDF produced? No.** The underlying environment gap (missing
  Windows GTK-stack native libraries) is unchanged from PR #81's
  validation; PR #82 hardened error handling and documentation, it did
  not install system-level dependencies, and did not claim to.
- **What remains blocked:** producing an actual local PDF via the
  markdown+weasyprint path, until the native GTK-stack libraries
  (Pango/GObject) are installed separately from the Python packages —
  e.g. via the MSYS2 steps PR #82 added to
  `paper/workshop_build_notes.md`. That heavier system-level install was
  intentionally not attempted in this task, per its scope.
- **Was page fit or SaTML formatting validated?** No — out of scope, as
  stated in Section 1.

## 5. Recommended Next PR

**Recommendation: `paper: attempt MSYS2 native-library install for weasyprint`.**

The hardening fix is confirmed working, and the remaining blocker
(missing Windows native GTK-stack libraries) is an environment-install
task, not a script or documentation defect, so no further code-facing PR
against `scripts/build_workshop_draft_pdf.py` is justified by this
result. The concrete next step is to follow the MSYS2/pango install
steps PR #82 added to `paper/workshop_build_notes.md` on this machine,
to determine whether they actually resolve the `libgobject-2.0-0` load
failure. If that succeeds and a PDF is produced, the follow-on
`paper: add rendered PDF inspection checklist` becomes the correct next
step at that point — not before, since there is still no rendered PDF to
build a checklist against.

**Alternatives considered and not chosen:**

- `paper: add rendered PDF inspection checklist` — the right choice only
  once a PDF actually exists to inspect. Not applicable yet; this
  validation reproduced the same missing-native-library state as before,
  just with better error handling around it.
- `paper: harden weasyprint install instructions` — already done (PR
  #82); this report validates it, it does not repeat it.
