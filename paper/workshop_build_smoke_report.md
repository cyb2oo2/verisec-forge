# Workshop Build Smoke Report

## 1. Purpose

This report checks whether the provisional build path
(`scripts/build_workshop_draft_pdf.py`, documented in
`paper/workshop_build_notes.md`) behaves honestly and reproducibly in this
project's current development environment. **It is not a page-fit
validation, and it does not validate SaTML 2027 formatting.** Its only
job is to confirm that `--check-only` correctly reports the environment's
state, and that a full build either produces a real PDF or fails with a
clear, honest message — never a fabricated success.

## 2. Commands Run

Both commands were run directly against `main` at commit `02dc5c4`, using
this environment's local interpreter:

```bash
.venv/Scripts/python.exe scripts/build_workshop_draft_pdf.py --check-only
.venv/Scripts/python.exe scripts/build_workshop_draft_pdf.py
```

(Equivalent to `.\.venv\Scripts\python.exe scripts\build_workshop_draft_pdf.py`
in Windows PowerShell, per `paper/workshop_build_notes.md`'s documented
convention — this environment's actual shell is Git Bash, so the
forward-slash form above is what was literally executed to produce the
output below.)

## 3. Observed Behavior

**`--check-only` run — full recorded output:**

```
Input: D:\code\start\paper\workshop_draft_v1.md
Structural summary (not a page-fit claim): {'body_words': 1556, 'numbered_sections': 7, 'figure_placeholders': 3, 'table_placeholders': 2}
pandoc on PATH: False
markdown+weasyprint importable: False
No PDF build tool is currently available in this environment. This is a documented, expected state -- see paper/workshop_build_notes.md for install options. --check-only never fails for this reason.
check-only: no PDF was built.
```

Exit code: `0` (success).

**Full build run — full recorded output:**

```
Input: D:\code\start\paper\workshop_draft_v1.md
Structural summary (not a page-fit claim): {'body_words': 1556, 'numbered_sections': 7, 'figure_placeholders': 3, 'table_placeholders': 2}
pandoc on PATH: False
markdown+weasyprint importable: False
pandoc not found on PATH
markdown/weasyprint not installed (No module named 'markdown')

FAILED: no PDF was produced. Neither pandoc (with a discoverable PDF engine) nor the markdown+weasyprint Python packages are available in this environment. See paper/workshop_build_notes.md for install options. This script does not fabricate a success result when no PDF exists.
```

Exit code: `1` (failure).

**Summary of the observed state:**

| Check | Result |
| --- | --- |
| `--check-only` succeeds | **Yes** — exits `0`, correctly reports environment state |
| Structural summary output | `body_words: 1556`, `numbered_sections: 7`, `figure_placeholders: 3`, `table_placeholders: 2` — matches `paper/workshop_draft_v1.md`'s actual 7 sections and 5 figure/table placeholders (3 figures + 2 tables) |
| `pandoc` available | **No** — not found on `PATH` |
| `markdown`+`weasyprint` available | **No** — `markdown` package not installed (the check short-circuits before reaching the `weasyprint` import) |
| Full PDF build succeeds | **No** — fails as expected given the above |
| Exact failure reason | `pandoc not found on PATH`; `markdown/weasyprint not installed (No module named 'markdown')` — both attempted paths reported individually, not a single opaque error |
| Was any PDF produced | **No** — `build/` directory does not exist after the run; confirmed directly by listing it |

## 4. Interpretation

- **Success of `--check-only` means the input file and structural scan are
  valid** — it confirms `paper/workshop_draft_v1.md` exists, is readable,
  and its section/figure/table structure can be mechanically parsed. It
  does not mean a PDF can be built, and it does not mean the draft's
  content is otherwise correct (that is `paper/workshop_draft_v0_readiness_audit.md`'s
  job, not this script's).
- **Failure of the full PDF build due to missing tools is expected and
  honest**, not a defect. The script correctly detected the absence of
  both supported toolchains and reported each one's specific absence
  reason, then exited non-zero. This matches exactly what
  `paper/workshop_build_notes.md`'s "Current Limitations" section already
  documented before this smoke test was run — the smoke test confirms the
  documentation was accurate, not that anything is broken.
- **No page fit is validated.** Since no PDF was produced, there is nothing
  to measure a page count against; the structural summary (1,556 body
  words, 7 sections, 5 figure/table placeholders) is a rough mechanical
  signal only, exactly as `paper/workshop_build_notes.md` already states.
- **No SaTML formatting is validated.** This build path is explicitly
  format-neutral (`paper/workshop_build_notes.md` "Why This Is
  Provisional") and was not expected to, and did not, validate anything
  about SaTML 2027's still-unpublished requirements.
- **No generated artifact should be committed**, and none exists to
  commit — the full build run produced no file in `build/`, which itself
  remains git-ignored per `.gitignore`.

## 5. Next Action

**Recommendation: `paper: install or document one supported PDF
toolchain`.**

This PR did not install any system dependency, per its own scope
constraint ("do not install new system dependencies unless they are
already available in the environment") — and neither toolchain was already
available, so this smoke report only observes and records the current
state rather than changing it. That leaves a genuine, concrete next step:
someone with the ability to install software in this environment needs to
either (a) install one working toolchain and confirm the build actually
succeeds, or (b) if installation is not desired right now, narrow
`paper/workshop_build_notes.md`'s two documented options down to one
concrete, tested set of install instructions rather than two untested
hypotheticals.

Between the two toolchains, **weasyprint is the more appropriate default
for this repository specifically** — it installs via `pip` and fits this
project's existing Python-only dependency management convention
(`pyproject.toml`'s `[dev]` extras), whereas pandoc requires a separate
system-level binary installer outside that convention. The final choice
belongs to whoever executes the recommended PR, not to this report.

**Alternatives considered and not chosen:**

- `paper: add pandoc-based local build instructions` — narrower than the
  chosen recommendation; pandoc is a reasonable choice but not obviously
  better-fit for this repo's existing pip-based dependency convention than
  weasyprint is, so committing to it specifically here would be a
  narrower decision than this report is positioned to make.
- `paper: add weasyprint-based local build instructions` — the same
  reasoning as above, from the other direction; a plausible choice, but
  premature to commit to exclusively without first confirming weasyprint's
  native library dependencies (noted in `paper/workshop_build_notes.md`)
  actually work cleanly on this specific machine.
- `paper: create workshop draft v1 quality audit after build smoke` — this
  pivots away from the PDF-tooling gap entirely. `paper/workshop_draft_v0_readiness_audit.md`
  already exists and its findings were already implemented in
  `paper/workshop_draft_v1.md`; another content audit without an
  intervening substantive change (a v2 draft, new evidence) would not have
  new material to audit. The unresolved gap right now is tooling, not
  draft content.
