"""Single-case Streamlit UI for the 50-pair author annotation study.

Run from the repo root (or any cwd):

    streamlit run scripts/annotation_tool.py

Loads:
  data/annotation/primevul_pair_study_v1/annotator_packet.jsonl
  data/annotation/primevul_pair_study_v1/annotator_answers.csv

Saves updates back to annotator_answers.csv (row upsert by case_id).
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
STUDY_DIR = ROOT / "data" / "annotation" / "primevul_pair_study_v1"
PACKET_PATH = STUDY_DIR / "annotator_packet.jsonl"
ANSWERS_PATH = STUDY_DIR / "annotator_answers.csv"

ANNOTATION_FIELDS = [
    "case_id",
    "annotator_id",
    "vulnerable_side",
    "root_cause",
    "minimal_evidence_lines",
    "context_sufficient",
    "confidence",
    "notes",
    "reviewed_at",
]

UNSET = "(unset)"
SIDE_OPTIONS = [UNSET, "A", "B", "neither", "unclear"]
CONTEXT_OPTIONS = [UNSET, "yes", "no", "unclear"]
# Selectbox (not slider): empty answers must stay empty — never default to "3".
CONFIDENCE_OPTIONS = [UNSET, "1", "2", "3", "4", "5"]
VIEW_MODES = ("Diff (recommended)", "Code", "Both")


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def empty_answer(case_id: str, annotator_id: str = "author") -> dict[str, str]:
    return {
        "case_id": case_id,
        "annotator_id": annotator_id,
        "vulnerable_side": "",
        "root_cause": "",
        "minimal_evidence_lines": "",
        "context_sufficient": "",
        "confidence": "",
        "notes": "",
        "reviewed_at": "",
    }


def load_answers(path: Path, case_ids: list[str]) -> dict[str, dict[str, str]]:
    by_id: dict[str, dict[str, str]] = {cid: empty_answer(cid) for cid in case_ids}
    if not path.exists():
        return by_id
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            case_id = str(row.get("case_id") or "").strip()
            if not case_id:
                continue
            merged = empty_answer(case_id, str(row.get("annotator_id") or "author"))
            for field in ANNOTATION_FIELDS:
                if field in row and row[field] is not None:
                    merged[field] = str(row[field])
            by_id[case_id] = merged
    # Preserve any case_ids from CSV not in packet (should not happen).
    return by_id


def save_answers(path: Path, answers_by_id: dict[str, dict[str, str]], case_order: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [answers_by_id[cid] for cid in case_order if cid in answers_by_id]
    # Append any extra ids not in packet order.
    for case_id, row in answers_by_id.items():
        if case_id not in case_order:
            rows.append(row)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ANNOTATION_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def _normalize_side(value: str) -> str:
    text = (value or "").strip()
    if not text or text == UNSET:
        return ""
    lower = text.lower()
    if lower in {"a", "b"}:
        return lower.upper()
    if lower in {"neither", "unclear"}:
        return lower
    return text


def is_complete(row: dict[str, str]) -> bool:
    side = _normalize_side(row.get("vulnerable_side") or "")
    context = (row.get("context_sufficient") or "").strip().lower()
    if context == UNSET.lower():
        context = ""
    confidence = (row.get("confidence") or "").strip()
    if confidence == UNSET:
        confidence = ""
    root = (row.get("root_cause") or "").strip()
    evidence = (row.get("minimal_evidence_lines") or "").strip()
    return (
        side in {"A", "B", "neither", "unclear"}
        and context in {"yes", "no", "unclear"}
        and confidence in {"1", "2", "3", "4", "5"}
        and bool(root)
        and bool(evidence)
    )


def side_panel(title: str, side: dict[str, Any], view_mode: str) -> None:
    st.markdown(f"### {title}")
    code = str(side.get("code") or "")
    diff = str(side.get("diff") or "")
    if view_mode in ("Diff (recommended)", "Both"):
        st.caption("Unified diff")
        st.code(diff or "(empty diff)", language="diff")
    if view_mode in ("Code", "Both"):
        st.caption("Full code snippet")
        st.code(code or "(empty code)", language="c")


def init_state(packets: list[dict[str, Any]], answers: dict[str, dict[str, str]]) -> None:
    if "case_index" not in st.session_state:
        st.session_state.case_index = 0
    if "answers" not in st.session_state:
        st.session_state.answers = answers
    if "dirty" not in st.session_state:
        st.session_state.dirty = False
    if "last_saved_at" not in st.session_state:
        st.session_state.last_saved_at = None
    if "loaded_case_id" not in st.session_state:
        st.session_state.loaded_case_id = None
    # Form field keys are hydrated when the case changes.
    _ = packets


def hydrate_form_from_answer(case_id: str) -> None:
    """Copy stored answer into widget-backed session keys for the active case."""
    row = st.session_state.answers.get(case_id, empty_answer(case_id))
    conf_raw = (row.get("confidence") or "").strip()
    conf_val = conf_raw if conf_raw in CONFIDENCE_OPTIONS and conf_raw != UNSET else UNSET

    side = _normalize_side(row.get("vulnerable_side") or "")
    context = (row.get("context_sufficient") or "").strip().lower()
    if context not in {"yes", "no", "unclear"}:
        context = UNSET
    st.session_state.form_vulnerable_side = side if side in SIDE_OPTIONS else UNSET
    st.session_state.form_root_cause = row.get("root_cause") or ""
    st.session_state.form_minimal_evidence_lines = row.get("minimal_evidence_lines") or ""
    st.session_state.form_context_sufficient = context if context in CONTEXT_OPTIONS else UNSET
    st.session_state.form_confidence = conf_val
    st.session_state.form_notes = row.get("notes") or ""
    st.session_state.loaded_case_id = case_id


def _stored_label(value: Any) -> str:
    text = str(value or "").strip()
    return "" if text in {"", UNSET} else text


def capture_form_to_answers(case_id: str, *, touch_reviewed_at: bool = True) -> dict[str, str]:
    """Write current form widgets into session answers for case_id."""
    prev = st.session_state.answers.get(case_id, empty_answer(case_id))
    side = _normalize_side(_stored_label(st.session_state.get("form_vulnerable_side", "")))
    root = str(st.session_state.get("form_root_cause", "") or "")
    evidence = str(st.session_state.get("form_minimal_evidence_lines", "") or "")
    context = _stored_label(st.session_state.get("form_context_sufficient", "")).lower()
    if context not in {"yes", "no", "unclear"}:
        context = ""
    confidence = _stored_label(st.session_state.get("form_confidence", ""))
    if confidence not in {"1", "2", "3", "4", "5"}:
        confidence = ""
    notes = str(st.session_state.get("form_notes", "") or "")

    row = {
        "case_id": case_id,
        "annotator_id": prev.get("annotator_id") or "author",
        "vulnerable_side": side,
        "root_cause": root,
        "minimal_evidence_lines": evidence,
        "context_sufficient": context,
        "confidence": confidence,
        "notes": notes,
        "reviewed_at": prev.get("reviewed_at") or "",
    }
    # Include intentional confidence edits in reviewed_at (once confidence is set).
    if touch_reviewed_at and any([side, root, evidence, context, confidence, notes]):
        row["reviewed_at"] = utc_now_iso()
    st.session_state.answers[case_id] = row
    st.session_state.dirty = True
    return row


def persist_all(case_order: list[str]) -> None:
    save_answers(ANSWERS_PATH, st.session_state.answers, case_order)
    st.session_state.dirty = False
    st.session_state.last_saved_at = utc_now_iso()


def main() -> None:
    st.set_page_config(
        page_title="VeriSec Forge · Pair Annotation",
        page_icon="🔎",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(
        """
        <style>
          .block-container { padding-top: 1.2rem; padding-bottom: 2rem; }
          div[data-testid="stHorizontalBlock"] code {
            font-size: 0.78rem;
            line-height: 1.35;
          }
          .status-pill {
            display: inline-block;
            padding: 0.15rem 0.55rem;
            border-radius: 999px;
            font-size: 0.85rem;
            font-weight: 600;
            margin-right: 0.35rem;
          }
          .pill-ok { background: #d9efe4; color: #1f7a5a; }
          .pill-todo { background: #f3e6c8; color: #8a5a12; }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if not PACKET_PATH.exists():
        st.error(
            f"Packet not found: `{PACKET_PATH}`\n\n"
            "Build the study first:\n\n"
            "`python scripts/build_pair_annotation_study.py --sample-size 50 --seed 20260720 --mode single_author`"
        )
        st.stop()

    packets = load_jsonl(PACKET_PATH)
    if not packets:
        st.error("Packet file is empty.")
        st.stop()

    case_order = [str(row["case_id"]) for row in packets]
    answers = load_answers(ANSWERS_PATH, case_order)
    init_state(packets, answers)

    # Clamp index.
    st.session_state.case_index = max(0, min(st.session_state.case_index, len(packets) - 1))
    idx = st.session_state.case_index
    case = packets[idx]
    case_id = str(case["case_id"])

    if st.session_state.loaded_case_id != case_id:
        hydrate_form_from_answer(case_id)

    complete_n = sum(1 for cid in case_order if is_complete(st.session_state.answers.get(cid, {})))
    progress = complete_n / len(case_order)

    # ----- Sidebar -----
    with st.sidebar:
        st.title("Pair annotation")
        st.caption("Single-author study · n=50 · blinded packets")
        st.progress(progress, text=f"Complete {complete_n} / {len(case_order)}")
        st.metric("Current case", f"{idx + 1} / {len(case_order)}")
        if st.session_state.last_saved_at:
            st.caption(f"Last saved: {st.session_state.last_saved_at}")
        elif st.session_state.dirty:
            st.caption("Unsaved changes in session")
        else:
            st.caption("No save yet this session")

        st.divider()
        st.markdown("**Instructions**")
        st.markdown(
            """
1. Read **Side A** and **Side B** (diff recommended).
2. Choose the **vulnerable** side (candidate-identity task).
3. Write a short root cause and minimal evidence spans  
   (e.g. `A:12-15;B:8`).
4. Set context sufficiency and confidence.
5. Use **Save** or **Previous/Next** (auto-saves).

**Do not** open `private_case_mapping.jsonl` or look up CVEs while labeling.  
**Do not** use AI to fill labels.
            """
        )
        st.divider()
        st.markdown("**Claim boundary**")
        st.caption(
            "Author audit labels ≠ dual-rater gold ≠ AI pilot. "
            "Not a prevalence estimate or model-quality benchmark."
        )
        st.divider()
        jump = st.number_input(
            "Jump to case #",
            min_value=1,
            max_value=len(packets),
            value=idx + 1,
            step=1,
        )
        if st.button("Go", use_container_width=True):
            capture_form_to_answers(case_id)
            persist_all(case_order)
            st.session_state.case_index = int(jump) - 1
            st.session_state.loaded_case_id = None
            st.rerun()

        st.divider()
        st.caption(f"Packet: `{PACKET_PATH.relative_to(ROOT).as_posix()}`")
        st.caption(f"Answers: `{ANSWERS_PATH.relative_to(ROOT).as_posix()}`")

    # ----- Header -----
    status = is_complete(st.session_state.answers.get(case_id, {}))
    pill = (
        '<span class="status-pill pill-ok">complete</span>'
        if status
        else '<span class="status-pill pill-todo">incomplete</span>'
    )
    st.markdown(f"## {case_id} {pill}", unsafe_allow_html=True)
    st.caption(
        "Task: decide which side is the **vulnerable** version. "
        "Metadata (project/CVE/CWE) is scrubbed from the packet."
    )

    view_mode = st.radio("Display", VIEW_MODES, horizontal=True, index=0)

    left, right = st.columns(2, gap="medium")
    with left:
        side_panel("Side A", case.get("side_a") or {}, view_mode)
    with right:
        side_panel("Side B", case.get("side_b") or {}, view_mode)

    st.divider()
    st.subheader("Your labels")

    c1, c2 = st.columns(2)
    with c1:
        st.selectbox(
            "Vulnerable side",
            options=SIDE_OPTIONS,
            key="form_vulnerable_side",
            help="A or B = that side is vulnerable; neither/unclear when appropriate.",
        )
        st.selectbox(
            "Context sufficient",
            options=CONTEXT_OPTIONS,
            key="form_context_sufficient",
            help="Is the provided code/diff enough to decide?",
        )
        st.selectbox(
            "Confidence",
            options=CONFIDENCE_OPTIONS,
            key="form_confidence",
            help="Leave as (unset) until you have a real rating — empty is not stored as 3.",
        )
    with c2:
        st.text_input(
            "Minimal evidence lines",
            key="form_minimal_evidence_lines",
            placeholder="A:12-15;B:8",
            help="Smallest side-prefixed spans that support your decision.",
        )
        st.text_area(
            "Root cause",
            key="form_root_cause",
            height=100,
            placeholder="Concise security mechanism (e.g. missing bounds check on length).",
        )
        st.text_area(
            "Notes (optional)",
            key="form_notes",
            height=80,
            placeholder="Ambiguity, missing context, etc.",
        )

    nav_l, nav_m, nav_r = st.columns([1, 1, 1])
    with nav_l:
        prev_clicked = st.button("← Previous", use_container_width=True, disabled=idx <= 0)
    with nav_m:
        save_clicked = st.button("💾 Save", use_container_width=True, type="primary")
    with nav_r:
        next_clicked = st.button("Next →", use_container_width=True, disabled=idx >= len(packets) - 1)

    if save_clicked:
        capture_form_to_answers(case_id)
        persist_all(case_order)
        st.success(f"Saved {case_id} → {ANSWERS_PATH.name}")
        st.rerun()

    if prev_clicked:
        capture_form_to_answers(case_id)
        persist_all(case_order)
        st.session_state.case_index = idx - 1
        st.session_state.loaded_case_id = None
        st.rerun()

    if next_clicked:
        capture_form_to_answers(case_id)
        persist_all(case_order)
        st.session_state.case_index = idx + 1
        st.session_state.loaded_case_id = None
        st.rerun()

    # Keep session answers aligned with widgets even without navigation (auto-save buffer).
    capture_form_to_answers(case_id, touch_reviewed_at=False)

    with st.expander("Keyboard-friendly tips"):
        st.markdown(
            """
- Prefer **Diff** view first; switch to **Code** if the hunk is hard to parse.
- Evidence format: `A:12-15;B:8` (side-prefixed).
- Use **unclear** / **context insufficient** rather than guessing.
- Progress is written to CSV on **Save**, **Previous**, **Next**, and **Go**.
            """
        )


if __name__ == "__main__":
    main()
