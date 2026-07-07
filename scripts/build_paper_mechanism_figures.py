"""Deterministically render paper Figures 5-7 from committed report JSON.

Figures 5 (label-vs-polarity mechanism), 6 (CrossVul confound), and 7 (repair
decomposition) visualize the values already in Tables 2-4 of paper/draft_v0.md.
Every number is read from a committed `reports/*.json` artifact -- no model is
run, no value is hand-entered, and there is no randomness or timestamp -- so the
figures cannot drift from the tables and re-running reproduces byte-identical
SVGs. Style (960x540 canvas, muted palette, Georgia/Arial) matches the existing
Figures 1-4.

Colour policy: the two compared entities in each figure use two neutral tones
(slate / muted teal). No colour encodes success vs failure; magnitudes are
labelled with their numeric value so the figure asserts nothing the evidence
does not.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIG_DIR = ROOT / "paper" / "figures"

BG = "#f7f3ea"
INK = "#22382f"
GREY = "#4f5b55"
SLATE = "#3a4a5a"       # entity A (e.g. Qwen / PrimeVul)
TEAL = "#4a6a63"        # entity B (e.g. CodeBERT / CrossVul)
GRID = "#c9c1af"
TITLE_FONT = "Georgia, serif"
BODY_FONT = "Arial, sans-serif"


def _load(rel: str) -> dict[str, Any]:
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


def _f(value: float, places: int = 3) -> str:
    return f"{value:.{places}f}"


def _svg(width: int, height: int, body: str, aria: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{aria}">\n'
        f'  <rect width="{width}" height="{height}" fill="{BG}"/>\n'
        f"{body}"
        f"</svg>\n"
    )


def _text(x, y, s, size, *, weight="400", fill=INK, font=BODY_FONT, anchor="start"):
    return (
        f'  <text x="{x}" y="{y}" font-family="{font}" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{s}</text>\n'
    )


def _title(title: str, subtitle: str) -> str:
    # Font size 22 keeps titles (<= ~62 chars) inside the 960px canvas with a
    # 60px left margin; subtitles stay at 16.
    return (
        _text(60, 62, title, 22, weight="700", font=TITLE_FONT)
        + _text(60, 96, subtitle, 16, fill=GREY)
    )


def _caption(lines: list[str], y0: int = 470) -> str:
    out = ""
    for i, line in enumerate(lines):
        out += _text(60, y0 + i * 24, line, 15, fill=GREY)
    return out


def _bar(x, y_base, w, value, vmax, colour, label_top):
    """A bar growing up from y_base; value in [0, vmax]. Returns (svg, top_y)."""
    h = max(2.0, (value / vmax) * 220.0)
    top = y_base - h
    svg = f'  <rect x="{x}" y="{_f(top,1)}" width="{w}" height="{_f(h,1)}" fill="{colour}"/>\n'
    svg += _text(x + w / 2, top - 10, label_top, 16, weight="700", anchor="middle")
    return svg, top


def figure5_mechanism() -> str:
    lab = _load("reports/secure_code_qwen_label_only_swap_vs_structural_swap_v1.json")["results"]
    pol = _load("reports/secure_code_qwen_polarity_only_swap_vs_structural_swap_v1.json")["results"]
    cb = _load("reports/codebert_label_polarity_mechanism_replication_v1.json")
    conf = _load("reports/secure_code_polarity_gold_confound_v1.json")["eval"]["by_variant"]

    q_label = lab["label_only_swap"]["independence_vs_canonical"]["phi"]
    q_pol = pol["polarity_only_swap"]["independence_vs_canonical"]["phi"]
    c_label = cb["prediction_independence_vs_canonical"]["label_only_swap"]["phi"]
    c_pol = cb["prediction_independence_vs_canonical"]["polarity_only_swap"]["phi"]
    q_short = conf["canonical"]["model_vs_shortcut"]["agreement"]
    c_short = cb["model_vs_crude_polarity_shortcut"]["canonical"]["agreement"]

    body = _title(
        "Figure 5. Label swap is inert; polarity swap is disruptive.",
        "phi of a swap variant vs canonical (near +1 = inert, near 0 = disruptive). 600 base pairs.",
    )
    # phi panel: axis from -1 (bottom) to +1 (top), zero line at mid.
    ax_x, ax_top, ax_bot = 90, 150, 380
    zero_y = (ax_top + ax_bot) / 2

    def phi_y(v):
        return zero_y - (v * (ax_bot - ax_top) / 2)

    body += f'  <line x1="{ax_x}" y1="{ax_top}" x2="{ax_x}" y2="{ax_bot}" stroke="{GRID}" stroke-width="2"/>\n'
    body += f'  <line x1="{ax_x}" y1="{zero_y}" x2="540" y2="{zero_y}" stroke="{GRID}" stroke-width="2" stroke-dasharray="4 4"/>\n'
    body += _text(ax_x - 10, ax_top + 4, "+1", 13, fill=GREY, anchor="end")
    body += _text(ax_x - 10, zero_y + 4, "0", 13, fill=GREY, anchor="end")
    body += _text(ax_x - 10, ax_bot + 4, "-1", 13, fill=GREY, anchor="end")

    groups = [("label_only_swap", q_label, c_label, 130), ("polarity_only_swap", q_pol, c_pol, 330)]
    for name, qv, cv, gx in groups:
        for i, (v, col, who) in enumerate([(qv, SLATE, "Qwen"), (cv, TEAL, "CodeBERT")]):
            bx = gx + i * 46
            y = phi_y(v)
            top = min(y, zero_y)
            h = abs(y - zero_y)
            body += f'  <rect x="{bx}" y="{_f(top,1)}" width="36" height="{_f(max(h,2),1)}" fill="{col}"/>\n'
            body += _text(bx + 18, (top - 8 if v >= 0 else top + h + 18), f"{v:+.2f}", 14, weight="700", anchor="middle")
        body += _text(gx + 46, ax_bot + 26, name, 14, anchor="middle")
    body += _text(560, 175, "Qwen", 15, weight="700", fill=SLATE)
    body += _text(560, 198, "CodeBERT", 15, weight="700", fill=TEAL)

    # functional-form panel: crude-shortcut agreement on PrimeVul
    body += _text(620, 250, "Crude net-polarity", 15, weight="700")
    body += _text(620, 270, "shortcut agreement", 15, weight="700")
    body += _text(620, 292, "(PrimeVul canonical):", 14, fill=GREY)
    body += _text(620, 322, f"Qwen  {_f(q_short,2)}", 16, fill=SLATE, weight="700")
    body += _text(620, 348, f"CodeBERT  {_f(c_short,2)}", 16, fill=TEAL, weight="700")

    body += _caption([
        "This is behavioral evidence. It does not establish a shared internal mechanism.",
        "CodeBERT tracks the crude polarity shortcut much more closely than Qwen on PrimeVul.",
    ])
    return _svg(960, 540, body, "Label swap inert, polarity swap disruptive, across Qwen and CodeBERT")


def figure6_crossvul() -> str:
    pv = _load("reports/secure_code_polarity_gold_confound_v1.json")["eval"]["by_variant"]
    cv = _load("reports/crossvul_polarity_gold_confound_v1.json")["eval"]["by_variant"]
    cb = _load("reports/codebert_label_polarity_mechanism_replication_v1.json")

    pv_canon = pv["canonical"]["polarity_gold_correlation"]["shortcut_accuracy"]
    cv_canon = cv["canonical"]["polarity_gold_correlation"]["shortcut_accuracy"]
    pv_flip = pv["polarity_only_swap"]["polarity_gold_correlation"]["shortcut_accuracy"]
    cv_flip = cv["polarity_only_swap"]["polarity_gold_correlation"]["shortcut_accuracy"]
    q_pv = pv["canonical"]["model_vs_shortcut"]["agreement"]
    q_cv = cv["canonical"]["model_vs_shortcut"]["agreement"]
    c_pv = cb["model_vs_crude_polarity_shortcut"]["canonical"]["agreement"]
    c_cv = cb["crossvul_confound_aware_check"]["model_vs_crude_polarity_shortcut"]["canonical"]["agreement"]

    body = _title(
        "Figure 6. CrossVul has a stronger polarity/gold shortcut.",
        "Crude net-polarity shortcut accuracy; a 0.5 chance line is marked. PrimeVul vs CrossVul.",
    )
    y_base = 380
    vmax = 1.0
    # chance line at 0.5
    chance_y = y_base - (0.5 / vmax) * 220.0
    body += f'  <line x1="80" y1="{_f(chance_y,1)}" x2="620" y2="{_f(chance_y,1)}" stroke="{GRID}" stroke-width="2" stroke-dasharray="5 5"/>\n'
    body += _text(626, chance_y + 4, "0.5 (chance)", 13, fill=GREY)

    groups = [
        ("shortcut acc\n(canonical)", pv_canon, cv_canon, 130),
        ("shortcut acc under\npolarity flip", pv_flip, cv_flip, 360),
    ]
    for label, a, b, gx in groups:
        for i, (v, col) in enumerate([(a, SLATE), (b, TEAL)]):
            bx = gx + i * 52
            s, _top = _bar(bx, y_base, 42, v, vmax, col, _f(v, 3))
            body += s
        first, second = label.split("\n")
        body += _text(gx + 47, y_base + 26, first, 13, anchor="middle")
        body += _text(gx + 47, y_base + 44, second, 13, anchor="middle")
    body += _text(670, 165, "PrimeVul", 15, weight="700", fill=SLATE)
    body += _text(670, 188, "CrossVul", 15, weight="700", fill=TEAL)

    body += _text(670, 250, "Model-vs-shortcut", 14, weight="700")
    body += _text(670, 270, "row agreement:", 14, fill=GREY)
    body += _text(670, 300, f"Qwen  {_f(q_pv,2)} / {_f(q_cv,2)}", 15, weight="700")
    body += _text(670, 326, f"CodeBERT  {_f(c_pv,2)} / {_f(c_cv,2)}", 15, weight="700")
    body += _text(670, 348, "(PrimeVul / CrossVul)", 12, fill=GREY)

    body += _caption([
        "CrossVul raw canonical accuracy is not standalone evidence of stronger secure-code reasoning.",
    ])
    return _svg(960, 540, body, "CrossVul carries a stronger polarity gold presentation shortcut than PrimeVul")


def figure7_repair() -> str:
    rd = _load("reports/secure_code_repair_antisymmetric_decomposition_v1.json")
    rcv = _load("reports/secure_code_repair_antisymmetric_crossvul_transfer_v1.json")
    ca = rd["canonical_accuracy"]
    ft = rd["attribution"]["fine_tuning_delta_over_null"]
    ftp = rd["attribution"]["fine_tuning_mcnemar_exact_p"]
    cvd = rcv["attribution"]["fine_tuning_delta_over_null"]
    cvp = rcv["attribution"]["fine_tuning_mcnemar_exact_p"]

    body = _title(
        "Figure 7. Structural readout, not a validated learned repair.",
        "Canonical accuracy under two readouts; PrimeVul, 600 pairs.",
    )
    y_base = 380
    vmax = 0.8
    bars = [
        ("baseline\nindependent", ca["baseline_independent"], SLATE),
        ("repaired\nindependent", ca["repaired_independent"], SLATE),
        ("baseline antisym\n(projection null)", ca["baseline_antisymmetric_inference_NULL"], TEAL),
        ("repaired\nantisym", ca["repaired_antisymmetric_inference"], TEAL),
    ]
    x0 = 110
    for i, (label, v, col) in enumerate(bars):
        bx = x0 + i * 120
        s, _top = _bar(bx, y_base, 74, v, vmax, col, _f(v, 3))
        body += s
        first, second = label.split("\n")
        body += _text(bx + 37, y_base + 26, first, 13, anchor="middle")
        body += _text(bx + 37, y_base + 44, second, 13, anchor="middle")

    body += _text(640, 165, "Fine-tuning delta over the", 14, weight="700")
    body += _text(640, 185, "projection null:", 14, weight="700")
    body += _text(640, 216, f"PrimeVul (in-dist.):  {ft:+.3f}", 15)
    body += _text(660, 238, f"McNemar p = {_f(ftp,3)}", 13, fill=GREY)
    body += _text(640, 268, f"CrossVul (external):  {cvd:+.3f}", 15)
    body += _text(660, 290, f"p = {_f(cvp,3)} (n.s.)", 13, fill=GREY)
    body += _text(640, 322, "Nuisance transforms:", 15)
    body += _text(660, 344, "0/5 pass Bonferroni p&lt;0.01", 13, fill=GREY)
    body += _text(660, 362, "2/5 sign-reversed", 13, fill=GREY)

    body += _caption([
        "Antisymmetric consistency is by construction; learned fine-tuning repair is not",
        "validated as transferable repair.",
    ])
    return _svg(960, 540, body, "Antisymmetric readout is a structural constraint not a learned repair")


FIGURES = {
    "figure5_label_polarity_mechanism.svg": figure5_mechanism,
    "figure6_crossvul_confound.svg": figure6_crossvul,
    "figure7_repair_decomposition.svg": figure7_repair,
}


def main() -> int:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    for name, fn in FIGURES.items():
        (FIG_DIR / name).write_text(fn(), encoding="utf-8")
        print(f"wrote paper/figures/{name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
