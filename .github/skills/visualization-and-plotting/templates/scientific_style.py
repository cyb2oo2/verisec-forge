"""Shared matplotlib defaults for VeriSec Forge publication figures.

Usage:
    from scientific_style import apply_style
    apply_style()

Design goals: colorblind-safe, grayscale-legible, print-sized, reproducible.
"""
from __future__ import annotations

import matplotlib as mpl

# Colorblind-safe qualitative palette (Wong 2011). Distinguish series by color
# AND marker/linestyle so figures survive grayscale printing.
WONG_PALETTE = [
    "#000000",  # black
    "#E69F00",  # orange
    "#56B4E9",  # sky blue
    "#009E73",  # bluish green
    "#F0E442",  # yellow
    "#0072B2",  # blue
    "#D55E00",  # vermillion
    "#CC79A7",  # reddish purple
]

MARKERS = ["o", "s", "^", "D", "v", "P", "X", "*"]


def apply_style() -> None:
    mpl.rcParams.update({
        "figure.figsize": (3.4, 2.6),   # single-column width (inches)
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "font.size": 9,
        "axes.titlesize": 9,
        "axes.labelsize": 9,
        "legend.fontsize": 8,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.alpha": 0.3,
        "lines.linewidth": 1.4,
        "lines.markersize": 4,
        "errorbar.capsize": 3,
        "axes.prop_cycle": mpl.cycler(color=WONG_PALETTE),
        "svg.fonttype": "none",         # keep text editable in SVG
    })
