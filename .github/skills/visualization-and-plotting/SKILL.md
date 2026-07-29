---
name: visualization-and-plotting
description: >-
  Produce publication-quality, reproducible scientific figures (matplotlib) and
  editable SVG for the paper. Use when creating or editing plots, choosing
  colors/axes, showing confidence intervals, or exporting figures for paper/.
  Triggers: plot, figure, chart, matplotlib, SVG, axis, colorbar, error bars,
  confidence interval, publication figure, colorblind, dpi.
---

# Visualization and Plotting

Create figures that are **honest, reproducible, and paper-ready**: every figure
is regenerable from a script + a checked-in data artifact, shows uncertainty,
and reads clearly in grayscale.

> Before writing chart code, if a richer design system is warranted (dashboards,
> multi-series palettes, HTML/React output), also consult the `dataviz` skill.
> This SKILL covers static scientific figures for the paper.

## When to Use

- Making/editing a figure for `paper/` or a `reports/` artifact.
- Plotting metrics with confidence intervals, ablation curves, or distributions.
- Exporting editable SVG or high-DPI raster for publication.

## Instructions

### 1. Regenerable, not hand-drawn
- A figure = a script in `scripts/` (or a `paper/` figure source) + a data file.
  Never paste numbers into a plotting call; read them from the JSON/JSONL artifact
  that a registered experiment produced.
- Save the figure next to a note of the source data + git commit.

### 2. Always show uncertainty
- This project reports CIs everywhere. Plot error bars / CI bands (bootstrap 95%
  where the report uses them). A bare point estimate is not acceptable.

### 3. Style for print and accessibility
- Colorblind-safe palette; distinguish series by BOTH color and marker/linestyle
  so the figure survives grayscale.
- Readable font sizes (≥ 9pt at final column width), labeled axes with units,
  minimal chartjunk, no unexplained truncated y-axes.
- Use the shared defaults in `templates/scientific_style.py`.

### 4. Export cleanly
- Prefer **editable SVG** for the paper (the repo keeps editable SVG in `paper/`);
  also export a high-DPI PNG (≥300 dpi) for previews. Keep the generating script.

### 5. Caption discipline
- The caption states the takeaway AND the sample size / seeds / CI method, so the
  figure is self-contained and matches the anchored claim.

## Best Practices & Guardrails

- **Do** read plotted values from registered artifacts, not literals.
- **Do** annotate n / seeds / CI method in-figure or in the caption.
- **Don't** use rainbow/jet colormaps or red-green-only encodings.
- **Don't** truncate axes to exaggerate an effect; if you must, mark the break.
- **Don't** commit only a raster; keep the editable source + script.

## Examples

```python
import matplotlib.pyplot as plt
from templates.scientific_style import apply_style  # see this skill's templates/
import json, pathlib

apply_style()
rows = json.loads(pathlib.Path("reports/secure_code_primevul_pair_annotation_agreement_v1.json").read_text())
# ... plot means with yerr = 95% CI half-width, distinct markers per series ...
fig, ax = plt.subplots(figsize=(3.4, 2.6))  # single-column width
ax.errorbar(x, mean, yerr=ci_halfwidth, marker="o", linestyle="-", capsize=3)
ax.set_xlabel("split"); ax.set_ylabel("balanced accuracy")
fig.savefig("paper/figures/pair_coupled_ba.svg")   # editable
fig.savefig("paper/figures/pair_coupled_ba.png", dpi=300)
```

## Dependencies / Tools

- `matplotlib` (add to `.[dev]` or a plotting extra); optional `numpy`
- Editable SVG output for `paper/`; PNG ≥300 dpi for previews
- `templates/scientific_style.py` (shared rc defaults)
- Related skills: [[scientific-paper-assistant]], [[research-experiment-manager]], `dataviz` (design system)
