# Example prompt: publication figure with CI

```text
Use the visualization-and-plotting skill.

Create a single-column figure for paper/figures/ from the pair-coupled
multi-split results artifact. Requirements:
- Read values from the registered JSON/JSONL — no hardcoded literals.
- Plot mean BA with 95% CI error bars; annotate n / seeds in caption.
- Colorblind-safe + distinct markers (grayscale-safe).
- Export editable SVG and PNG at ≥300 dpi.
- Caption must match the bounded claim (system layer, not open-set discovery).
```
