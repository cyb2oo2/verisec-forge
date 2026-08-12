"""Build the bounded, report-backed synthesis of current training controls."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vrf.current_training_synthesis import (  # noqa: E402
    build_current_training_synthesis,
    render_current_training_markdown,
)
from vrf.io_utils import read_json  # noqa: E402
from vrf.reproducibility import capture_artifact_provenance  # noqa: E402

MATCHED_SOURCES = {
    "Qwen2.5-Coder-1.5B bf16": "reports/veripatch_rr_4ep_qwen15b_seed_replication.json",
    "Qwen2.5-Coder-7B nf4": "reports/veripatch_rr_4ep_qwen7b_seed_replication.json",
    "Qwen2.5-Coder-3B bf16": "reports/veripatch_rr_4ep_seed_replication.json",
}
SUPPLY_SOURCES = {
    "v1 balanced (2,208 pairs)": "reports/veripatch_rr_4ep_seed_replication.json",
    "v2 decontaminated (2,164 pairs)": "reports/veripatch_rr_decon_v2_seed_replication.json",
    "v3 mined (3,160 pairs)": "reports/veripatch_rr_mined_v3_seed_replication.json",
}
CONFIGS = [
    "configs/research_polarity_balanced_scaled_4ep_qwen15b_seed7_v1.json",
    "configs/research_polarity_balanced_scaled_4ep_qwen15b_seed123_v1.json",
    "configs/research_polarity_balanced_scaled_4ep_qwen7b_seed7_v1.json",
    "configs/research_polarity_balanced_scaled_4ep_qwen7b_seed123_v1.json",
    "configs/research_polarity_balanced_scaled_4ep_qwen3b_v1.json",
    "configs/research_polarity_balanced_scaled_4ep_qwen3b_seed123_v1.json",
    "configs/research_polarity_balanced_decontaminated_v2_4ep_qwen3b_seed7_v1.json",
    "configs/research_polarity_balanced_decontaminated_v2_4ep_qwen3b_seed123_v1.json",
    "configs/research_polarity_balanced_mined_v3_4ep_qwen3b_seed7_v1.json",
    "configs/research_polarity_balanced_mined_v3_4ep_qwen3b_seed123_v1.json",
]
CODE = [
    "scripts/build_current_training_synthesis.py",
    "src/vrf/current_training_synthesis.py",
    "src/vrf/reproducibility.py",
]
JSON_OUTPUT = "reports/current_shortcut_resistant_training_synthesis_v1.json"
MARKDOWN_OUTPUT = "reports/CURRENT_SHORTCUT_RESISTANT_TRAINING_SYNTHESIS.md"


def build() -> tuple[dict, str]:
    payload = build_current_training_synthesis(
        matched_compute_payloads={
            name: read_json(ROOT / path) for name, path in MATCHED_SOURCES.items()
        },
        supply_payloads={
            name: read_json(ROOT / path) for name, path in SUPPLY_SOURCES.items()
        },
    )
    source_paths = list(dict.fromkeys([*MATCHED_SOURCES.values(), *SUPPLY_SOURCES.values()]))
    payload["provenance"] = capture_artifact_provenance(
        ROOT,
        source_paths=source_paths,
        config_paths=CONFIGS,
        code_paths=CODE,
    )
    return payload, render_current_training_markdown(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if checked-in outputs are stale")
    args = parser.parse_args()
    payload, markdown = build()

    if args.check:
        actual_payload = read_json(ROOT / JSON_OUTPUT)
        actual_markdown = (ROOT / MARKDOWN_OUTPUT).read_text(encoding="utf-8")
        expected_provenance = payload.pop("provenance")
        actual_provenance = actual_payload.pop("provenance", {})
        stable_provenance_fields = ("sources", "configs", "code")
        provenance_matches = all(
            actual_provenance.get(field) == expected_provenance.get(field)
            for field in stable_provenance_fields
        )
        if actual_payload != payload or not provenance_matches or actual_markdown != markdown:
            print("STALE: current training synthesis outputs need regeneration", file=sys.stderr)
            return 1
        print("OK: current training synthesis outputs match retained sources")
        return 0

    json_path = ROOT / JSON_OUTPUT
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    with (ROOT / MARKDOWN_OUTPUT).open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(markdown)
    print(f"wrote {JSON_OUTPUT} and {MARKDOWN_OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
