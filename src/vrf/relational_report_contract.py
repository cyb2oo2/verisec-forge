"""Admission contract for new relational report builders.

A builder that emits a relational claim must attach all four of:

(a) the strongest semantics-free control on the same pairs
(b) independent (per-rendering) *and* projected (antisymmetric) metrics
(c) both glyph and prose families
(d) the exact-mirror rejection table from the suite summary

Only the purified v4/v5 suites are admissible. Missing any piece is a hard
error: the builder must not emit a result.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from vrf.artifact_guard import require_artifact
from vrf.pair_decision import ADMISSIBLE_SUITE_VERSIONS

REQUIRED_FAMILIES = ("glyph", "prose")
REQUIRED_INDEPENDENT_KEYS = (
    "independent_canonical_accuracy",
    "independent_both_correct",
    "side_swap_equivariance",
)
REQUIRED_PROJECTED_KEYS = ("antisym_accuracy",)
REQUIRED_CONTROL_KEYS = ("control_accuracy",)


class RelationalReportContractError(ValueError):
    """Raised when a relational report is missing a required attachment."""


def suite_version_from_summary(summary: Mapping[str, Any]) -> str:
    version = str(summary.get("benchmark_version") or "").strip()
    if version not in ADMISSIBLE_SUITE_VERSIONS:
        raise RelationalReportContractError(
            f"suite is not admissible: benchmark_version={version!r}; "
            f"only {sorted(ADMISSIBLE_SUITE_VERSIONS)} are allowed"
        )
    return version


def exact_mirror_rejection_table(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Per-source exact-mirror rejection rates from a v4/v5 suite summary."""

    sources = summary.get("sources")
    if not isinstance(sources, dict) or not sources:
        raise RelationalReportContractError(
            "suite summary is missing sources[]; cannot attach the exact-mirror "
            "rejection table"
        )
    table: dict[str, Any] = {}
    for name, block in sources.items():
        if not isinstance(block, Mapping):
            raise RelationalReportContractError(
                f"suite summary source {name!r} is not an object"
            )
        required = (
            "eligible_pairs",
            "rejected_non_mirror_pairs",
            "non_mirror_rejection_rate",
        )
        missing = [key for key in required if key not in block]
        if missing:
            raise RelationalReportContractError(
                f"suite summary source {name!r} missing {missing}"
            )
        ingestion = block.get("ingestion") or {}
        table[name] = {
            "pairs_seen": ingestion.get("pairs_seen", block.get("pairs_seen")),
            "single_line_pairs": ingestion.get("single_line_pairs"),
            "single_line_rate": ingestion.get("single_line_rate"),
            "eligible_pairs": block["eligible_pairs"],
            "rejected_non_mirror_pairs": block["rejected_non_mirror_pairs"],
            "non_mirror_rejection_rate": block["non_mirror_rejection_rate"],
            "sampled_pairs": block.get("sampled_pairs"),
        }
    return {
        "invariant": "swap_mirror_is_exact enforced at load; non-mirror pairs rejected",
        "sources": table,
    }


def load_admissible_suite_summary(path: str | Path) -> dict[str, Any]:
    import json

    resolved = require_artifact(
        path,
        produced_by="scripts/build_relational_benchmark_v4.py or scripts/build_relational_benchmark_v5.py",
        purpose="exact-mirror rejection table and suite admission",
    )
    summary = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(summary, dict):
        raise RelationalReportContractError(f"{path} is not a JSON object")
    suite_version_from_summary(summary)
    exact_mirror_rejection_table(summary)
    return summary


def require_relational_report_contract(payload: Mapping[str, Any]) -> None:
    """Fail if a report payload is missing any required attachment."""

    version = payload.get("suite_version") or payload.get("benchmark_version")
    if str(version) not in ADMISSIBLE_SUITE_VERSIONS:
        raise RelationalReportContractError(
            f"report is missing an admissible suite_version (got {version!r})"
        )

    rejection = payload.get("exact_mirror_rejection")
    if not isinstance(rejection, Mapping) or "sources" not in rejection:
        raise RelationalReportContractError(
            "report is missing exact_mirror_rejection.sources"
        )
    if not rejection["sources"]:
        raise RelationalReportContractError("exact_mirror_rejection.sources is empty")

    families = payload.get("families")
    if not isinstance(families, Mapping):
        raise RelationalReportContractError("report is missing families{}")
    missing_families = [name for name in REQUIRED_FAMILIES if name not in families]
    if missing_families:
        raise RelationalReportContractError(
            f"report is missing rendering families: {missing_families}"
        )

    systems = payload.get("systems")
    if not isinstance(systems, Mapping) or not systems:
        raise RelationalReportContractError("report is missing systems{}")

    for family in REQUIRED_FAMILIES:
        block = families[family]
        if not isinstance(block, Mapping):
            raise RelationalReportContractError(f"families[{family!r}] is not an object")
        control = block.get("strongest_control")
        if not isinstance(control, Mapping) and "control_accuracy" not in block:
            raise RelationalReportContractError(
                f"families[{family!r}] is missing the strongest semantics-free control"
            )
        if isinstance(control, Mapping) and "control_accuracy" not in control and "control_accuracy" not in block:
            raise RelationalReportContractError(
                f"families[{family!r}].strongest_control is missing control_accuracy"
            )

    for label, system in systems.items():
        if not isinstance(system, Mapping):
            raise RelationalReportContractError(f"systems[{label!r}] is not an object")
        by_family = system.get("families") or system.get("slices")
        if not isinstance(by_family, Mapping):
            raise RelationalReportContractError(
                f"systems[{label!r}] is missing families{{}} / slices{{}}"
            )
        present = set(by_family)
        if not set(REQUIRED_FAMILIES) <= present:
            # Some payloads nest family -> slice. Accept either.
            if not set(REQUIRED_FAMILIES) <= set(system.get("families") or {}):
                raise RelationalReportContractError(
                    f"systems[{label!r}] is missing glyph/prose attachments "
                    f"(have {sorted(present)})"
                )
        family_map = system.get("families") or {}
        if not family_map:
            continue
        for family in REQUIRED_FAMILIES:
            family_block = family_map[family]
            _require_system_family(family_block, where=f"systems[{label}].families[{family}]")


def _require_metric_block(
    block: Mapping[str, Any], *, where: str, projected: bool
) -> None:
    needed = list(REQUIRED_INDEPENDENT_KEYS) + list(REQUIRED_CONTROL_KEYS)
    if projected:
        needed.extend(REQUIRED_PROJECTED_KEYS)
    missing = [key for key in needed if key not in block]
    if missing:
        raise RelationalReportContractError(f"{where} missing {missing}")


def _require_system_family(block: Mapping[str, Any], *, where: str) -> None:
    # A family block is either a metric dict or a dict of slices that each
    # carry the metrics.
    if any(key in block for key in REQUIRED_INDEPENDENT_KEYS):
        _require_metric_block(block, where=where, projected=True)
        return
    slices = block.get("slices") or {
        name: value
        for name, value in block.items()
        if isinstance(value, Mapping)
        and any(key in value for key in REQUIRED_INDEPENDENT_KEYS)
    }
    if not slices:
        raise RelationalReportContractError(
            f"{where} has neither metric keys nor slices with independent/projected metrics"
        )
    for slice_name, slice_block in slices.items():
        if not isinstance(slice_block, Mapping):
            continue
        if any(key in slice_block for key in REQUIRED_INDEPENDENT_KEYS):
            _require_metric_block(
                slice_block, where=f"{where}.slices[{slice_name}]", projected=True
            )
        else:
            for cell_name, cell_block in slice_block.items():
                if isinstance(cell_block, Mapping) and any(
                    key in cell_block for key in REQUIRED_INDEPENDENT_KEYS
                ):
                    _require_metric_block(
                        cell_block,
                        where=f"{where}.slices[{slice_name}][{cell_name}]",
                        projected=True,
                    )
