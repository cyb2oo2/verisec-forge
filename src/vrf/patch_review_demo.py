from __future__ import annotations

from pathlib import Path
from typing import Any

from vrf.io_utils import read_jsonl


DEFAULT_DATASET_PATH = "data/processed/secure_code_primevul_pair_diff_only_eval_balanced_1800_dedup_metadata.jsonl"
DEFAULT_PREDICTIONS_PATH = "outputs/secure_code_primevul_pair_coupled_router_v1_predictions.jsonl"
DEFAULT_EVIDENCE_PATH = "outputs/secure_code_primevul_pair_evidence_localization_v1.jsonl"


def _side_label(value: int | bool | str | None) -> str:
    return "vulnerable" if int(bool(value)) else "safe"


def _shorten(text: object, *, limit: int) -> str:
    if text is None:
        return ""
    value = str(text).replace("\r\n", "\n")
    if len(value) <= limit:
        return value
    return value[: limit - 3].rstrip() + "..."


def _load_jsonl_by_id(path: str | Path) -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in read_jsonl(path)}


def _load_dataset_by_pair(path: str | Path) -> dict[str, list[dict[str, Any]]]:
    pairs: dict[str, list[dict[str, Any]]] = {}
    for row in read_jsonl(path):
        pair_key = str(row.get("pair_key") or row["id"])
        pairs.setdefault(pair_key, []).append(row)
    return pairs


def list_demo_examples(
    dataset_path: str | Path = DEFAULT_DATASET_PATH,
    *,
    limit: int = 5,
) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    for pair_key, rows in _load_dataset_by_pair(dataset_path).items():
        first = rows[0]
        examples.append(
            {
                "pair_key": pair_key,
                "ids": [row["id"] for row in rows],
                "project": first.get("project", "unknown"),
                "cve": first.get("cve", "unknown"),
                "vulnerability_type": first.get("vulnerability_type", "unknown"),
            }
        )
        if len(examples) >= limit:
            break
    return examples


def _select_pair(
    pairs: dict[str, list[dict[str, Any]]],
    *,
    sample_id: str | None,
    pair_key: str | None,
) -> tuple[str, list[dict[str, Any]]]:
    if pair_key:
        if pair_key not in pairs:
            raise KeyError(f"Unknown pair_key: {pair_key}")
        return pair_key, pairs[pair_key]
    if sample_id:
        for candidate_key, rows in pairs.items():
            if any(str(row["id"]) == sample_id for row in rows):
                return candidate_key, rows
        raise KeyError(f"Unknown id: {sample_id}")
    if not pairs:
        raise ValueError("No demo rows are available")
    first_key = next(iter(pairs))
    return first_key, pairs[first_key]


def _evidence_windows(evidence: dict[str, Any] | None, *, limit: int, text_limit: int) -> list[dict[str, Any]]:
    if not evidence:
        return []
    windows = []
    for hunk in evidence.get("top_hunks", [])[:limit]:
        removed = hunk.get("removed_text", hunk.get("removed_preview", ""))
        added = hunk.get("added_text", hunk.get("added_preview", ""))
        windows.append(
            {
                "header": hunk.get("header", ""),
                "direction_labels": hunk.get("direction_labels", []),
                "risk_support": hunk.get("risk_support", 0),
                "safety_support": hunk.get("safety_support", 0),
                "net_risk_support": hunk.get("net_risk_support", 0),
                "removed": _shorten("\n".join(removed) if isinstance(removed, list) else removed, limit=text_limit),
                "added": _shorten("\n".join(added) if isinstance(added, list) else added, limit=text_limit),
            }
        )
    return windows


def build_patch_review_demo(
    *,
    dataset_path: str | Path = DEFAULT_DATASET_PATH,
    predictions_path: str | Path = DEFAULT_PREDICTIONS_PATH,
    evidence_path: str | Path = DEFAULT_EVIDENCE_PATH,
    sample_id: str | None = None,
    pair_key: str | None = None,
    evidence_limit: int = 2,
    text_limit: int = 700,
) -> dict[str, Any]:
    pairs = _load_dataset_by_pair(dataset_path)
    predictions = _load_jsonl_by_id(predictions_path)
    evidence_rows = _load_jsonl_by_id(evidence_path)
    selected_key, rows = _select_pair(pairs, sample_id=sample_id, pair_key=pair_key)

    reviewed_rows: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda item: str(item["id"])):
        prediction = predictions.get(str(row["id"]), {})
        evidence = evidence_rows.get(str(row["id"]))
        pred = int(prediction.get("pred", 0))
        gold = int(prediction.get("gold", int(bool(row.get("has_vulnerability")))))
        reviewed_rows.append(
            {
                "id": row["id"],
                "project": row.get("project", "unknown"),
                "cve": row.get("cve", "unknown"),
                "file_name": row.get("file_name", "unknown"),
                "cwe": row.get("vulnerability_type", "unknown"),
                "decision": _side_label(pred),
                "gold_label": _side_label(gold),
                "correct_on_benchmark": bool(pred == gold),
                "vulnerability_probability": prediction.get("vuln_probability"),
                "pre_coupled_decision": _side_label(prediction.get("pre_coupled_pred", pred)),
                "pair_coupled": bool(prediction.get("pair_coupled", False)),
                "support_label": evidence.get("support_label") if evidence else "missing_evidence_artifact",
                "risk_support": evidence.get("risk_support") if evidence else None,
                "safety_support": evidence.get("safety_support") if evidence else None,
                "net_risk_support": evidence.get("net_risk_support") if evidence else None,
                "evidence_windows": _evidence_windows(evidence, limit=evidence_limit, text_limit=text_limit),
            }
        )

    sorted_by_probability = sorted(
        reviewed_rows,
        key=lambda item: float(item["vulnerability_probability"] or 0.0),
        reverse=True,
    )
    gap = 0.0
    if len(sorted_by_probability) >= 2:
        gap = float(sorted_by_probability[0]["vulnerability_probability"] or 0.0) - float(
            sorted_by_probability[1]["vulnerability_probability"] or 0.0
        )
    return {
        "mode": "artifact_backed_patch_review_demo",
        "query": {"id": sample_id, "pair_key": pair_key},
        "pair_key": selected_key,
        "pair_decision": {
            "riskier_side_id": sorted_by_probability[0]["id"] if sorted_by_probability else None,
            "safer_side_id": sorted_by_probability[-1]["id"] if sorted_by_probability else None,
            "probability_gap": round(gap, 6),
            "pair_coupled": any(row["pair_coupled"] for row in reviewed_rows),
        },
        "rows": reviewed_rows,
        "caveats": [
            "This is an artifact-backed demo over the PrimeVul paired eval artifacts, not online inference for arbitrary new code.",
            "Evidence windows are heuristic/pseudo-localization outputs; final evidence labels require independent adjudication.",
            "Use this output for reviewer orientation and failure analysis, not as a standalone vulnerability scanner.",
        ],
    }
