from __future__ import annotations

import math
import re
from statistics import mean
from typing import Any


METADATA_PREFIXES = ("Project:", "CVE:", "CWE:", "Language:")
IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
PROTECTED_TOKENS = {
    "if",
    "else",
    "for",
    "while",
    "return",
    "true",
    "false",
    "null",
    "nullptr",
    "int",
    "char",
    "bool",
    "void",
    "const",
    "struct",
    "class",
    "public",
    "private",
    "protected",
    "static",
    "sizeof",
}


def strip_metadata(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith(METADATA_PREFIXES))


def normalize_identifiers(text: str) -> str:
    mapping: dict[str, str] = {}

    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        if token.lower() in PROTECTED_TOKENS or token.startswith(("CVE", "CWE")):
            return token
        if token not in mapping:
            mapping[token] = f"id_{len(mapping) + 1}"
        return mapping[token]

    return IDENTIFIER_RE.sub(replace, text)


def normalize_formatting(text: str) -> str:
    lines = []
    for line in text.splitlines():
        prefix = ""
        body = line
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
            prefix, body = line[0], line[1:]
        body = " ".join(body.strip().split())
        lines.append(prefix + body)
    return "\n".join(lines)


def add_nonsecurity_padding(text: str, *, lines: int = 12) -> str:
    padding = "\n".join(f" // counterfactual non-security padding {index + 1}" for index in range(lines))
    return f"{text.rstrip()}\n{padding}\n"


def truncate_context(text: str, *, keep_changed_context: int = 2) -> str:
    lines = text.splitlines()
    changed = [
        index
        for index, line in enumerate(lines)
        if (line.startswith("+") and not line.startswith("+++")) or (line.startswith("-") and not line.startswith("---"))
    ]
    if not changed:
        return text
    keep: set[int] = set()
    for index in changed:
        keep.update(range(max(0, index - keep_changed_context), min(len(lines), index + keep_changed_context + 1)))
    keep.update(index for index, line in enumerate(lines) if line.startswith(("Task:", "Unified diff:", "---", "+++", "@@")))
    return "\n".join(line for index, line in enumerate(lines) if index in keep)


def build_interventions(row: dict[str, Any], counterpart: dict[str, Any]) -> list[dict[str, Any]]:
    text = str(row.get("pair_text") or "")
    base = {
        "base_id": row["id"],
        "pair_key": row.get("pair_key"),
        "base_label": int(bool(row.get("has_vulnerability"))),
    }
    return [
        {
            **base,
            "intervention": "metadata_removed",
            "expected_relation": "invariant",
            "text": strip_metadata(text),
        },
        {
            **base,
            "intervention": "identifier_normalized",
            "expected_relation": "invariant",
            "text": normalize_identifiers(text),
        },
        {
            **base,
            "intervention": "format_normalized",
            "expected_relation": "invariant",
            "text": normalize_formatting(text),
        },
        {
            **base,
            "intervention": "nonsecurity_padding",
            "expected_relation": "invariant",
            "text": add_nonsecurity_padding(text),
        },
        {
            **base,
            "intervention": "side_order_swapped",
            "expected_relation": "equivariant_flip",
            "text": str(counterpart.get("pair_text") or ""),
            "expected_label": 1 - int(bool(row.get("has_vulnerability"))),
        },
        {
            **base,
            "intervention": "context_truncated",
            "expected_relation": "abstention_sensitivity",
            "text": truncate_context(text),
        },
    ]


def evaluate_intervention_predictions(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["intervention"]), []).append(row)

    by_intervention: dict[str, dict[str, Any]] = {}
    for name, items in sorted(grouped.items()):
        relation = str(items[0].get("expected_relation"))
        comparable = [row for row in items if row.get("base_pred") is not None and row.get("intervention_pred") is not None]
        if relation == "invariant":
            success = sum(int(row["base_pred"]) == int(row["intervention_pred"]) for row in comparable)
        elif relation == "equivariant_flip":
            success = sum(int(row["intervention_pred"]) == 1 - int(row["base_pred"]) for row in comparable)
        else:
            success = sum(
                bool(row.get("intervention_abstain")) or float(row.get("intervention_confidence") or 1.0) <= float(row.get("base_confidence") or 0.0)
                for row in comparable
            )
        success_rate = success / len(comparable) if comparable else None
        probability_shifts = [
            float(row.get("intervention_probability") or 0.0)
            - (1.0 - float(row.get("base_confidence") or 0.0) if int(row["base_pred"]) == 0 else float(row.get("base_confidence") or 0.0))
            for row in comparable
            if row.get("base_confidence") is not None and row.get("intervention_probability") is not None
        ]
        expected_labeled = []
        for row in comparable:
            expected_label = row.get("expected_label")
            if expected_label is None and relation == "invariant":
                expected_label = row.get("base_label")
            if expected_label is not None:
                expected_labeled.append((row, int(expected_label)))
        base_correct = sum(int(row["base_pred"]) == int(row.get("base_label")) for row, _expected in expected_labeled)
        intervention_correct = sum(int(row["intervention_pred"]) == expected for row, expected in expected_labeled)
        flips_0_to_1 = sum(int(row["base_pred"]) == 0 and int(row["intervention_pred"]) == 1 for row in comparable)
        flips_1_to_0 = sum(int(row["base_pred"]) == 1 and int(row["intervention_pred"]) == 0 for row in comparable)
        by_intervention[name] = {
            "expected_relation": relation,
            "rows": len(items),
            "comparable_rows": len(comparable),
            "relation_success_rate": success_rate,
            "relation_success_ci95": _wilson_interval(success, len(comparable)),
            "unexpected_change_rate": 1.0 - success_rate if success_rate is not None else None,
            "unexpected_change_ci95": _wilson_interval(len(comparable) - success, len(comparable)),
            "mean_probability_shift": mean(probability_shifts) if probability_shifts else None,
            "mean_absolute_probability_shift": mean(abs(value) for value in probability_shifts) if probability_shifts else None,
            "flip_0_to_1": flips_0_to_1,
            "flip_1_to_0": flips_1_to_0,
            "expected_label_rows": len(expected_labeled),
            "base_expected_label_accuracy": base_correct / len(expected_labeled) if expected_labeled else None,
            "intervention_expected_label_accuracy": intervention_correct / len(expected_labeled) if expected_labeled else None,
            "by_base_label": _relation_by_base_label(comparable, relation),
        }
    return {"rows": len(rows), "by_intervention": by_intervention}


def _wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total <= 0:
        return None
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = z * math.sqrt(proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)) / denominator
    return [center - margin, center + margin]


def _relation_by_base_label(rows: list[dict[str, Any]], relation: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for label in [0, 1]:
        subset = [row for row in rows if int(row.get("base_label", -1)) == label]
        if relation == "invariant":
            success = sum(int(row["base_pred"]) == int(row["intervention_pred"]) for row in subset)
        elif relation == "equivariant_flip":
            success = sum(int(row["intervention_pred"]) == 1 - int(row["base_pred"]) for row in subset)
        else:
            success = sum(
                bool(row.get("intervention_abstain"))
                or float(row.get("intervention_confidence") or 1.0) <= float(row.get("base_confidence") or 0.0)
                for row in subset
            )
        result[str(label)] = {
            "rows": len(subset),
            "relation_success_rate": success / len(subset) if subset else None,
            "unexpected_change_rate": 1.0 - success / len(subset) if subset else None,
        }
    return result
