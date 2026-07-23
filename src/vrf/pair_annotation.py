from __future__ import annotations

import math
import random
import re
from collections import Counter, defaultdict
from typing import Any


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

SIDE_LABELS = {"A", "B", "neither", "unclear"}
CONTEXT_LABELS = {"yes", "no", "unclear"}
CONFIDENCE_LABELS = {"1", "2", "3", "4", "5"}

REQUIRED_ANSWER_FIELDS = ("vulnerable_side", "root_cause", "minimal_evidence_lines", "context_sufficient", "confidence")

ADJUDICATION_FIELDS = [
    "pair_key",
    "consensus_vulnerable_side_id",
    "consensus_context_sufficient",
    "taxonomy",
    "adjudication_basis",
    "adjudicator_id",
    "adjudicated_at",
    "notes",
    "benchmark_gold_revealed_after",
    "matches_benchmark_gold",
]

CLAIM_BOUNDARY = {
    "human_gold_not_ai_pilot": True,
    "not_prevalence_estimate": True,
    "not_model_quality_benchmark": True,
    "distinct_from_evidence_localization_30_row_rounds": True,
    "packets_not_public_until_license_privacy_gate": True,
}

STUDY_ID_SINGLE_AUTHOR_50 = "primevul_pair_study_author50_v1"
DEFAULT_SINGLE_AUTHOR_SEED = 20260720
DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE = 50


def single_author_study_id(sample_size: int, seed: int) -> str:
    """Study id must track the actual sample size and seed (provenance).

    The canonical id ``primevul_pair_study_author50_v1`` is reserved for the
    default n=50 / seed=20260720 configuration only. Any other size or seed
    gets a distinct id so summaries cannot mislabel a non-50 run as the
    official author50 study.
    """
    if (
        int(sample_size) == DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE
        and int(seed) == DEFAULT_SINGLE_AUTHOR_SEED
    ):
        return STUDY_ID_SINGLE_AUTHOR_50
    return f"primevul_pair_study_author{int(sample_size)}_s{int(seed)}_v1"


def single_author_claim_boundary(sample_size: int) -> dict[str, Any]:
    """Claim boundary for a single-author audit of the given sample size."""
    return {
        **CLAIM_BOUNDARY,
        "protocol": "single_author_blinded_audit",
        "sample_size": int(sample_size),
        "single_author_annotator": True,
        "no_inter_annotator_agreement": True,
        "not_independent_dual_rater_gold": True,
        "author_may_know_system_under_study": True,
        "suitable_for": "qualitative_evidence_coupled_audit_and_error_analysis",
        "not_suitable_for": "inter_annotator_reliability_or_prevalence_claims",
    }


def paper_claim_boundary_statement(sample_size: int = DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE) -> str:
    n = int(sample_size)
    return (
        f"The human pair audit is a stratified {n}-pair single-author annotation under blinded "
        "packet presentation (metadata scrubbed; sides randomized). It supports qualitative "
        "evidence-coupled error analysis and author-facing case review. It is not independent "
        "dual-rater gold, does not report inter-annotator Cohen's κ, is not a prevalence estimate "
        "for PrimeVul, is not AI pilot labeling, and must not be promoted as a model-quality "
        "benchmark or replacement for the pair-coupled decoding mainline metrics."
    )


# Backward-compatible aliases for the default n=50 configuration.
SINGLE_AUTHOR_CLAIM_BOUNDARY = single_author_claim_boundary(DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE)
PAPER_CLAIM_BOUNDARY_STATEMENT = paper_claim_boundary_statement(DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE)


def not_applicable_agreement_report(
    *,
    study_id: str = STUDY_ID_SINGLE_AUTHOR_50,
    reason: str = "active_study_is_single_author",
) -> dict[str, Any]:
    """Agreement artifact when dual IAA is not defined (single-author mode).

    Prevents a stale dual n=150-shaped report from being read as an in-progress
    dual-rater study while the active protocol is single-author n=50.
    """
    return {
        "status": "not_applicable_single_author",
        "mode": "single_author",
        "study_id": study_id,
        "reason": reason,
        "claim_boundary": {
            **CLAIM_BOUNDARY,
            "no_inter_annotator_agreement": True,
            "active_study_is_single_author": True,
            "not_independent_dual_rater_gold": True,
        },
        "paired_annotations": 0,
        "dual_complete_n": 0,
        "minimum_publishable_dual_complete": None,
        "publishable_gate_met": False,
        "side_exact_agreement": None,
        "side_cohen_kappa": None,
        "context_exact_agreement": None,
        "context_cohen_kappa": None,
        "disagreement_count": 0,
        "disagreements": [],
        "label_distributions": {
            "side_a": {},
            "side_b": {},
            "context_a": {},
            "context_b": {},
        },
        "by_stratum": {},
        "annotator_a_complete": 0,
        "annotator_b_complete": 0,
        "note": (
            "Inter-annotator agreement is not applicable: the active study is a "
            "single-author blinded audit. Do not report Cohen's κ as dual-rater "
            "reliability. Dual-independent agreement requires annotator_1/2 "
            "answer CSVs under mode=dual_independent."
        ),
    }

# Lines that must not appear in annotator-facing packet text.
_METADATA_LINE_RE = re.compile(
    r"^\s*(Project|CVE|CWE|cve_id|project|vulnerability_type|Commit|commit_hash)\s*:",
    re.IGNORECASE,
)
_METADATA_INLINE_RE = re.compile(
    r"\b(CVE-\d{4}-\d+|CWE-\d+|cwe-\d+)\b",
    re.IGNORECASE,
)
# Inline "Project: foo" inside code comments (not only line-leading metadata).
_PROJECT_INLINE_RE = re.compile(
    r"\bProject\s*:\s*\S+",
    re.IGNORECASE,
)


def scrub_packet_diff_text(text: str) -> str:
    """Remove identity metadata from packet text (diff *or* code snippets).

    Strips Project/CVE/CWE header lines and redacts inline CVE/CWE/Project
    tokens so neither the Diff nor Code annotator views can unblind the case.
    """
    if not text:
        return ""
    kept: list[str] = []
    for line in str(text).splitlines():
        if _METADATA_LINE_RE.match(line):
            continue
        scrubbed = _METADATA_INLINE_RE.sub("[REDACTED]", line)
        scrubbed = _PROJECT_INLINE_RE.sub("[REDACTED]", scrubbed)
        kept.append(scrubbed)
    return "\n".join(kept)


# Alias: same scrub applies to code and diff packet fields.
scrub_packet_text = scrub_packet_diff_text


def select_high_value_pairs(
    pairs: list[dict[str, Any]],
    *,
    sample_size: int = 150,
    seed: int = 42,
) -> list[dict[str, Any]]:
    if sample_size <= 0:
        return []

    rng = random.Random(seed)
    strata: dict[str, list[dict[str, Any]]] = {
        "model_error": [],
        "low_margin": [],
        "high_confidence": [],
        "large_patch": [],
        "control": [],
    }
    for pair in pairs:
        if pair.get("model_pair_correct") is False:
            stratum = "model_error"
        elif float(pair.get("probability_gap") or 0.0) <= 0.15:
            stratum = "low_margin"
        elif float(pair.get("probability_gap") or 0.0) >= 0.7:
            stratum = "high_confidence"
        elif int(pair.get("changed_lines") or 0) >= 26:
            stratum = "large_patch"
        else:
            stratum = "control"
        enriched = dict(pair)
        enriched["selection_stratum"] = stratum
        strata[stratum].append(enriched)

    for rows in strata.values():
        rng.shuffle(rows)

    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    target_per_stratum = max(1, sample_size // len(strata))
    for name in strata:
        for row in strata[name][:target_per_stratum]:
            pair_key = str(row["pair_key"])
            if pair_key in seen:
                continue
            selected.append(row)
            seen.add(pair_key)

    remaining = [row for rows in strata.values() for row in rows if str(row["pair_key"]) not in seen]
    rng.shuffle(remaining)
    for row in remaining:
        if len(selected) >= sample_size:
            break
        selected.append(row)
        seen.add(str(row["pair_key"]))
    return selected[:sample_size]


def build_blinded_packet(
    selected_pairs: list[dict[str, Any]],
    *,
    annotator_id: str,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    rng = random.Random(seed)
    packet_rows: list[dict[str, Any]] = []
    answer_rows: list[dict[str, Any]] = []
    mapping_rows: list[dict[str, Any]] = []

    ordered = list(selected_pairs)
    rng.shuffle(ordered)
    for index, pair in enumerate(ordered, start=1):
        canonical_rows = list(pair["rows"])
        rng.shuffle(canonical_rows)
        side_a, side_b = canonical_rows
        case_id = f"pair-{index:03d}"
        packet_rows.append(
            {
                "case_id": case_id,
                "side_a": {
                    # Scrub code as well as diff: Code/Both views show `code` raw.
                    "code": scrub_packet_text(str(side_a.get("code", "") or "")),
                    "diff": scrub_packet_text(str(side_a.get("pair_text", "") or "")),
                },
                "side_b": {
                    "code": scrub_packet_text(str(side_b.get("code", "") or "")),
                    "diff": scrub_packet_text(str(side_b.get("pair_text", "") or "")),
                },
                "instructions": {
                    "vulnerable_side": "A|B|neither|unclear",
                    "minimal_evidence_lines": "Use side-prefixed line references such as A:12-15;B:8.",
                    "context_sufficient": "yes|no|unclear",
                    "confidence": "1-5",
                },
            }
        )
        answer_rows.append(
            {
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
        )
        mapping_rows.append(
            {
                "case_id": case_id,
                "annotator_id": annotator_id,
                "pair_key": pair["pair_key"],
                "side_a_id": side_a["id"],
                "side_b_id": side_b["id"],
                "gold_vulnerable_id": pair.get("gold_vulnerable_id"),
                "selection_stratum": pair.get("selection_stratum"),
            }
        )
    return packet_rows, answer_rows, mapping_rows


def _normalize_label(value: Any) -> str:
    return str(value or "").strip()


def normalize_side_label(value: Any) -> str:
    """Canonical vulnerable_side: A/B uppercased; neither/unclear lowercased.

    Accepts case variants (``a``, ``Neither``). Unknown non-empty strings are
    returned stripped as-is so validation can still reject them.
    """
    raw = _normalize_label(value)
    if not raw:
        return ""
    lower = raw.lower()
    if lower in {"a", "b"}:
        return lower.upper()
    if lower in {"neither", "unclear"}:
        return lower
    return raw


def normalize_context_label(value: Any) -> str:
    raw = _normalize_label(value)
    return raw.lower() if raw else ""


def is_answer_complete(row: dict[str, Any]) -> bool:
    side = normalize_side_label(row.get("vulnerable_side"))
    context = normalize_context_label(row.get("context_sufficient"))
    confidence = _normalize_label(row.get("confidence"))
    root = _normalize_label(row.get("root_cause"))
    evidence = _normalize_label(row.get("minimal_evidence_lines"))
    if side not in SIDE_LABELS:
        return False
    if context not in CONTEXT_LABELS:
        return False
    if confidence not in CONFIDENCE_LABELS:
        return False
    if not root or not evidence:
        return False
    return True


def validate_answer_row(row: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    case_id = _normalize_label(row.get("case_id")) or "<missing-case>"
    side_raw = _normalize_label(row.get("vulnerable_side"))
    side = normalize_side_label(side_raw) if side_raw else ""
    context_raw = _normalize_label(row.get("context_sufficient"))
    context = normalize_context_label(context_raw) if context_raw else ""
    confidence = _normalize_label(row.get("confidence"))

    if not case_id or case_id == "<missing-case>":
        errors.append("missing case_id")
    if side_raw and side not in SIDE_LABELS:
        errors.append(f"{case_id}: invalid vulnerable_side={side_raw!r}")
    if context_raw and context not in CONTEXT_LABELS:
        errors.append(f"{case_id}: invalid context_sufficient={context_raw!r}")
    if confidence and confidence not in CONFIDENCE_LABELS:
        errors.append(f"{case_id}: invalid confidence={confidence!r}")
    return errors


def validate_answer_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    errors: list[str] = []
    complete = 0
    for row in rows:
        errors.extend(validate_answer_row(row))
        if is_answer_complete(row):
            complete += 1
    return {
        "status": "ok" if not errors else "error",
        "row_count": len(rows),
        "complete_count": complete,
        "error_count": len(errors),
        "errors": errors[:50],
        "truncated": len(errors) > 50,
    }


def _cohen_kappa(labels_a: list[str], labels_b: list[str]) -> float | None:
    if not labels_a or len(labels_a) != len(labels_b):
        return None
    observed = sum(a == b for a, b in zip(labels_a, labels_b)) / len(labels_a)
    counts_a = Counter(labels_a)
    counts_b = Counter(labels_b)
    labels = set(counts_a) | set(counts_b)
    expected = sum((counts_a[label] / len(labels_a)) * (counts_b[label] / len(labels_b)) for label in labels)
    if math.isclose(expected, 1.0):
        return 1.0 if math.isclose(observed, 1.0) else 0.0
    return (observed - expected) / (1.0 - expected)


def _disagreement_taxonomy(side_a: str, side_b: str, context_a: str, context_b: str) -> str:
    side_disagree = side_a != side_b
    context_disagree = context_a != context_b
    involves_unclear = any(
        label in {"unclear", "neither", "missing"} for label in (side_a, side_b, context_a, context_b)
    )
    if side_disagree and context_disagree:
        base = "both"
    elif side_disagree:
        base = "side_only"
    elif context_disagree:
        base = "context_only"
    else:
        base = "none"
    if involves_unclear and base != "none":
        return f"{base}|involves_unclear_neither"
    return base


def analyze_independent_annotations(
    annotations_a: list[dict[str, Any]],
    annotations_b: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
    *,
    minimum_publishable_dual_complete: int = 100,
) -> dict[str, Any]:
    mapping_by_case = {(row["annotator_id"], row["case_id"]): row for row in mappings}
    stratum_by_pair: dict[str, str] = {}
    for row in mappings:
        stratum_by_pair[str(row["pair_key"])] = str(row.get("selection_stratum") or "unknown")

    def canonical_side(row: dict[str, Any]) -> str:
        choice = normalize_side_label(row.get("vulnerable_side"))
        mapping = mapping_by_case.get((row.get("annotator_id"), row.get("case_id")))
        if not mapping or choice not in {"A", "B"}:
            return choice if choice else "missing"
        selected_id = str(mapping["side_a_id"] if choice == "A" else mapping["side_b_id"])
        canonical_ids = sorted([str(mapping["side_a_id"]), str(mapping["side_b_id"])])
        return "canonical_0" if selected_id == canonical_ids[0] else "canonical_1"

    def raw_side(row: dict[str, Any]) -> str:
        choice = normalize_side_label(row.get("vulnerable_side"))
        return choice if choice else "missing"

    def raw_context(row: dict[str, Any]) -> str:
        choice = normalize_context_label(row.get("context_sufficient"))
        return choice if choice else "missing"

    by_pair_a: dict[str, dict[str, Any]] = {}
    by_pair_b: dict[str, dict[str, Any]] = {}
    for row in annotations_a:
        mapping = mapping_by_case.get((row.get("annotator_id"), row.get("case_id")))
        if mapping:
            by_pair_a[str(mapping["pair_key"])] = row
    for row in annotations_b:
        mapping = mapping_by_case.get((row.get("annotator_id"), row.get("case_id")))
        if mapping:
            by_pair_b[str(mapping["pair_key"])] = row

    common = sorted(set(by_pair_a) & set(by_pair_b))
    dual_complete_keys = [
        key
        for key in common
        if is_answer_complete(by_pair_a[key]) and is_answer_complete(by_pair_b[key])
    ]

    def metrics_for_keys(keys: list[str]) -> dict[str, Any]:
        if not keys:
            return {
                "n": 0,
                "side_exact_agreement": None,
                "side_cohen_kappa": None,
                "context_exact_agreement": None,
                "context_cohen_kappa": None,
                "disagreement_count": 0,
                "disagreements": [],
                "side_label_distribution_a": {},
                "side_label_distribution_b": {},
                "context_label_distribution_a": {},
                "context_label_distribution_b": {},
            }
        side_a = [canonical_side(by_pair_a[key]) for key in keys]
        side_b = [canonical_side(by_pair_b[key]) for key in keys]
        context_a = [raw_context(by_pair_a[key]) for key in keys]
        context_b = [raw_context(by_pair_b[key]) for key in keys]
        side_agreement = sum(a == b for a, b in zip(side_a, side_b))
        context_agreement = sum(a == b for a, b in zip(context_a, context_b))
        disagreements = []
        for index, key in enumerate(keys):
            if side_a[index] == side_b[index] and context_a[index] == context_b[index]:
                continue
            disagreements.append(
                {
                    "pair_key": key,
                    "selection_stratum": stratum_by_pair.get(key, "unknown"),
                    "annotator_a_side": side_a[index],
                    "annotator_b_side": side_b[index],
                    "annotator_a_side_raw": raw_side(by_pair_a[key]),
                    "annotator_b_side_raw": raw_side(by_pair_b[key]),
                    "annotator_a_context": context_a[index],
                    "annotator_b_context": context_b[index],
                    "taxonomy": _disagreement_taxonomy(
                        side_a[index], side_b[index], context_a[index], context_b[index]
                    ),
                }
            )
        return {
            "n": len(keys),
            "side_exact_agreement": side_agreement / len(keys),
            "side_cohen_kappa": _cohen_kappa(side_a, side_b),
            "context_exact_agreement": context_agreement / len(keys),
            "context_cohen_kappa": _cohen_kappa(context_a, context_b),
            "disagreement_count": len(disagreements),
            "disagreements": disagreements,
            "side_label_distribution_a": dict(sorted(Counter(side_a).items())),
            "side_label_distribution_b": dict(sorted(Counter(side_b).items())),
            "context_label_distribution_a": dict(sorted(Counter(context_a).items())),
            "context_label_distribution_b": dict(sorted(Counter(context_b).items())),
        }

    dual_metrics = metrics_for_keys(dual_complete_keys)
    by_stratum: dict[str, dict[str, Any]] = {}
    stratum_keys: dict[str, list[str]] = defaultdict(list)
    for key in dual_complete_keys:
        stratum_keys[stratum_by_pair.get(key, "unknown")].append(key)
    for stratum, keys in sorted(stratum_keys.items()):
        by_stratum[stratum] = metrics_for_keys(keys)

    dual_complete_n = len(dual_complete_keys)
    publishable = dual_complete_n >= minimum_publishable_dual_complete
    status = "ok" if dual_complete_n > 0 else "annotation_pending"
    if dual_complete_n > 0 and not publishable:
        status = "partial"

    # Backward-compatible top-level fields: only on dual-complete rows (never on all-missing).
    return {
        "status": status,
        "claim_boundary": dict(CLAIM_BOUNDARY),
        "paired_annotations": len(common),
        "dual_complete_n": dual_complete_n,
        "minimum_publishable_dual_complete": minimum_publishable_dual_complete,
        "publishable_gate_met": publishable,
        "side_exact_agreement": dual_metrics["side_exact_agreement"],
        "side_cohen_kappa": dual_metrics["side_cohen_kappa"],
        "context_exact_agreement": dual_metrics["context_exact_agreement"],
        "context_cohen_kappa": dual_metrics["context_cohen_kappa"],
        "disagreement_count": dual_metrics["disagreement_count"],
        "disagreements": dual_metrics["disagreements"],
        "label_distributions": {
            "side_a": dual_metrics["side_label_distribution_a"],
            "side_b": dual_metrics["side_label_distribution_b"],
            "context_a": dual_metrics["context_label_distribution_a"],
            "context_b": dual_metrics["context_label_distribution_b"],
        },
        "by_stratum": by_stratum,
        "annotator_a_complete": sum(1 for row in annotations_a if is_answer_complete(row)),
        "annotator_b_complete": sum(1 for row in annotations_b if is_answer_complete(row)),
    }


def study_status(
    annotations_a: list[dict[str, Any]],
    annotations_b: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
    *,
    target_pairs: int = 150,
    minimum_publishable_dual_complete: int = 100,
) -> dict[str, Any]:
    """Legacy dual-annotator status (retained for tests / optional future dual runs)."""
    agreement = analyze_independent_annotations(
        annotations_a,
        annotations_b,
        mappings,
        minimum_publishable_dual_complete=minimum_publishable_dual_complete,
    )
    mapping_a = {str(row["pair_key"]): row for row in mappings if row.get("annotator_id") == "annotator_1"}
    if not mapping_a:
        # Fallback: use any mapping rows unique by pair.
        mapping_a = {}
        for row in mappings:
            mapping_a.setdefault(str(row["pair_key"]), row)

    strata_counts = Counter(str(row.get("selection_stratum") or "unknown") for row in mapping_a.values())
    dual_complete = agreement["dual_complete_n"]
    engineering_ready = True
    return {
        "status": agreement["status"],
        "study_id": "primevul_pair_study_v1",
        "mode": "dual_independent",
        "target_pairs": target_pairs,
        "materialized_pairs": len(mapping_a),
        "selection_strata": dict(sorted(strata_counts.items())),
        "annotator_1_complete": agreement["annotator_a_complete"],
        "annotator_2_complete": agreement["annotator_b_complete"],
        "dual_complete_n": dual_complete,
        "minimum_publishable_dual_complete": minimum_publishable_dual_complete,
        "publishable_gate_met": agreement["publishable_gate_met"],
        "disagreement_count_on_dual_complete": agreement["disagreement_count"],
        "engineering_scaffold_ready": engineering_ready,
        "human_annotation_complete": dual_complete >= target_pairs,
        "claim_boundary": dict(CLAIM_BOUNDARY),
        "side_cohen_kappa": agreement["side_cohen_kappa"],
        "context_cohen_kappa": agreement["context_cohen_kappa"],
    }


def single_author_study_status(
    annotations: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
    *,
    target_pairs: int = DEFAULT_SINGLE_AUTHOR_SAMPLE_SIZE,
    study_id: str | None = None,
    seed: int = DEFAULT_SINGLE_AUTHOR_SEED,
) -> dict[str, Any]:
    """Completion status for a single-author stratified audit."""
    by_pair: dict[str, dict[str, Any]] = {}
    for row in mappings:
        by_pair.setdefault(str(row["pair_key"]), row)
    strata_counts = Counter(str(row.get("selection_stratum") or "unknown") for row in by_pair.values())

    mapping_by_case = {(row.get("annotator_id"), row.get("case_id")): row for row in mappings}
    complete_rows = [row for row in annotations if is_answer_complete(row)]
    complete_n = len(complete_rows)

    side_counts: Counter[str] = Counter()
    context_counts: Counter[str] = Counter()
    stratum_complete: Counter[str] = Counter()
    for row in complete_rows:
        side_counts[normalize_side_label(row.get("vulnerable_side")) or "missing"] += 1
        context_counts[normalize_context_label(row.get("context_sufficient")) or "missing"] += 1
        mapping = mapping_by_case.get((row.get("annotator_id"), row.get("case_id")))
        if mapping:
            stratum_complete[str(mapping.get("selection_stratum") or "unknown")] += 1

    resolved_id = study_id or single_author_study_id(target_pairs, seed)
    status = "annotation_pending" if complete_n == 0 else ("ok" if complete_n >= target_pairs else "partial")
    return {
        "status": status,
        "study_id": resolved_id,
        "mode": "single_author",
        "target_pairs": target_pairs,
        "materialized_pairs": len(by_pair),
        "selection_strata": dict(sorted(strata_counts.items())),
        "author_complete_n": complete_n,
        "complete_by_stratum": dict(sorted(stratum_complete.items())),
        "side_label_distribution": dict(sorted(side_counts.items())),
        "context_label_distribution": dict(sorted(context_counts.items())),
        "publishable_gate_met": complete_n >= target_pairs,
        "minimum_publishable_complete": target_pairs,
        "engineering_scaffold_ready": True,
        "human_annotation_complete": complete_n >= target_pairs,
        "inter_annotator_agreement": None,
        "inter_annotator_agreement_note": (
            "Not applicable: single-author study has no second independent annotator; "
            "do not report Cohen's κ as dual-rater reliability."
        ),
        "claim_boundary": single_author_claim_boundary(target_pairs),
        "paper_claim_boundary_statement": paper_claim_boundary_statement(target_pairs),
    }


def render_agreement_markdown(report: dict[str, Any]) -> str:
    status = report.get("status", "unknown")
    if status == "not_applicable_single_author":
        return "\n".join(
            [
                "# PrimeVul Pair Annotation Agreement v1",
                "",
                f"**Status:** `{status}`",
                "",
                f"**Study id:** `{report.get('study_id', 'n/a')}`",
                "",
                "## Not applicable",
                "",
                str(
                    report.get("note")
                    or (
                        "The active study is single-author; dual-rater Cohen's κ is not defined. "
                        "See `reports/secure_code_primevul_pair_annotation_status_v1.json` for "
                        "author completion status."
                    )
                ),
                "",
                "## Claim boundary",
                "",
                "- **No inter-annotator agreement** under single-author protocol.",
                "- **Human gold ≠ AI pilot** labels and ≠ the separate 30-row evidence-localization rounds.",
                "- The sample is **not** a prevalence estimate for the full benchmark.",
                "- Dual-independent agreement requires `mode=dual_independent` with both annotator CSVs.",
                "",
                "## Non-claims",
                "",
                "- Does not establish model quality or replace pair-coupled decoding mainline metrics.",
                "- Does not report dual-rater κ for the single-author audit.",
                "",
            ]
        )

    lines = [
        "# PrimeVul Pair Annotation Agreement v1",
        "",
        f"**Status:** `{status}`",
        "",
        "## Claim boundary",
        "",
        "- This report measures **independent human annotator agreement** on a high-value audit sample.",
        "- **Human gold ≠ AI pilot** labels and ≠ the separate 30-row evidence-localization rounds.",
        "- The sample is **not** a prevalence estimate for the full benchmark.",
        "- Agreement metrics are computed only on **dual-complete** rows; empty answer sheets do not yield scientific κ.",
        "",
        "## Completion",
        "",
        f"- Paired mappings present: `{report.get('paired_annotations')}`",
        f"- Dual-complete pairs: `{report.get('dual_complete_n')}`",
        f"- Annotator A complete: `{report.get('annotator_a_complete')}`",
        f"- Annotator B complete: `{report.get('annotator_b_complete')}`",
        f"- Publishable gate (≥{report.get('minimum_publishable_dual_complete')} dual-complete): "
        f"`{report.get('publishable_gate_met')}`",
        "",
        "## Agreement (dual-complete only)",
        "",
    ]
    if report.get("dual_complete_n", 0) == 0:
        lines.extend(
            [
                "_No dual-complete annotations yet. Metrics intentionally null._",
                "",
                "| Metric | Value |",
                "| --- | --- |",
                "| Side exact agreement | n/a |",
                "| Side Cohen's κ | n/a |",
                "| Context exact agreement | n/a |",
                "| Context Cohen's κ | n/a |",
                "| Disagreement count | n/a |",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "| Metric | Value |",
                "| --- | --- |",
                f"| Side exact agreement | {report.get('side_exact_agreement')} |",
                f"| Side Cohen's κ | {report.get('side_cohen_kappa')} |",
                f"| Context exact agreement | {report.get('context_exact_agreement')} |",
                f"| Context Cohen's κ | {report.get('context_cohen_kappa')} |",
                f"| Disagreement count | {report.get('disagreement_count')} |",
                "",
            ]
        )
    lines.extend(
        [
            "## Disagreement taxonomy (dual-complete)",
            "",
        ]
    )
    tax = Counter(item.get("taxonomy", "unknown") for item in report.get("disagreements") or [])
    if not tax:
        lines.append("_None yet._")
        lines.append("")
    else:
        lines.append("| Taxonomy | Count |")
        lines.append("| --- | ---: |")
        for key, count in sorted(tax.items()):
            lines.append(f"| `{key}` | {count} |")
        lines.append("")
    lines.extend(
        [
            "## Stratum breakdown",
            "",
        ]
    )
    by_stratum = report.get("by_stratum") or {}
    if not by_stratum:
        lines.append("_No dual-complete rows for stratum metrics._")
        lines.append("")
    else:
        lines.append("| Stratum | n | Side κ | Context κ | Disagreements |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        for stratum, metrics in sorted(by_stratum.items()):
            lines.append(
                f"| `{stratum}` | {metrics.get('n')} | {metrics.get('side_cohen_kappa')} | "
                f"{metrics.get('context_cohen_kappa')} | {metrics.get('disagreement_count')} |"
            )
        lines.append("")
    lines.extend(
        [
            "## Non-claims",
            "",
            "- Does not establish model quality or replace pair-coupled decoding mainline metrics.",
            "- Free-text root-cause / evidence spans require qualitative review, not κ alone.",
            "- AI-assisted prioritization of adjudication queues is not gold.",
            "",
        ]
    )
    return "\n".join(lines)


def empty_adjudication_template_rows(disagreements: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in disagreements:
        rows.append(
            {
                "pair_key": item.get("pair_key", ""),
                "consensus_vulnerable_side_id": "",
                "consensus_context_sufficient": "",
                "taxonomy": item.get("taxonomy", ""),
                "adjudication_basis": "",
                "adjudicator_id": "",
                "adjudicated_at": "",
                "notes": "",
                "benchmark_gold_revealed_after": "false",
                "matches_benchmark_gold": "",
            }
        )
    return rows


def _side_choice_to_id(choice: str, mapping: dict[str, Any]) -> str | None:
    """Map packet-side label A/B to sample id; pass through neither/unclear."""
    side = normalize_side_label(choice)
    if side == "A":
        return str(mapping["side_a_id"])
    if side == "B":
        return str(mapping["side_b_id"])
    if side in {"neither", "unclear"}:
        return side
    return None


def exact_dual_agreement_rows(
    annotations_a: list[dict[str, Any]],
    annotations_b: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Dual-complete pairs where side+context agree — auto-exportable consensus rows.

    Uses annotator A's mapping to resolve A/B → sample ids. Does not invent labels:
    only pairs where both annotators already agree.
    """
    mapping_by_case = {(row["annotator_id"], row["case_id"]): row for row in mappings}
    by_pair_a: dict[str, dict[str, Any]] = {}
    by_pair_b: dict[str, dict[str, Any]] = {}
    for row in annotations_a:
        mapping = mapping_by_case.get((row.get("annotator_id"), row.get("case_id")))
        if mapping:
            by_pair_a[str(mapping["pair_key"])] = row
    for row in annotations_b:
        mapping = mapping_by_case.get((row.get("annotator_id"), row.get("case_id")))
        if mapping:
            by_pair_b[str(mapping["pair_key"])] = row

    gold_by_pair = {str(row["pair_key"]): row.get("gold_vulnerable_id") for row in mappings}
    # Prefer annotator_1 mapping for id resolution when present.
    mapping_by_pair: dict[str, dict[str, Any]] = {}
    for row in mappings:
        key = str(row["pair_key"])
        if key not in mapping_by_pair or str(row.get("annotator_id") or "") == "annotator_1":
            mapping_by_pair[key] = row

    agreements: list[dict[str, Any]] = []
    for pair_key in sorted(set(by_pair_a) & set(by_pair_b)):
        row_a = by_pair_a[pair_key]
        row_b = by_pair_b[pair_key]
        if not (is_answer_complete(row_a) and is_answer_complete(row_b)):
            continue
        side_a = normalize_side_label(row_a.get("vulnerable_side"))
        side_b = normalize_side_label(row_b.get("vulnerable_side"))
        ctx_a = normalize_context_label(row_a.get("context_sufficient"))
        ctx_b = normalize_context_label(row_b.get("context_sufficient"))
        # Agreement must be on the *canonical* side identity, not raw A/B labels
        # (sides are randomized per annotator packet).
        mapping_a = mapping_by_case.get((row_a.get("annotator_id"), row_a.get("case_id")))
        mapping_b = mapping_by_case.get((row_b.get("annotator_id"), row_b.get("case_id")))
        if not mapping_a or not mapping_b:
            continue
        id_a = _side_choice_to_id(side_a, mapping_a)
        id_b = _side_choice_to_id(side_b, mapping_b)
        if id_a is None or id_b is None or id_a != id_b or ctx_a != ctx_b:
            continue
        mapping = mapping_by_pair.get(pair_key) or mapping_a
        agreements.append(
            {
                "pair_key": pair_key,
                "consensus_vulnerable_side_id": id_a,
                "consensus_context_sufficient": ctx_a,
                "taxonomy": "none",
                "adjudication_basis": "exact_dual_agreement",
                "adjudicator_id": "",
                "adjudicated_at": "",
                "notes": "",
                "benchmark_gold_id": gold_by_pair.get(pair_key),
                "matches_benchmark_gold": (
                    id_a == str(gold_by_pair[pair_key])
                    if gold_by_pair.get(pair_key) is not None and id_a not in {"neither", "unclear"}
                    else None
                ),
                "source": "exact_dual_agreement",
                "claim_boundary": "human_gold_not_ai_pilot",
            }
        )
    return agreements


def apply_adjudications(
    disagreements: list[dict[str, Any]],
    adjudication_rows: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
    *,
    exact_agreements: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Merge human adjudication + exact dual agreements into full consensus gold.

    Does not invent labels. Exact agreements (optional) are dual-complete pairs
    where both annotators already agree; disagreements require filled adjudication
    rows. The returned ``consensus`` list is the union (agreements first, then
    adjudicated disagreements), which is what ``human_gold_consensus_v1.jsonl``
    should contain.
    """
    gold_by_pair = {}
    for row in mappings:
        gold_by_pair[str(row["pair_key"])] = row.get("gold_vulnerable_id")

    by_key = {str(row.get("pair_key") or ""): row for row in adjudication_rows if str(row.get("pair_key") or "")}
    consensus: list[dict[str, Any]] = []
    seen_pairs: set[str] = set()

    # 1) Exact dual agreements (auto-copied; no adjudicator required).
    for record in exact_agreements or []:
        pair_key = str(record.get("pair_key") or "")
        if not pair_key or pair_key in seen_pairs:
            continue
        consensus.append(dict(record))
        seen_pairs.add(pair_key)

    # 2) Human-adjudicated disagreements.
    missing: list[str] = []
    adjudicated: list[dict[str, Any]] = []
    for item in disagreements:
        pair_key = str(item.get("pair_key") or "")
        if pair_key in seen_pairs:
            # Already covered by exact agreement (should be rare if disagreement list is clean).
            continue
        adj = by_key.get(pair_key)
        if adj is None:
            missing.append(pair_key)
            continue
        side_id = _normalize_label(adj.get("consensus_vulnerable_side_id"))
        context = normalize_context_label(adj.get("consensus_context_sufficient"))
        # Human adjudicator must fill both consensus fields for each disagreement.
        if not side_id or context not in CONTEXT_LABELS:
            missing.append(pair_key)
            continue
        record = {
            "pair_key": pair_key,
            "consensus_vulnerable_side_id": side_id or None,
            "consensus_context_sufficient": context or None,
            "taxonomy": _normalize_label(adj.get("taxonomy")) or item.get("taxonomy"),
            "adjudication_basis": _normalize_label(adj.get("adjudication_basis")),
            "adjudicator_id": _normalize_label(adj.get("adjudicator_id")),
            "adjudicated_at": _normalize_label(adj.get("adjudicated_at")),
            "notes": _normalize_label(adj.get("notes")),
            "benchmark_gold_id": gold_by_pair.get(pair_key),
            "matches_benchmark_gold": None,
            "source": "human_adjudication",
            "claim_boundary": "human_gold_not_ai_pilot",
        }
        revealed = _normalize_label(adj.get("benchmark_gold_revealed_after")).lower() in {"1", "true", "yes"}
        if revealed and side_id and gold_by_pair.get(pair_key) is not None:
            record["matches_benchmark_gold"] = side_id == str(gold_by_pair[pair_key])
        adjudicated.append(record)
        consensus.append(record)
        seen_pairs.add(pair_key)

    agreement_n = len(exact_agreements or [])
    return {
        "status": "ok" if not missing else "incomplete",
        "consensus_count": len(consensus),
        "exact_agreement_count": agreement_n,
        "adjudicated_disagreement_count": len(adjudicated),
        "missing_disagreement_pair_keys": missing,
        "disagreement_count": len(disagreements),
        # True when every disagreement row has a filled adjudication (agreements
        # are separate and do not require adjudicator fields).
        "all_disagreements_adjudicated": not missing,
        "consensus": consensus,
        "claim_boundary": dict(CLAIM_BOUNDARY),
    }


def export_review_sheet_markdown(packet_rows: list[dict[str, Any]], *, annotator_id: str) -> str:
    lines = [
        f"# Pair annotation review sheet — {annotator_id}",
        "",
        "Blinded study packet. Do **not** search for CVE identifiers or share answers with the other annotator until lock.",
        "Fill the matching answers CSV only.",
        "",
    ]
    for row in packet_rows:
        case_id = row.get("case_id", "")
        lines.append(f"## {case_id}")
        lines.append("")
        lines.append("### Side A")
        lines.append("")
        lines.append("```")
        lines.append(str((row.get("side_a") or {}).get("diff") or (row.get("side_a") or {}).get("code") or ""))
        lines.append("```")
        lines.append("")
        lines.append("### Side B")
        lines.append("")
        lines.append("```")
        lines.append(str((row.get("side_b") or {}).get("diff") or (row.get("side_b") or {}).get("code") or ""))
        lines.append("```")
        lines.append("")
        lines.append(
            "Labels: `vulnerable_side` ∈ {A,B,neither,unclear}; "
            "`context_sufficient` ∈ {yes,no,unclear}; `confidence` ∈ {1..5}; "
            "evidence like `A:12-15;B:8`."
        )
        lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


def packet_contains_identity_leak(packet_row: dict[str, Any]) -> list[str]:
    """Return leak descriptions if Project/CVE/CWE-style identity remains in packet text."""
    leaks: list[str] = []
    blob = json_safe_blob(packet_row)
    for pattern, name in (
        (r"\bProject\s*:", "Project"),
        (r"\bCVE-\d{4}-\d+\b", "CVE-id"),
        (r"\bCVE\s*:", "CVE"),
        (r"\bCWE\s*:", "CWE"),
        (r"\bcwe-\d+\b", "cwe-id"),
    ):
        if re.search(pattern, blob, flags=re.IGNORECASE):
            leaks.append(name)
    return leaks


def json_safe_blob(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(json_safe_blob(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(json_safe_blob(v) for v in value)
    return str(value or "")
