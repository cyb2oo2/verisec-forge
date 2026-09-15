"""Accept an input-bound annotation run and translate labels to display order."""
from __future__ import annotations

from collections import Counter
from vrf.ai_annotation import validate_annotation


def assemble_run(cases, responses, metadata, provenance, keys):
    for field in ("provider", "model_id", "model_version", "run_id", "started_at", "completed_at"):
        if not isinstance(metadata.get(field), str) or not metadata[field].strip():
            raise ValueError(f"missing runtime metadata: {field}")
    if metadata.get("annotation_source") != "ai" or type(metadata.get("mock")) is not bool:
        raise ValueError("explicit AI origin and mock flag required")
    if not isinstance(metadata.get("parameters"), dict):
        raise ValueError("runtime parameters required")
    execution_mode = metadata.get("execution_mode", "provider_api")
    if execution_mode not in {"provider_api", "current_assistant_context"}:
        raise ValueError("unsupported execution mode")
    if execution_mode == "current_assistant_context":
        if metadata.get("independent_contexts") is not False or metadata.get("prepared_requests_executed_verbatim") is not False:
            raise ValueError("assistant-context annotation must disclose non-independent, adapted execution")
    case_index = {r["case_id"]: r for r in cases}
    if len(case_index) != len(cases):
        raise ValueError("duplicate cases")
    records = {}
    for row in responses:
        identifier = row.get("case_id")
        if identifier not in case_index or identifier in records:
            raise ValueError("unknown or duplicate response")
        validity = validate_annotation(row, case_index[identifier])
        records[identifier] = (row, validity)
    if set(records) != set(case_index):
        raise ValueError("incomplete run; missing responses must not become exclusions")
    pi = {r["case_id"]: r for r in provenance}
    if len(pi) != len(provenance) or set(pi) != set(case_index):
        raise ValueError("provenance coverage mismatch")
    if len({k["id"] for k in keys}) != len(keys) or {k["case_id"] for k in keys} != set(case_index):
        raise ValueError("key identity mismatch")
    counts, exclusions, eligible, gold = {}, [], {}, []
    for identifier, (row, validity) in records.items():
        source = pi[identifier]["dataset"]
        counts.setdefault(source, Counter(total=0, eligible=0, unresolved=0))
        counts[source]["total"] += 1
        if validity["eligible_for_provisional_ab"]:
            counts[source]["eligible"] += 1
            label = row["vulnerable_side"]
            reverse = pi[identifier].get("r1_reverse")
            if type(reverse) is not bool:
                raise ValueError("missing annotation orientation")
            eligible[identifier] = ("B" if label == "A" else "A") if reverse else label
        else:
            counts[source]["unresolved"] += 1
            exclusions.append({"case_id": identifier, "label": row["vulnerable_side"],
                               "context": row["context_sufficient"], "confidence": row["confidence"]})
    # Bind provisional security labels to each rendered code order; binding-task
    # gold remains constructed. Keep every label-eligible case's full 12 cells.
    for k in keys:
        identifier = k["case_id"]
        if identifier not in eligible:
            continue
        label = eligible[identifier]
        if k["order"] not in (0, 1):
            raise ValueError("invalid display order")
        if k["task"] == "security":
            label = ("B" if label == "A" else "A") if k["order"] else label
        else:
            label = k["gold"]
        gold.append({"id": k["id"], "case_id": identifier, "task": k["task"], "gold": label,
                     "label_source": "ai_provisional" if k["task"] == "security" else "constructed",
                     "prompt_sha256": k["prompt_sha256"]})
    status = "MOCK_ONLY" if metadata["mock"] else (
        "AI_EXPLORATORY_ANNOTATIONS_ACCEPTED" if execution_mode == "current_assistant_context"
        else "AI_LABELS_ACCEPTED_NOT_EVALUATED")
    return {"status": status,
            "human_gold": False, "factual_correctness_validated": False,
            "model_inference_allowed": False, "by_source": counts, "unresolved": exclusions,
            "evaluation_keys": gold, "run_metadata": metadata}
