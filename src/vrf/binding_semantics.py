"""Offline P1 construction; benchmark labels are provisional, not human gold."""
from __future__ import annotations

import hashlib
import re
from collections import Counter

from vrf.relational_benchmark import CanonicalPair


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def project_key(project: str) -> str:
    """Conservative basename aliases; collisions over-exclude, never certify identity."""
    return project.strip().lower().rstrip("/").removesuffix(".git").split("/")[-1]


def code_key(code: str) -> str:
    # Whitespace-normalized exact content only; this is not a clone detector.
    return digest(re.sub(r"\s+", "", code))


def select_candidates(pool: list[CanonicalPair], prior: list[CanonicalPair],
                      per_source: int = 12) -> tuple[list[CanonicalPair], dict]:
    if per_source < 1:
        raise ValueError("per_source must be positive")
    old_keys = {(p.dataset, p.pair_key) for p in prior}
    projects = {project_key(p.project) for p in prior}
    codes = {code_key(s.code) for p in prior for s in (p.side_a, p.side_b)}
    selected, counts, excluded = [], Counter(), Counter()
    seen = set()
    for p in sorted(pool, key=lambda p: digest(f"p1-v1::{p.dataset}::{p.pair_key}")):
        key = (p.dataset, p.pair_key)
        if key in seen:
            raise ValueError("duplicate source/pair identity")
        seen.add(key)
        project = project_key(p.project)
        hashes = {code_key(p.side_a.code), code_key(p.side_b.code)}
        reason = None
        if key in old_keys:
            reason = "prior_pair"
        elif project in {"", "unknown", "none", "null", "n/a"}:
            reason = "unknown_project"
        elif project in projects:
            reason = "prior_or_selected_project"
        elif not p.side_a.code.strip() or not p.side_b.code.strip() or len(hashes) != 2:
            reason = "empty_or_identical_code"
        elif hashes & codes:
            reason = "prior_or_selected_code"
        elif counts[p.dataset] >= per_source:
            reason = "source_quota"
        if reason:
            excluded[reason] += 1
            continue
        selected.append(p)
        counts[p.dataset] += 1
        projects.add(project)
        codes.update(hashes)
    return selected, {"selected_by_source": dict(counts), "excluded": dict(excluded),
                      "project_alias_rule": "lowercase repository basename; conservative",
                      "training_overlap": "not_checked", "near_duplicate_overlap": "not_checked"}


def build_case(pair: CanonicalPair) -> tuple[list[dict], list[dict], dict]:
    case = digest(f"p1::{pair.dataset}::{pair.pair_key}")[:20]
    prompts, keys = [], []
    for order in range(2):
        sides = (pair.side_a, pair.side_b) if not order else (pair.side_b, pair.side_a)
        for assignment in range(2):
            tokens = ("K7", "M2") if not assignment else ("M2", "K7")
            # Length framing preserves all source text without interpreting embedded fences.
            body = "\n\n".join(
                f"Candidate {side} [tag {tag}] ({len(item.code)} characters):\n{item.code}"
                for side, tag, item in zip(("A", "B"), tokens, sides)
            )
            tasks = [("security", None, "Which candidate is more vulnerable?"),
                     ("binding_K7", "K7", "Which candidate carries tag K7?"),
                     ("binding_M2", "M2", "Which candidate carries tag M2?")]
            for task, target, question in tasks:
                identifier = f"{case}:o{order}:t{assignment}:{task}"
                answer = ("A" if sides[0].vulnerable else "B") if target is None else (
                    "A" if tokens[0] == target else "B")
                text = body + "\n\n" + question + " Answer A or B only."
                prompts.append({"id": identifier, "text": text})
                keys.append({"id": identifier, "case_id": case, "dataset": pair.dataset,
                             "project": project_key(pair.project), "pair_key": pair.pair_key,
                             "order": order, "tag_assignment": assignment, "task": task,
                             "gold": answer, "gold_status": "benchmark_provisional" if target is None else "constructed",
                             "prompt_sha256": digest(text), "body_sha256": digest(body)})
    private = {"case_id": case, "dataset": pair.dataset, "pair_key": pair.pair_key,
               "project": project_key(pair.project), "source_ids": [pair.side_a.id, pair.side_b.id],
               "code_sha256": [digest(pair.side_a.code), digest(pair.side_b.code)]}
    return prompts, keys, private


def validate_design(prompts: list[dict], keys: list[dict]) -> dict:
    pi = {p["id"]: p for p in prompts}
    if len(pi) != len(prompts) or len({k["id"] for k in keys}) != len(keys):
        raise ValueError("duplicate ID")
    if set(pi) != {k["id"] for k in keys}:
        raise ValueError("prompt/key coverage mismatch")
    groups = {}
    for k in keys:
        if set(pi[k["id"]]) != {"id", "text"}:
            raise ValueError("model packet contains metadata")
        if digest(pi[k["id"]]["text"]) != k["prompt_sha256"]:
            raise ValueError("prompt hash mismatch")
        groups.setdefault(k["case_id"], []).append(k)
    for rows in groups.values():
        cells = {(r["order"], r["tag_assignment"], r["task"]) for r in rows}
        expected = {(o, t, task) for o in range(2) for t in range(2)
                    for task in ("security", "binding_K7", "binding_M2")}
        if len(rows) != 12 or cells != expected:
            raise ValueError("incomplete factorial design")
        indexed = {(r["order"], r["tag_assignment"], r["task"]): r for r in rows}
        for o in range(2):
            for t in range(2):
                if len({indexed[o, t, task]["body_sha256"] for task in ("security", "binding_K7", "binding_M2")}) != 1:
                    raise ValueError("tasks do not share code body")
                for task in ("security", "binding_K7", "binding_M2"):
                    a = indexed[o, t, task]["gold"]
                    if a not in {"A", "B"} or a == indexed[1-o, t, task]["gold"]:
                        # Tag placement stays at display positions under order flips.
                        if task == "security" or a not in {"A", "B"}:
                            raise ValueError("invalid swap gold")
                if indexed[o, t, "security"]["gold"] != indexed[o, 1-t, "security"]["gold"]:
                    raise ValueError("security gold depends on tag")
                if indexed[o, t, "binding_K7"]["gold"] == indexed[o, t, "binding_M2"]["gold"]:
                    raise ValueError("binding targets not complementary")
                if indexed[o, t, "binding_K7"]["gold"] != ("A" if t == 0 else "B"):
                    raise ValueError("binding gold not tag-bound")
    return {"status": "ok", "cases": len(groups), "prompts": len(prompts)}
