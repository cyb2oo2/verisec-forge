"""Recover selected P1 inputs from immutable commits/cache; never invent missing code."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
from vrf.source_integrity import match_patch_functions, pair_changed_functions, snippet_check


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def fetch(url, cache):
    path = cache / (sha(url.encode()) + ".bin")
    if path.exists():
        data = path.read_bytes()
    else:
        with urlopen(Request(url, headers={"User-Agent": "VeriSec-source-repair"}), timeout=30) as response:
            data = response.read(10_000_001)
        if len(data) > 10_000_000:
            raise ValueError("source download exceeds 10MB bound")
        path.write_bytes(data)
    return data, {"url": url, "path": path.relative_to(ROOT).as_posix(), "sha256": sha(data)}


def recover_delta(task, cache):
    case, row = task
    recovered, evidence = [], []
    try:
        parsed = urlparse(row["project"])
        if parsed.hostname != "github.com" or len(parsed.path.strip("/").split("/")) != 2:
            raise ValueError("unrecognized public repository")
        repo = parsed.path.strip("/").removesuffix(".git")
        commit = row["commit_sha"]
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError("non-immutable commit ID")
        raw, ref = fetch(f"https://api.github.com/repos/{repo}/commits/{commit}", cache)
        evidence.append(ref)
        metadata = json.loads(raw)
        if metadata["sha"] != commit or len(metadata["parents"]) != 1:
            raise ValueError("commit identity or single-parent requirement failed")
        parent = metadata["parents"][0]["sha"]
        paths = {f["path"] for f in row["files"]}
        for f in metadata["files"]:
            path = f["filename"]
            if path not in paths or f["status"] not in {"modified", "renamed"} or not f.get("patch"):
                continue
            extension = Path(path).suffix.lower()
            if extension not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
                continue
            before_path = f.get("previous_filename", path)
            old, old_ref = fetch(f"https://raw.githubusercontent.com/{repo}/{parent}/{quote(before_path, safe='/')}", cache)
            new, new_ref = fetch(f"https://raw.githubusercontent.com/{repo}/{commit}/{quote(path, safe='/')}", cache)
            evidence.extend([old_ref, new_ref])
            language = "c" if extension == ".c" else "cpp"
            for before, after in pair_changed_functions(old.decode("utf-8"), new.decode("utf-8"), f["patch"], language):
                recovered.append({"case_id": case["case_id"], "dataset": "deltasecommits",
                    "unit_id": sha((case["case_id"]+path+before["name"]).encode())[:24],
                    "project": case["project"], "file_path": path, "function_name": before["name"],
                    "before": before["code"], "after": after["code"], "language": language,
                    "before_lines": [before["start_line"], before["end_line"]],
                    "after_lines": [after["start_line"], after["end_line"]],
                    "before_commit": parent, "after_commit": commit,
                    "before_file_sha256": old_ref["sha256"], "after_file_sha256": new_ref["sha256"],
                    "scope": "whole parsed changed function; vulnerability relevance not certified"})
        return {"case_id": case["case_id"], "status": "recovered" if recovered else "quarantined_no_unique_clean_changed_function",
                "units": recovered, "evidence": evidence}
    except Exception as exc:
        return {"case_id": case["case_id"], "status": "quarantined_recovery_error", "error": str(exc), "units": [], "evidence": evidence}


def main():
    out = ROOT / "data/annotation/p1_source_repair_v3"
    if out.exists():
        raise FileExistsError("Refusing to overwrite repaired source version")
    cache = ROOT / "data/annotation/p1_source_recovery_cache"
    cache.mkdir(parents=True, exist_ok=True)
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["HF_DATASETS_OFFLINE"] = "1"
    from datasets import load_dataset
    patch = load_dataset("ByteDance/PatchEval", split="train")
    delta = load_dataset("rufimelo/DeltaSecommits", split="train")
    provenance_path = ROOT / "data/annotation/binding_semantics_p1_v2/PRIVATE_provenance.json"
    provenance = load(provenance_path)
    cases = {r["case_id"]: r for r in load(ROOT / "data/annotation/binding_semantics_p1_ai_v1/cases.json")}
    results, tasks = [], []
    for p in provenance:
        if p["dataset"] == "deltasecommits":
            tasks.append((p, delta[int(p["pair_key"].split("-")[1])]))
            continue
        if p["dataset"] == "patcheval":
            _, example_index, before_index = p["pair_key"].split("-")
            row = patch[int(example_index)]
            matches, rejected = match_patch_functions(row)
            matched = [m for m in matches if m[0] == int(before_index)]
            units = [{"case_id": p["case_id"], "dataset": p["dataset"], "project": p["project"],
                      "unit_id": p["case_id"], "before": b["snippet"], "after": a["snippet"],
                      "language": row["programming_language"].lower(), "file_path": b["file_path"],
                      "function_name": proof["before_syntax"]["name"], "pairing": proof,
                      "before_commit": b.get("commit"), "after_commit": a.get("commit"),
                      "scope": "cached source snippet with matched syntax identity; external context not certified"}
                     for _, b, a, proof in matched]
            # Record the old positional-pair defect even if the corrected function
            # still cannot meet the strict one-function interface requirement.
            b = row["vul_func"][int(before_index)]
            positional = row["fix_func"][int(before_index)] if int(before_index) < len(row["fix_func"]) else {}
            results.append({"case_id": p["case_id"], "status": "matched" if units else "quarantined_pairing_or_syntax",
                            "old_positional_file_mismatch": b.get("file_path") != positional.get("file_path"),
                            "units": units, "rejections": rejected})
        else:
            c = cases[p["case_id"]]
            before, after = c["candidate_A"], c["candidate_B"]
            language = "c"
            checks = [snippet_check(x, language) for x in (before, after)]
            if not all(q.get("ok") for q in checks):
                language = "cpp"
                checks = [snippet_check(x, language) for x in (before, after)]
            ok = all(q.get("ok") for q in checks) and checks[0]["name"] == checks[1]["name"]
            units = [{"case_id": p["case_id"], "dataset": p["dataset"], "project": p["project"],
                      "unit_id": p["case_id"], "before": before, "after": after, "language": language,
                      "function_name": checks[0]["name"], "scope": "existing masked A/B order, not before/after chronology"}] if ok else []
            results.append({"case_id": p["case_id"], "status": "syntax_checked" if ok else "quarantined_syntax", "units": units, "checks": checks})
    for task in tasks:
        result = recover_delta(task, cache)
        results.append(result)
        print(result["case_id"], result["status"], len(result["units"]), flush=True)
    units = [u for r in results for u in r["units"]]
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(ROOT / "checkpoints/cls_secure_code_primevul_joint_pairwise_qwen15b_lora_v1", local_files_only=True)
    # New security-only, versioned inputs. Source metadata and prior labels are kept private.
    prompts = []
    for u in units:
        u["before_sha256"], u["after_sha256"] = sha(u["before"].encode()), sha(u["after"].encode())
        for swap in (False, True):
            a, b = (u["after"], u["before"]) if swap else (u["before"], u["after"])
            text = f"Candidate A:\n{a}\n\nCandidate B:\n{b}\n\nWhich candidate is more vulnerable? Answer A or B only."
            prompts.append({"id": f"v3::{u['unit_id']}::{int(swap)}", "text": text,
                            "tokens": len(tokenizer(text, truncation=False, add_special_tokens=True)["input_ids"]),
                            "text_sha256": sha(text.encode())})
    write(out / "PRIVATE_units.json", units)
    write(out / "security_prompts.json", prompts)
    write(out / "recovery_details.json", results)
    packages = ["tree-sitter", "tree-sitter-c", "tree-sitter-cpp", "tree-sitter-javascript", "tree-sitter-python", "tree-sitter-go"]
    summary = {"status": "SOURCES_REBUILT_NOT_SEMANTICALLY_CERTIFIED", "original_cases": len(provenance),
               "cases_with_units": sum(bool(r["units"]) for r in results), "units": len(units),
               "cases_quarantined": [r["case_id"] for r in results if not r["units"]],
               "by_source": {source: {"cases_with_units": len({u['case_id'] for u in units if u['dataset']==source}),
                                     "units": sum(u['dataset']==source for u in units)}
                             for source in {p['dataset'] for p in provenance}},
               "lengths": {"prompts": len(prompts), "over_1024": sum(p['tokens']>1024 for p in prompts),
                           "over_4096": sum(p['tokens']>4096 for p in prompts), "max": max((p['tokens'] for p in prompts), default=0)},
               "parser_versions": {p: importlib.metadata.version(p) for p in packages},
               "cached_input_hashes": {c['filename']: sha(Path(c['filename']).read_bytes()) for d in (patch, delta) for c in d.cache_files},
               "bundle": out.relative_to(ROOT).as_posix(),
               "bundle_hashes": {p.name: sha(p.read_bytes()) for p in out.glob('*.json')},
               "training_or_model_inference": False, "old_annotations_transferred": False,
               "boundary": "Parser acceptance is not compilability or vulnerability gold. Multiple functions from one case remain clustered; no quota refill."}
    write(ROOT / "reports/scientific_review_2026_09_07/p1/source_repair_v3.json", summary)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
