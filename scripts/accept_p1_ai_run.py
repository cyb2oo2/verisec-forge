"""Accept a complete AI run. Does not execute a provider or a tested model."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vrf.ai_annotation_run import assemble_run
from vrf.binding_semantics import validate_design


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Refusing to overwrite accepted run")
    load = lambda p: json.loads(p.read_text(encoding="utf-8"))
    report = ROOT / "reports/scientific_review_2026_09_07/p1"
    prep = load(report / "ai_annotation_preparation.json")
    selection = load(report / "selection_v2.json")
    bundle = ROOT / prep["bundle"]
    prior = ROOT / selection["bundle"]
    cases_path = bundle / "cases.json"
    if sha(cases_path) != prep["hashes"]["cases.json"]:
        raise ValueError("annotation input drift")
    for name in ("PRIVATE_provenance.json", "PRIVATE_keys.json", "model_prompts.json"):
        if sha(prior / name) != selection["bundle_hashes"][name]:
            raise ValueError("evaluation provenance drift")
    validate_design(load(prior / "model_prompts.json"), load(prior / "PRIVATE_keys.json"))
    metadata = load(args.metadata)
    if metadata.get("requests_sha256") != prep["hashes"]["requests.jsonl"]:
        raise ValueError("run not bound to prepared requests")
    if metadata.get("responses_sha256") != sha(args.responses):
        raise ValueError("response hash mismatch")
    raw = Path(metadata.get("raw_responses_path", ""))
    if not raw.is_file() or metadata.get("raw_responses_sha256") != sha(raw):
        raise ValueError("missing or modified raw responses")
    responses = [json.loads(line) for line in args.responses.read_text(encoding="utf-8").splitlines() if line.strip()]
    result = assemble_run(load(cases_path), responses, metadata,
                          load(prior / "PRIVATE_provenance.json"), load(prior / "PRIVATE_keys.json"))
    result["input_hashes"] = {str(p): sha(p) for p in (args.responses, args.metadata, raw, cases_path)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "by_source": result["by_source"]}, indent=2))


if __name__ == "__main__":
    main()
