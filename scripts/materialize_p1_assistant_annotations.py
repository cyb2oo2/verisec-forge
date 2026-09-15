"""Serialize already-authored assistant decisions; this does not run an LLM."""
import hashlib
import argparse
import json
from pathlib import Path
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vrf.ai_annotation import input_hash, validate_annotation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-v3', action='store_true')
    args = parser.parse_args()
    bundle = ROOT / ("data/annotation/p1_ai_source_v3" if args.source_v3 else "data/annotation/binding_semantics_p1_ai_v1")
    report = ROOT / "reports/scientific_review_2026_09_07/p1"
    raw = report / ("assistant_annotation_decisions_source_v3.json" if args.source_v3 else "assistant_annotation_decisions_v1.json")
    out = ROOT / ("data/annotation/p1_assistant_source_v3" if args.source_v3 else "data/annotation/p1_assistant_diagnostic_v1")
    if out.exists():
        raise FileExistsError("Refusing to overwrite actual annotation artifacts")
    cases = json.loads((bundle / "cases.json").read_text(encoding="utf-8"))
    decisions = json.loads(raw.read_text(encoding="utf-8"))
    if sorted(r[0] for r in decisions) != list(range(len(cases))):
        raise ValueError("decision coverage mismatch")
    responses = []
    for i, side, context, confidence, summary, evidence, triggers, missing, alternative in decisions:
        c = cases[i]
        r = dict(case_id=c["case_id"], input_sha256=input_hash(c["case_id"], c["candidate_A"], c["candidate_B"]),
                 annotation_source="ai", vulnerable_side=side, context_sufficient=context, confidence=confidence,
                 summary=summary, evidence=[dict(side=e[0], start_line=e[1], end_line=e[2], reason=e[3]) for e in evidence],
                 trigger_conditions=triggers, missing_context=missing, alternative_explanation=alternative)
        validate_annotation(r, c)
        responses.append(r)
    out.mkdir(parents=True)
    response_path = out / "responses.jsonl"
    response_path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in responses), encoding="utf-8")
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    metadata = dict(provider="OpenAI via current Codex conversation", model_id="current_assistant_exact_serving_id_unavailable",
        model_version="unknown", run_id="p1-assistant-source-v3" if args.source_v3 else "p1-assistant-diagnostic-v1", started_at="2026-09-09 (conversation turn; exact start unavailable)",
        completed_at=now, annotation_source="ai", mock=False, parameters={"sampling_parameters": "host-controlled, unavailable"},
        execution_mode="current_assistant_context", independent_contexts=False, prepared_requests_executed_verbatim=False,
        requests_sha256=sha(bundle / "requests.jsonl"), responses_sha256=sha(response_path),
        raw_responses_path=str(raw), raw_responses_sha256=sha(raw),
        requests_hash_role="reference template pack, not an API dispatch log",
        actual_input_sha256=sha(bundle / "cases.json"),
        execution_disclosure=f"Assistant read all {len(cases)} displayed code pairs in batches in this existing conversation. Prior project context visible. No external provider API call, no independent sessions, no blinded certification. Judgments were newly authored for these inputs.",
        authorship="Judgments authored in assistant tool message; script only maps fields and verifies input/evidence.")
    (out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"assistant_authored_cases": len(responses), "provider_api_calls": 0, "mock": False}))


if __name__ == "__main__":
    main()
