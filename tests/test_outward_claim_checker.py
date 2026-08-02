"""Behavioural tests for the outward-facing claim integrity checker.

These test the *checker*, not the documents: each case writes a small synthetic
document and asserts the checker's verdict. That keeps them from degenerating
into "assert this string appears in that file" tests, which lock in wording
without validating anything.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from scripts.check_outward_claims import (  # noqa: E402
    check_file,
    check_staleness,
    document_status,
    load_rules,
    phrase_is_negated,
)

RULES_PATH = ROOT / "reproducibility/outward_claim_rules.json"


@pytest.fixture(scope="module")
def rules() -> dict:
    return load_rules(RULES_PATH)


def _check(tmp_path: Path, body: str, rules: dict, name: str = "doc.md") -> list[dict]:
    # The checker reports paths relative to the repo root, so write inside it.
    target = ROOT / "reports" / f"_tmp_claimcheck_{name}"
    target.write_text(body, encoding="utf-8")
    try:
        return check_file(target, rules)
    finally:
        target.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 1. An unqualified withdrawn claim fails
# ---------------------------------------------------------------------------


def test_unqualified_withdrawn_metric_is_flagged(tmp_path: Path, rules: dict) -> None:
    body = "# Results\n\nOur detector reaches a three-seed mean balanced accuracy of `0.8287`.\n"
    findings = _check(tmp_path, body, rules)
    assert any(f["kind"] == "unqualified_withdrawn_value" for f in findings)
    assert any(f["claim_id"] == "primevul-diff-only-mainline" for f in findings)


def test_unqualified_pair_coupled_metric_is_flagged(tmp_path: Path, rules: dict) -> None:
    body = "# Results\n\nPair-coupled decoding reaches `0.8572` mean balanced accuracy.\n"
    findings = _check(tmp_path, body, rules)
    assert any(f["claim_id"] == "pair-coupled-system-layer" for f in findings)


# ---------------------------------------------------------------------------
# 2. Clearly labelled historical discussion passes
# ---------------------------------------------------------------------------


def test_document_level_historical_banner_passes(tmp_path: Path, rules: dict) -> None:
    body = (
        "# Old Draft\n\n"
        "> **HISTORICAL DOCUMENT — CONTAINS WITHDRAWN RESULTS.**\n"
        "> Do not cite as the current conclusion.\n\n"
        "Pair-coupled decoding reaches `0.8572`, the strongest system layer, with delta `0.0348`.\n"
    )
    assert document_status(body.split("\n"), rules) == "historical"
    assert _check(tmp_path, body, rules) == []


def test_inline_withdrawal_label_passes(tmp_path: Path, rules: dict) -> None:
    body = (
        "# Results\n\n"
        "**WITHDRAWN.** The historical three-seed mean was `0.8287`; it is matched by a\n"
        "semantics-free character control and is no longer presented as evidence.\n"
    )
    assert _check(tmp_path, body, rules) == []


def test_corrected_banner_allows_numbers_but_still_checks_wording(tmp_path: Path, rules: dict) -> None:
    """A current-facing corrected doc may cite history but not re-assert the claim."""

    head = (
        "# Summary\n\n"
        "> **CORRECTED — WITHDRAWN RESULTS.**\n"
        "> No semantic advantage beyond diff structure was established.\n\n"
    )
    numbers_only = head + "The historical figure was `0.8287`.\n"
    assert document_status(numbers_only.split("\n"), rules) == "corrected"
    assert _check(tmp_path, numbers_only, rules) == []

    reasserted = head + ("x\n" * 30) + "Diff-only paired reasoning is the credible mainline of this project.\n"
    findings = _check(tmp_path, reasserted, rules, name="b.md")
    assert any(f["kind"] == "prohibited_active_wording" for f in findings), (
        "a corrected document must not be allowed to re-assert the withdrawn claim"
    )


# ---------------------------------------------------------------------------
# 3. Paraphrased semantic-advantage language is detected
# ---------------------------------------------------------------------------


def test_paraphrased_semantic_claim_is_detected(tmp_path: Path, rules: dict) -> None:
    body = "# Discussion\n\nThis experiment establishes semantic reasoning over secure patches.\n"
    findings = _check(tmp_path, body, rules)
    assert any(f["claim_id"] == "semantic-reasoning-claim" for f in findings)


def test_controls_protect_paraphrase_is_detected(tmp_path: Path, rules: dict) -> None:
    body = "# Controls\n\nThe near-chance controls protect the paired-diff formulation.\n"
    findings = _check(tmp_path, body, rules)
    assert any(f["claim_id"] == "controls-protect-formulation" for f in findings)


def test_negated_mention_is_not_flagged(tmp_path: Path, rules: dict) -> None:
    """Denying a claim must pass; asserting it must not."""

    assert phrase_is_negated("This is not localization accuracy.", "localization accuracy")
    assert not phrase_is_negated("Localization accuracy reached 0.76.", "localization accuracy")
    body = (
        "# Evidence\n\n"
        "This measurement must not be cited as localization accuracy, and it is not\n"
        "independently human validated.\n"
    )
    assert _check(tmp_path, body, rules) == []


# ---------------------------------------------------------------------------
# 4. Current corrected wording passes
# ---------------------------------------------------------------------------


def test_current_corrected_wording_passes(tmp_path: Path, rules: dict) -> None:
    body = (
        "# Result\n\n"
        "Under the closed-world pair constraint the detector reaches balanced accuracy\n"
        "`0.8596`; a semantics-free character-level diff structural control reaches `0.8588`\n"
        "on the same evaluation population. The difference is `+0.0008` with a pair-group\n"
        "clustered 95% CI of `[-0.0202, +0.0222]`. No semantic advantage beyond diff\n"
        "structure was established.\n"
    )
    assert _check(tmp_path, body, rules) == []


# ---------------------------------------------------------------------------
# 5. Gate precision without uncertainty fails; with uncertainty passes
# ---------------------------------------------------------------------------


def test_gate_precision_without_uncertainty_is_flagged(tmp_path: Path, rules: dict) -> None:
    body = "# Gate\n\nThe evidence-conditioned gate achieves precision `1.0000` on the holdout pool.\n"
    findings = _check(tmp_path, body, rules)
    assert any(f["kind"] == "precision_without_uncertainty" for f in findings)


def test_gate_precision_with_sample_size_and_interval_passes(tmp_path: Path, rules: dict) -> None:
    body = (
        "# Gate\n\n"
        "Accept precision is `1.0000` on n=4 accepted pairs, exact 95% CI `[0.3976, 1.0]`,\n"
        "selected on the same pool it is reported on.\n"
    )
    assert _check(tmp_path, body, rules) == []


# ---------------------------------------------------------------------------
# 6. Stale generated documentation fails
# ---------------------------------------------------------------------------


def test_staleness_is_content_based_not_mtime_based(rules: dict) -> None:
    """Touching a file must not make documentation look stale.

    A checkout stamps every file with the clone time, so an mtime comparison is
    both false-negative on a fresh clone and false-positive after an unrelated
    touch. Only content drift may count.
    """

    import os

    entry = rules["staleness"][0]
    generated = ROOT / entry["generated"]
    if not generated.exists():
        pytest.skip("staleness pair not present")

    stat = generated.stat()
    try:
        # Move the mtime far into the past without changing a byte.
        os.utime(generated, (stat.st_atime, stat.st_mtime - 86_400))
        findings = check_staleness(rules)
        assert not any(
            f["file"] == entry["generated"] and f["kind"] == "stale_generated_documentation"
            for f in findings
        ), "an mtime change alone was reported as staleness; the check is not content-based"
    finally:
        os.utime(generated, (stat.st_atime, stat.st_mtime))


def test_content_drift_in_a_generated_document_is_flagged(rules: dict) -> None:
    """Editing a generated document away from its recorded hash must be caught."""

    entry = rules["staleness"][0]
    generated = ROOT / entry["generated"]
    manifest = ROOT / "reports/REPRODUCTION_PROVENANCE.json"
    if not generated.exists() or not manifest.exists():
        pytest.skip("staleness pair or provenance manifest not present")

    recorded = json.loads(manifest.read_text(encoding="utf-8"))
    tracked = {
        item["path"]
        for stage in recorded.get("stages", [])
        for item in stage.get("inputs", []) + stage.get("outputs", [])
        if item.get("sha256")
    }
    if entry["generated"] not in tracked:
        pytest.skip("generated document has no recorded provenance hash")

    original = generated.read_bytes()
    try:
        generated.write_bytes(original + b"\n<!-- drift -->\n")
        findings = check_staleness(rules)
        assert any(
            f["file"] == entry["generated"] and f["kind"] == "stale_generated_documentation"
            for f in findings
        ), "content drift from the recorded provenance hash was not flagged"
    finally:
        generated.write_bytes(original)

    assert not any(
        f["file"] == entry["generated"] and f["kind"] == "stale_generated_documentation"
        for f in check_staleness(rules)
    ), "restoring the original content should clear the finding"


# ---------------------------------------------------------------------------
# 7. The repository itself is clean
# ---------------------------------------------------------------------------


def test_repository_has_no_unqualified_outward_claims() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_outward_claims.py", "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    assert completed.returncode == 0, json.dumps(payload["violations"][:10], indent=2)
    assert payload["violations"] == []
    assert payload["files_scanned"] > 50


def test_rules_reference_the_source_of_truth_ledger(rules: dict) -> None:
    ledger = (ROOT / rules["source_of_truth"]).read_text(encoding="utf-8")
    for claim in rules["claims"]:
        assert claim["required_qualification"], claim["id"]
        assert claim["ledger_entry"], claim["id"]
    # the ledger must actually record the corrected comparison
    assert "0.8588" in ledger and "0.8596" in ledger
