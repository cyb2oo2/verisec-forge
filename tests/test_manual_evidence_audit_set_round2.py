from scripts.build_manual_evidence_audit_set_round2 import exclude_round1_candidates


def test_exclude_round1_candidates_dedupes_by_audit_id_and_pair_key():
    all_rows = [
        {"audit_id": "a1", "pair_key": "proj|commit1|CVE-1"},
        {"audit_id": "a2", "pair_key": "proj|commit1|CVE-1"},  # same pair, different audit_id
        {"audit_id": "a3", "pair_key": "proj|commit2|CVE-2"},
    ]
    excluded = [{"audit_id": "a1", "pair_key": "proj|commit1|CVE-1"}]

    remaining = exclude_round1_candidates(all_rows, excluded)

    assert remaining == [{"audit_id": "a3", "pair_key": "proj|commit2|CVE-2"}]


def test_exclude_round1_candidates_returns_empty_when_source_is_exhausted():
    all_rows = [
        {"audit_id": "a1", "pair_key": "proj|commit1|CVE-1"},
        {"audit_id": "a2", "pair_key": "proj|commit1|CVE-1"},
    ]
    excluded = [{"audit_id": "a1", "pair_key": "proj|commit1|CVE-1"}]

    remaining = exclude_round1_candidates(all_rows, excluded)

    assert remaining == []
