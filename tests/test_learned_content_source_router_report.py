from scripts.build_learned_content_source_router_report import build_report, predict_one, train_nb


def test_character_ngram_nb_learns_simple_source_markers():
    model = train_nb(
        [
            {"true_source": "PrimeVul-time", "pair_key": "p1", "text": "linux cve unified diff struct kfree"},
            {"true_source": "DeltaSecommits", "pair_key": "d1", "text": "tensorflow ghsa tensor op_requires"},
            {"true_source": "PatchEval", "pair_key": "e1", "text": "language go func err nil"},
        ],
        max_features=500,
    )

    assert predict_one(model, "tensorflow tensor errors") == "DeltaSecommits"
    assert predict_one(model, "language go func") == "PatchEval"


def test_learned_content_source_router_builds_surface_and_diff_metrics():
    payload = build_report(
        train_prime_metadata=[{"pair_key": "p1", "pair_text": "Project: linux\nUnified diff:\n+struct kfree"}],
        train_delta_metadata=[{"pair_key": "d1", "pair_text": "Project: https://github.com/tensorflow/tensorflow\nUnified diff:\n+OP_REQUIRES tensor"}],
        train_patch_metadata=[{"pair_key": "e1", "pair_text": "Language: Go\nUnified diff:\n+func f() { err := nil }"}],
        eval_prime_metadata=[{"pair_key": "p2", "pair_text": "Project: linux\nUnified diff:\n+struct kfree"}],
        eval_delta_metadata=[{"pair_key": "d2", "pair_text": "Project: https://github.com/tensorflow/tensorflow\nUnified diff:\n+OP_REQUIRES tensor"}],
        eval_patch_metadata=[{"pair_key": "e2", "pair_text": "Language: Go\nUnified diff:\n+func f() { err := nil }"}],
        max_features=1000,
    )

    assert payload["status"] == "ok"
    assert payload["routing_metrics"]["learned_surface"]["row_accuracy"] == 1.0
    assert payload["routing_metrics"]["learned_diff_body"]["pair_group_accuracy"] == 1.0
