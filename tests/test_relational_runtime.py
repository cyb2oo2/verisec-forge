from vrf.relational_runtime import (
    materialize_context_pressure,
    materialize_runtime_rows,
    runtime_accounting,
)


class CharacterTokenizer:
    is_fast = True

    def encode(self, text, add_special_tokens=True):
        prefix = [9001] if add_special_tokens else []
        return prefix + [ord(char) for char in text]

    def __call__(
        self,
        text,
        *,
        add_special_tokens=True,
        return_offsets_mapping=True,
        truncation=False,
    ):
        del return_offsets_mapping, truncation
        ids = self.encode(text, add_special_tokens=add_special_tokens)
        offsets = ([(0, 0)] if add_special_tokens else []) + [
            (index, index + 1) for index in range(len(text))
        ]
        return {"input_ids": ids, "offset_mapping": offsets}

    def decode(self, ids, skip_special_tokens=True):
        return "".join(
            chr(value)
            for value in ids
            if not (skip_special_tokens and value == 9001)
        )


def test_occurrence_aware_runtime_accounting_does_not_match_duplicate_elsewhere():
    text = "header\n-return 0;\ncontext return 0;\n+return 1;\n"
    accounting = runtime_accounting(
        text,
        tokenizer=CharacterTokenizer(),
        model_id="demo",
        tokenizer_id="character",
        max_length=20,
        truncation_side="right",
        add_special_tokens=False,
    )

    assert accounting["critical_lines_total"] == 2
    assert accounting["critical_lines_visible"] == 1
    assert accounting["critical_line_visibility_ratio"] == 0.5
    assert accounting["critical_tokens_visible"] < accounting[
        "critical_tokens_total"
    ]


def test_left_and_right_truncation_track_exact_changed_occurrences():
    text = "-early\n" + ("x" * 40) + "\n+late\n"
    right = runtime_accounting(
        text,
        tokenizer=CharacterTokenizer(),
        model_id="demo",
        tokenizer_id="character",
        max_length=20,
        truncation_side="right",
        add_special_tokens=False,
    )
    left = runtime_accounting(
        text,
        tokenizer=CharacterTokenizer(),
        model_id="demo",
        tokenizer_id="character",
        max_length=20,
        truncation_side="left",
        add_special_tokens=False,
    )

    assert right["critical_line_occurrences"][0]["fully_visible"] is True
    assert right["critical_line_occurrences"][1]["fully_visible"] is False
    assert left["critical_line_occurrences"][0]["fully_visible"] is False
    assert left["critical_line_occurrences"][1]["fully_visible"] is True


def test_context_pressure_hits_runtime_token_ratio():
    base = (
        "Task\nOutput\n\nUnified diff from Side A to Side B:\n"
        "--- Side A\n+++ Side B\n-old\n+new\n"
    )
    _, metadata = materialize_context_pressure(
        base,
        tokenizer=CharacterTokenizer(),
        target_ratio=0.5,
        add_special_tokens=False,
    )

    assert abs(metadata["achieved_budget_ratio"] - 0.5) <= 0.10


def test_runtime_materialization_records_model_specific_configuration():
    base = {
        "id": "demo::base",
        "base_id": "demo::base",
        "pair_key": "same",
        "cluster_id": "source::same",
        "dataset": "source",
        "expected_relation": "identity",
        "gold_riskier_side": "A",
        "text": (
            "Task\nUnified diff from Side A to Side B:\n"
            "--- Side A\n+++ Side B\n-old\n+new\n"
        ),
        "runtime_transform": {},
    }
    pressure = {
        **base,
        "id": "demo::pressure",
        "expected_relation": "context_pressure",
        "runtime_transform": {
            "operation": "insert_token_budget_padding_before_diff",
            "target_budget_ratio": 0.25,
        },
    }
    rows = materialize_runtime_rows(
        [base, pressure],
        tokenizer=CharacterTokenizer(),
        model_id="model-x",
        tokenizer_id="character",
        max_length=128,
        truncation_side="right",
        add_special_tokens=False,
    )

    assert rows[0]["runtime_accounting"]["model_id"] == "model-x"
    assert (
        rows[0]["runtime_accounting"]["offset_mapping_quality"]
        == "exact_fast_tokenizer"
    )
    assert rows[1]["runtime_accounting"]["achieved_budget_ratio"] > 0
    assert rows[1]["runtime_accounting"]["transformation_tokens_total"] > 0
    assert (
        rows[1]["runtime_accounting"]["transformation_tokens_visible"]
        <= rows[1]["runtime_accounting"]["transformation_tokens_total"]
    )


def test_slow_tokenizer_is_rejected_for_exact_visibility():
    tokenizer = CharacterTokenizer()
    tokenizer.is_fast = False

    try:
        runtime_accounting(
            "-old\n+new\n",
            tokenizer=tokenizer,
            model_id="demo",
            tokenizer_id="slow",
            max_length=20,
            truncation_side="right",
            add_special_tokens=False,
        )
    except ValueError as error:
        assert "fast tokenizer" in str(error)
    else:
        raise AssertionError("slow tokenizer must not enter exact accounting")
