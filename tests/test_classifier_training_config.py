from __future__ import annotations

import ast
from pathlib import Path


def test_classifier_training_entrypoint_threads_config_seed_into_training_args() -> None:
    source = Path("scripts/train_eval_codexglue_classifier.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    training_args_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "TrainingArguments"
    ]

    assert training_args_calls
    keyword_names = {keyword.arg for keyword in training_args_calls[0].keywords}
    assert "seed" in keyword_names
    assert "data_seed" in keyword_names
    assert "transformers.set_seed(seed)" in source
