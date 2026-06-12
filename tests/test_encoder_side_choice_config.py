import json
from pathlib import Path


def test_codebert_control_uses_same_training_rows_and_bounded_claim():
    config = json.loads(
        Path(
            "configs/research_primevul_joint_side_choice_codebert_v1.json"
        ).read_text(encoding="utf-8")
    )

    assert config["train_dataset"].endswith(
        "secure_code_primevul_joint_side_choice_train_v1.jsonl"
    )
    assert config["max_seq_length"] == 512
    assert config["training"]["num_train_epochs"] == 1
