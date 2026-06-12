from pathlib import Path


def test_batch_shape_audit_script_exists_with_bounded_claim():
    text = Path("scripts/audit_qwen_batch_shape_stability.py").read_text(
        encoding="utf-8"
    )

    assert "identical target text" in text
    assert "not widespread prediction instability" in text
