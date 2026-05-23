from scripts import build_final_submission_statistics as stats


def test_final_submission_statistics_rows_cover_main_claims():
    rows = stats.build_rows()
    claim_areas = {row["claim_area"] for row in rows}

    assert len(rows) == 14
    assert "Shortcut diagnosis" in claim_areas
    assert "Task-structured decoding" in claim_areas
    assert "External validation" in claim_areas
    assert "Learned router boundary" in claim_areas
    assert any("0.8572" in row["primary_result"] for row in rows)
    assert any("open-set source discovery is not claimed" in row["reviewer_safe_interpretation"] for row in rows)


def test_final_submission_statistics_markdown_has_boundary_notes():
    markdown = stats.render_markdown(stats.build_rows())

    assert markdown.startswith("# Final Submission Statistics")
    assert "same-source PrimeVul `0.9524`" in markdown
    assert "pair-coupled decoding versus bucket routing" in markdown
    assert "Evidence localization and safe flip gates are audit-loop diagnostics" in markdown
