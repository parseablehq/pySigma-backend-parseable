from scripts.corpus_sweep import baseline_errors

BASELINE = {
    "corpus_commit": "abc123",
    "files": 3783,
    "minimum_success": 3734,
    "maximum_statuses": {"unsupported": 24, "pipeline_required": 25},
    "allowed_statuses": ["success", "unsupported", "pipeline_required"],
}


def summary(**statuses: int) -> dict:
    return {"files": 3783, "statuses": statuses}


def test_corpus_baseline_accepts_current_result_and_improvements():
    assert not baseline_errors(
        summary(success=3734, unsupported=24, pipeline_required=25), BASELINE, "abc123"
    )
    assert not baseline_errors(
        summary(success=3758, pipeline_required=25), BASELINE, "abc123"
    )


def test_corpus_baseline_rejects_compatibility_regressions():
    errors = baseline_errors(
        summary(success=3733, unsupported=25, pipeline_required=24), BASELINE, "abc123"
    )
    assert "success regressed: minimum 3734, got 3733" in errors
    assert "unsupported regressed: maximum 24, got 25" in errors


def test_corpus_baseline_rejects_unexpected_status_and_file_drift():
    current = summary(success=3734, unsupported=24, pipeline_required=24, backend_bug=1)
    current["files"] = 3784
    errors = baseline_errors(current, BASELINE, "wrong")
    assert "corpus commit changed: expected abc123, got wrong" in errors
    assert "files changed: expected 3783, got 3784" in errors
    assert "unexpected statuses: backend_bug=1" in errors
