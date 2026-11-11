from app.monitoring import compute_monitoring_stats, log_run, log_tool_call, read_events


def test_log_run_then_read_events_round_trips(tmp_path):
    log_path = tmp_path / "logs.jsonl"
    log_run("f1", "M01", 1.5, log_path=log_path)
    events = read_events(log_path)
    assert len(events) == 1
    assert events[0]["event"] == "run"
    assert events[0]["finding_id"] == "f1"
    assert events[0]["duration_seconds"] == 1.5
    assert "timestamp" in events[0]


def test_read_events_filters_by_type(tmp_path):
    log_path = tmp_path / "logs.jsonl"
    log_run("f1", "M01", 1.0, log_path=log_path)
    log_tool_call("f1", "check_misconfig", 0.1, log_path=log_path)
    assert len(read_events(log_path)) == 2
    assert len(read_events(log_path, event="run")) == 1
    assert len(read_events(log_path, event="tool_call")) == 1


def test_read_events_on_missing_file_returns_empty_list(tmp_path):
    assert read_events(tmp_path / "does_not_exist.jsonl") == []


def test_read_events_skips_corrupt_lines(tmp_path):
    log_path = tmp_path / "logs.jsonl"
    log_run("f1", "M01", 1.0, log_path=log_path)
    with log_path.open("a") as f:
        f.write("not valid json\n")
    log_run("f2", "M02", 2.0, log_path=log_path)
    events = read_events(log_path, event="run")
    assert len(events) == 2


def test_compute_monitoring_stats_aggregates_runs_and_tool_latency(tmp_path):
    log_path = tmp_path / "logs.jsonl"
    log_run("f1", "M01", 2.0, log_path=log_path)
    log_run("f2", "M02", 4.0, log_path=log_path)
    log_tool_call("f1", "check_misconfig", 0.1, log_path=log_path)
    log_tool_call("f2", "check_misconfig", 0.3, log_path=log_path)
    log_tool_call("f2", "lookup_controls", 0.5, log_path=log_path)

    stats = compute_monitoring_stats(log_path)
    assert stats["total_runs"] == 2
    assert stats["total_errors"] == 0
    assert stats["avg_run_seconds"] == 3.0
    assert stats["max_run_seconds"] == 4.0
    assert stats["avg_latency_by_tool"]["check_misconfig"] == 0.2
    assert stats["avg_latency_by_tool"]["lookup_controls"] == 0.5


def test_compute_monitoring_stats_counts_errors(tmp_path):
    log_path = tmp_path / "logs.jsonl"
    log_run("f1", "NEEDS_REVIEW", 1.0, error="LLM call timed out", log_path=log_path)
    log_run("f2", "M01", 1.0, log_path=log_path)
    stats = compute_monitoring_stats(log_path)
    assert stats["total_errors"] == 1


def test_compute_monitoring_stats_on_empty_log_does_not_crash(tmp_path):
    stats = compute_monitoring_stats(tmp_path / "empty.jsonl")
    assert stats["total_runs"] == 0
    assert stats["avg_run_seconds"] == 0.0
    assert stats["avg_latency_by_tool"] == {}


def test_log_event_never_raises_on_unwritable_path():
    # A path whose parent cannot be created (file where a dir is expected).
    import tempfile

    with tempfile.NamedTemporaryFile() as f:
        bogus_path = f"{f.name}/subdir/logs.jsonl"
        log_run("f1", "M01", 1.0, log_path=bogus_path)  # must not raise
