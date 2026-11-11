import csv
import json

import chromadb
import pytest

from app.ui import controller
from app.tools.retrieval import COLLECTION_NAME, HashingEmbeddingFunction
from kb.ingest import CONTROLS_PATH, build_index

VALID_RECORD = {
    "finding_id": "SYN-0001",
    "resource_id": "arn:aws:s3:::example-bucket",
    "resource_type": "S3",
    "region": "us-east-1",
    "config": {"BlockPublicAcls": False, "BlockPublicPolicy": False, "IgnorePublicAcls": False, "RestrictPublicBuckets": False},
    "tags": {"Name": "example-bucket"},
    "source": "synthetic",
    "label": "M01",
}


@pytest.fixture
def real_collection(tmp_path):
    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    build_index(controls_path=CONTROLS_PATH, embedding_function=HashingEmbeddingFunction(), client=client)
    return client.get_collection(COLLECTION_NAME, embedding_function=HashingEmbeddingFunction())


def write_json(tmp_path, records, name="upload.json"):
    path = tmp_path / name
    path.write_text(json.dumps(records))
    return str(path)


def test_analyze_file_populates_results_for_a_valid_finding(tmp_path, real_collection):
    db_path = tmp_path / "approvals.db"
    upload_path = write_json(tmp_path, [VALID_RECORD])

    outcome = controller.analyze_file(upload_path, force_mock=True, collection=real_collection, db_path=db_path, log_path=tmp_path / "logs.jsonl")

    assert outcome == {"error": None, "analyzed": 1, "needs_review": 0, "used_mock": True}
    rows = controller.results_table(db_path=db_path)
    assert len(rows) == 1
    assert rows[0][0] == "SYN-0001"
    assert rows[0][3] == "M01"


def test_analyze_file_records_malformed_entries_as_needs_review(tmp_path, real_collection):
    db_path = tmp_path / "approvals.db"
    broken = dict(VALID_RECORD)
    del broken["resource_id"]
    upload_path = write_json(tmp_path, [broken])

    outcome = controller.analyze_file(upload_path, force_mock=True, collection=real_collection, db_path=db_path, log_path=tmp_path / "logs.jsonl")

    assert outcome["analyzed"] == 0
    assert outcome["needs_review"] == 1
    rows = controller.results_table(db_path=db_path)
    assert len(rows) == 1
    assert rows[0][1] == "UNKNOWN"
    assert rows[0][3] == "NEEDS_REVIEW"


def test_analyze_file_with_broken_syntax_returns_an_error_not_a_crash(tmp_path):
    db_path = tmp_path / "approvals.db"
    upload_path = tmp_path / "broken.json"
    upload_path.write_text("{not valid json")

    outcome = controller.analyze_file(str(upload_path), force_mock=True, db_path=db_path)

    assert outcome["error"] is not None
    assert outcome["analyzed"] == 0
    assert controller.results_table(db_path=db_path) == []


def test_finding_detail_and_agent_trace_round_trip(tmp_path, real_collection):
    db_path = tmp_path / "approvals.db"
    upload_path = write_json(tmp_path, [VALID_RECORD])
    controller.analyze_file(upload_path, force_mock=True, collection=real_collection, db_path=db_path, log_path=tmp_path / "logs.jsonl")

    detail = controller.finding_detail("SYN-0001", db_path=db_path)
    assert detail["misconfig_type"] == "M01"
    assert detail["field_sources"]["misconfig_type"] == "Rule"
    assert detail["requires_approval"] is True

    trace = controller.agent_trace("SYN-0001", db_path=db_path)
    assert trace[0]["tool"] == "check_misconfig"


def test_finding_detail_for_unknown_id_returns_none(tmp_path):
    assert controller.finding_detail("nope", db_path=tmp_path / "approvals.db") is None


def test_pending_queue_and_approval_flow(tmp_path, real_collection):
    db_path = tmp_path / "approvals.db"
    upload_path = write_json(tmp_path, [VALID_RECORD])
    controller.analyze_file(upload_path, force_mock=True, collection=real_collection, db_path=db_path, log_path=tmp_path / "logs.jsonl")

    pending = controller.pending_queue(db_path=db_path)
    assert len(pending) == 1
    assert pending[0][0] == "SYN-0001"

    assert controller.approve("SYN-0001", actor="jaya", db_path=db_path) is True
    assert controller.pending_queue(db_path=db_path) == []

    rows = controller.results_table(db_path=db_path)
    assert rows[0][6] == "approved"


def test_export_audit_log_csv_contains_the_analysis_and_approval(tmp_path, real_collection):
    db_path = tmp_path / "approvals.db"
    upload_path = write_json(tmp_path, [VALID_RECORD])
    controller.analyze_file(upload_path, force_mock=True, collection=real_collection, db_path=db_path, log_path=tmp_path / "logs.jsonl")
    controller.approve("SYN-0001", actor="jaya", db_path=db_path)

    csv_path = controller.export_audit_log_csv(db_path=db_path, out_path=tmp_path / "audit.csv")
    with open(csv_path) as f:
        rows = list(csv.DictReader(f))
    actions = [r["action"] for r in rows]
    assert "analyzed" in actions
    assert "approved" in actions


def test_export_fixes_text_includes_fix_snippet_and_side_effects(tmp_path, real_collection):
    db_path = tmp_path / "approvals.db"
    upload_path = write_json(tmp_path, [VALID_RECORD])
    controller.analyze_file(upload_path, force_mock=True, collection=real_collection, db_path=db_path, log_path=tmp_path / "logs.jsonl")

    out_path = controller.export_fixes_text(db_path=db_path, out_path=tmp_path / "fixes.txt")
    text = open(out_path).read()
    assert "SYN-0001" in text
    assert "aws_s3_bucket_public_access_block" in text
    assert "Side effects" in text


def test_monitoring_summary_reports_totals(tmp_path, real_collection):
    db_path = tmp_path / "approvals.db"
    log_path = tmp_path / "logs.jsonl"
    upload_path = write_json(tmp_path, [VALID_RECORD])
    controller.analyze_file(upload_path, force_mock=True, collection=real_collection, db_path=db_path, log_path=log_path)

    summary = controller.monitoring_summary(db_path=db_path, log_path=log_path)
    assert summary["total_runs"] == 1
    assert summary["by_misconfig_type"]["M01"] == 1
    assert summary["logged"]["total_runs"] == 1
    assert "check_misconfig" in summary["logged"]["avg_latency_by_tool"]


def test_ollama_is_available_returns_a_bool_without_crashing():
    assert isinstance(controller.ollama_is_available(), bool)
