from app.agent.loop import AgentRunResult, ToolTrace
from app.approval import (
    STATUS_AUTO_APPROVED,
    STATUS_PENDING,
    approve,
    get_monitoring_stats,
    get_result,
    list_audit_log,
    list_results,
    reject,
    save_result,
)
from app.schemas import AgentOutput, Confidence, MisconfigVerdict, Severity


def make_run_result(finding_id="f-001", requires_approval=True, misconfig_type=None, severity=None):
    if misconfig_type is None:
        misconfig_type = MisconfigVerdict.M01 if requires_approval else MisconfigVerdict.M02
    if severity is None:
        severity = Severity.HIGH if requires_approval else Severity.MEDIUM
    output = AgentOutput(
        finding_id=finding_id,
        misconfig_type=misconfig_type,
        severity=severity,
        explanation="Public bucket.",
        confidence=Confidence.HIGH,
        requires_approval=requires_approval,
    )
    trace = [ToolTrace(iteration=0, tool="check_misconfig", arguments={}, result={"misconfig_type": misconfig_type.value})]
    return AgentRunResult(output=output, trace=trace)


def test_save_result_requiring_approval_is_pending(tmp_path):
    db_path = tmp_path / "approvals.db"
    status = save_result("S3", "us-east-1", make_run_result(requires_approval=True), db_path=db_path)
    assert status == STATUS_PENDING
    stored = get_result("f-001", db_path=db_path)
    assert stored.status == STATUS_PENDING
    assert stored.output.misconfig_type is MisconfigVerdict.M01


def test_save_result_not_requiring_approval_is_auto_approved(tmp_path):
    db_path = tmp_path / "approvals.db"
    status = save_result("S3", "us-east-1", make_run_result(requires_approval=False), db_path=db_path)
    assert status == STATUS_AUTO_APPROVED


def test_save_result_persists_the_trace(tmp_path):
    db_path = tmp_path / "approvals.db"
    save_result("S3", "us-east-1", make_run_result(), db_path=db_path)
    stored = get_result("f-001", db_path=db_path)
    assert stored.trace[0]["tool"] == "check_misconfig"


def test_save_result_upserts_on_rerun(tmp_path):
    db_path = tmp_path / "approvals.db"
    save_result("S3", "us-east-1", make_run_result(), db_path=db_path)
    save_result("S3", "us-east-1", make_run_result(requires_approval=False), db_path=db_path)
    assert len(list_results(db_path=db_path)) == 1
    assert get_result("f-001", db_path=db_path).status == STATUS_AUTO_APPROVED


def test_get_result_for_unknown_id_returns_none(tmp_path):
    db_path = tmp_path / "approvals.db"
    assert get_result("does-not-exist", db_path=db_path) is None


def test_list_results_filters_by_status(tmp_path):
    db_path = tmp_path / "approvals.db"
    save_result("S3", "us-east-1", make_run_result(finding_id="pending-1", requires_approval=True), db_path=db_path)
    save_result("S3", "us-east-1", make_run_result(finding_id="auto-1", requires_approval=False), db_path=db_path)

    pending = list_results(db_path=db_path, status=STATUS_PENDING)
    assert [r.finding_id for r in pending] == ["pending-1"]


def test_approve_updates_status_and_appends_audit_log(tmp_path):
    db_path = tmp_path / "approvals.db"
    save_result("S3", "us-east-1", make_run_result(requires_approval=True), db_path=db_path)

    ok = approve("f-001", actor="jaya", note="looks fine", db_path=db_path)
    assert ok is True
    assert get_result("f-001", db_path=db_path).status == "approved"

    log = list_audit_log(db_path=db_path)
    assert log[-1]["action"] == "approved"
    assert log[-1]["actor"] == "jaya"


def test_reject_updates_status_and_appends_audit_log(tmp_path):
    db_path = tmp_path / "approvals.db"
    save_result("S3", "us-east-1", make_run_result(requires_approval=True), db_path=db_path)

    ok = reject("f-001", actor="laura", note="needs more context", db_path=db_path)
    assert ok is True
    assert get_result("f-001", db_path=db_path).status == "rejected"


def test_approve_unknown_finding_id_returns_false_without_crashing(tmp_path):
    db_path = tmp_path / "approvals.db"
    assert approve("does-not-exist", db_path=db_path) is False


def test_monitoring_stats_counts_and_rejection_rate(tmp_path):
    db_path = tmp_path / "approvals.db"
    save_result("S3", "us-east-1", make_run_result(finding_id="a", misconfig_type=MisconfigVerdict.M01), db_path=db_path)
    save_result("S3", "us-east-1", make_run_result(finding_id="b", misconfig_type=MisconfigVerdict.M01), db_path=db_path)
    save_result("S3", "us-east-1", make_run_result(finding_id="c", misconfig_type=MisconfigVerdict.M04), db_path=db_path)
    approve("a", db_path=db_path)
    reject("b", db_path=db_path)

    stats = get_monitoring_stats(db_path=db_path)
    assert stats["total_runs"] == 3
    assert stats["by_misconfig_type"]["M01"] == 2
    assert stats["by_status"]["pending"] == 1
    assert stats["rejection_rate_by_type"]["M01"] == 0.5
    assert "M04" not in stats["rejection_rate_by_type"]  # still pending, not decided yet
