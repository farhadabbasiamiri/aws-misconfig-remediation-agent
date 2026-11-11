from app.agent.loop import ToolTrace
from app.schemas import AgentOutput, Confidence, MisconfigVerdict, Severity
from eval.metrics import (
    approval_routing_compliance,
    control_mapping_accuracy,
    detection_metrics,
    expected_controls_by_type,
    latency_stats,
    mitre_mapping_accuracy,
    tool_selection_accuracy,
    verdict_integrity_rate,
)


def make_output(finding_id="f1", misconfig_type=MisconfigVerdict.M01, control_ids=None, mitre_techniques=None, requires_approval=None):
    if requires_approval is None:
        requires_approval = misconfig_type.value not in ("COMPLIANT", "M02", "M09", "M10")
    return AgentOutput(
        finding_id=finding_id,
        misconfig_type=misconfig_type,
        severity=Severity.HIGH if requires_approval else None,
        control_ids=control_ids or [],
        mitre_techniques=mitre_techniques or [],
        explanation="x",
        confidence=Confidence.HIGH,
        requires_approval=requires_approval,
    )


# --- detection_metrics -----------------------------------------------------------


def test_detection_metrics_perfect_predictions():
    labels = ["M01", "COMPLIANT", "M04"]
    predictions = ["M01", "COMPLIANT", "M04"]
    result = detection_metrics(labels, predictions)
    assert result.accuracy == 1.0
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1 == 1.0


def test_detection_metrics_false_positive_and_false_negative():
    labels = ["COMPLIANT", "M01"]
    predictions = ["M01", "COMPLIANT"]  # one false positive, one false negative
    result = detection_metrics(labels, predictions)
    assert result.accuracy == 0.0
    assert result.precision == 0.0
    assert result.recall == 0.0


def test_detection_metrics_confusion_matrix_tracks_mismatches():
    result = detection_metrics(["M01", "M01"], ["M01", "M02"])
    assert result.confusion["M01"] == {"M01": 1, "M02": 1}


def test_detection_metrics_mismatched_lengths_raises():
    import pytest

    with pytest.raises(ValueError):
        detection_metrics(["M01"], ["M01", "M02"])


def test_detection_metrics_empty_input_is_perfect_by_convention():
    result = detection_metrics([], [])
    assert result.accuracy == 1.0


# --- control / mitre mapping ---------------------------------------------------------


def test_expected_controls_by_type_covers_all_ten():
    expected = expected_controls_by_type()
    assert {f"M{i:02d}" for i in range(1, 11)} == set(expected.keys())
    assert expected["M01"]["control_ids"]
    assert expected["M01"]["mitre_techniques"] == ["T1530"]


def test_control_mapping_accuracy_full_marks_when_correct():
    expected = expected_controls_by_type()
    output = make_output(control_ids=expected["M01"]["control_ids"])
    assert control_mapping_accuracy([output], expected) == 1.0


def test_control_mapping_accuracy_zero_when_wrong():
    expected = expected_controls_by_type()
    output = make_output(control_ids=["totally-wrong-control"])
    assert control_mapping_accuracy([output], expected) == 0.0


def test_mitre_mapping_accuracy_full_marks_when_correct():
    expected = expected_controls_by_type()
    output = make_output(mitre_techniques=expected["M01"]["mitre_techniques"])
    assert mitre_mapping_accuracy([output], expected) == 1.0


def test_mapping_accuracy_ignores_outputs_with_no_expected_entry():
    expected = {"M01": {"control_ids": ["x"], "mitre_techniques": ["T1"]}}
    compliant_output = make_output(misconfig_type=MisconfigVerdict.COMPLIANT, requires_approval=False)
    assert control_mapping_accuracy([compliant_output], expected) == 1.0


# --- tool_selection_accuracy --------------------------------------------------------


def test_tool_selection_accuracy_correct_full_protocol():
    trace = [
        ToolTrace(0, "check_misconfig", {}, {}),
        ToolTrace(1, "lookup_controls", {}, {}),
        ToolTrace(1, "get_fix_template", {}, {}),
    ]
    assert tool_selection_accuracy([(trace, "M01")]) == 1.0


def test_tool_selection_accuracy_compliant_only_needs_check_misconfig():
    trace = [ToolTrace(0, "check_misconfig", {}, {})]
    assert tool_selection_accuracy([(trace, "COMPLIANT")]) == 1.0


def test_tool_selection_accuracy_penalises_missing_check_misconfig_first():
    trace = [ToolTrace(0, "lookup_controls", {}, {})]
    assert tool_selection_accuracy([(trace, "M01")]) == 0.0


def test_tool_selection_accuracy_penalises_skipping_fix_template():
    trace = [ToolTrace(0, "check_misconfig", {}, {}), ToolTrace(1, "lookup_controls", {}, {})]
    assert tool_selection_accuracy([(trace, "M01")]) == 0.0


def test_tool_selection_accuracy_on_empty_runs_is_perfect_by_convention():
    assert tool_selection_accuracy([]) == 1.0


# --- approval routing / verdict integrity -------------------------------------------


def test_approval_routing_compliance_is_always_satisfied_by_a_valid_agentoutput():
    outputs = [make_output(misconfig_type=MisconfigVerdict.M04), make_output(misconfig_type=MisconfigVerdict.M02)]
    assert approval_routing_compliance(outputs) == 1.0


def test_verdict_integrity_rate_matches_rule_result():
    output = make_output(finding_id="f1", misconfig_type=MisconfigVerdict.M01)
    assert verdict_integrity_rate([output], {"f1": "M01"}) == 1.0


def test_verdict_integrity_rate_catches_mismatch():
    output = make_output(finding_id="f1", misconfig_type=MisconfigVerdict.M01)
    assert verdict_integrity_rate([output], {"f1": "COMPLIANT"}) == 0.0


# --- latency -----------------------------------------------------------------------------


def test_latency_stats_basic():
    stats = latency_stats([1.0, 2.0, 3.0])
    assert stats.count == 3
    assert stats.avg_seconds == 2.0
    assert stats.max_seconds == 3.0
    assert stats.under_30s_rate == 1.0


def test_latency_stats_flags_slow_runs():
    stats = latency_stats([5.0, 35.0])
    assert stats.under_30s_rate == 0.5


def test_latency_stats_empty_is_perfect_by_convention():
    stats = latency_stats([])
    assert stats.count == 0
    assert stats.under_30s_rate == 1.0
