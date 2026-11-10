import json

import chromadb
import pytest

from app.agent.loop import run_agent
from app.schemas import Finding, FindingSource, MisconfigLabel, MisconfigVerdict, ResourceType
from app.tools.retrieval import COLLECTION_NAME, HashingEmbeddingFunction
from kb.ingest import CONTROLS_PATH, build_index


def make_finding(resource_type=ResourceType.S3, config=None, tags=None, label=MisconfigLabel.M01, **overrides):
    base = dict(
        finding_id="f-001",
        resource_id="arn:aws:s3:::example-bucket",
        resource_type=resource_type,
        region="us-east-1",
        config=config if config is not None else {"BlockPublicAcls": False},
        tags=tags or {"Name": "example-bucket"},
        source=FindingSource.SYNTHETIC,
        label=label,
    )
    base.update(overrides)
    return Finding(**base)


def make_chat_fn(responses):
    responses = list(responses)

    def chat_fn(messages, tools, model):
        if not responses:
            raise AssertionError("chat_fn was called more times than scripted")
        return responses.pop(0)

    return chat_fn


def tool_call_response(*calls):
    return {
        "message": {
            "content": "",
            "tool_calls": [{"function": {"name": name, "arguments": args}} for name, args in calls],
        }
    }


def final_response(explanation="Public bucket.", remediation_steps=None, confidence="high"):
    payload = {
        "explanation": explanation,
        "remediation_steps": remediation_steps or ["Do the fix."],
        "confidence": confidence,
    }
    return {"message": {"content": json.dumps(payload), "tool_calls": []}}


@pytest.fixture
def real_collection(tmp_path):
    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    build_index(controls_path=CONTROLS_PATH, embedding_function=HashingEmbeddingFunction(), client=client)
    return client.get_collection(COLLECTION_NAME, embedding_function=HashingEmbeddingFunction())


# --- happy path -----------------------------------------------------------------


def test_happy_path_assembles_full_agent_output(real_collection):
    finding = make_finding()
    chat_fn = make_chat_fn(
        [
            tool_call_response(("check_misconfig", {})),
            tool_call_response(("lookup_controls", {"misconfig_type": "M01"}), ("get_fix_template", {"misconfig_type": "M01"})),
            final_response(explanation="This bucket is public.", remediation_steps=["Enable Block Public Access."]),
        ]
    )

    result = run_agent(finding, chat_fn=chat_fn, collection=real_collection)
    output = result.output

    assert output.misconfig_type is MisconfigVerdict.M01
    assert output.requires_approval is True
    assert output.explanation == "This bucket is public."
    assert output.remediation_steps == ["Enable Block Public Access."]
    assert output.confidence.value == "high"
    assert output.control_ids
    assert output.mitre_techniques
    assert output.fix_snippet
    assert output.side_effects
    assert output.field_sources["misconfig_type"].value == "Rule"
    assert output.field_sources["explanation"].value == "LLM"
    assert output.field_sources["control_ids"].value == "Retrieved"
    assert len(result.trace) == 3


def test_llm_cannot_override_the_rule_engines_verdict(real_collection):
    finding = make_finding()
    chat_fn = make_chat_fn(
        [
            tool_call_response(("check_misconfig", {})),
            # A model that tries to smuggle a different verdict into its JSON.
            {
                "message": {
                    "content": json.dumps(
                        {
                            "misconfig_type": "COMPLIANT",
                            "severity": None,
                            "requires_approval": False,
                            "explanation": "Actually this is fine.",
                            "remediation_steps": [],
                            "confidence": "high",
                        }
                    ),
                    "tool_calls": [],
                }
            },
        ]
    )

    result = run_agent(finding, chat_fn=chat_fn, collection=real_collection)
    assert result.output.misconfig_type is MisconfigVerdict.M01
    assert result.output.requires_approval is True


# --- handled errors --------------------------------------------------------------


def test_model_never_calling_check_misconfig_falls_back_to_needs_review():
    finding = make_finding()
    chat_fn = make_chat_fn([final_response()])

    result = run_agent(finding, chat_fn=chat_fn)
    assert result.output.misconfig_type is MisconfigVerdict.NEEDS_REVIEW
    assert result.output.requires_approval is True
    assert "check_misconfig" in result.output.explanation


def test_invalid_json_is_retried_once_then_succeeds(real_collection):
    finding = make_finding()
    chat_fn = make_chat_fn(
        [
            tool_call_response(("check_misconfig", {})),
            {"message": {"content": "not json at all", "tool_calls": []}},
            final_response(),
        ]
    )

    result = run_agent(finding, chat_fn=chat_fn, collection=real_collection)
    assert result.output.explanation == "Public bucket."
    assert result.output.misconfig_type is MisconfigVerdict.M01


def test_invalid_json_twice_is_a_handled_error_not_a_crash():
    finding = make_finding()
    chat_fn = make_chat_fn(
        [
            tool_call_response(("check_misconfig", {})),
            {"message": {"content": "still not json", "tool_calls": []}},
            {"message": {"content": "still not json", "tool_calls": []}},
        ]
    )

    result = run_agent(finding, chat_fn=chat_fn)
    assert result.output.misconfig_type is MisconfigVerdict.M01  # rule result was already known
    assert result.output.confidence.value == "low"
    assert result.output.requires_approval is True
    assert "valid JSON" in result.output.explanation


def test_chat_fn_exception_is_a_handled_error():
    finding = make_finding()

    def exploding_chat_fn(messages, tools, model):
        raise ConnectionError("ollama is not running")

    result = run_agent(finding, chat_fn=exploding_chat_fn)
    assert result.output.misconfig_type is MisconfigVerdict.NEEDS_REVIEW
    assert "ollama is not running" in result.output.explanation


def test_timeout_is_a_handled_error():
    import time

    finding = make_finding()

    def slow_chat_fn(messages, tools, model):
        time.sleep(0.3)
        return final_response()

    result = run_agent(finding, chat_fn=slow_chat_fn, timeout_seconds=0.05)
    assert "timed out" in result.output.explanation
    assert result.output.requires_approval is True


def test_exceeding_max_iterations_is_a_handled_error_but_keeps_known_verdict():
    finding = make_finding()

    def always_tool_calling_chat_fn(messages, tools, model):
        return tool_call_response(("check_misconfig", {}))

    result = run_agent(finding, chat_fn=always_tool_calling_chat_fn, max_iterations=3)
    assert result.output.misconfig_type is MisconfigVerdict.M01
    assert "iterations" in result.output.explanation
    assert len(result.trace) == 3


def test_unknown_tool_name_does_not_crash_the_loop():
    finding = make_finding()
    chat_fn = make_chat_fn(
        [
            tool_call_response(("not_a_real_tool", {})),
            tool_call_response(("check_misconfig", {})),
            final_response(),
        ]
    )

    result = run_agent(finding, chat_fn=chat_fn)
    assert result.trace[0].tool == "not_a_real_tool"
    assert "error" in result.trace[0].result
    assert result.output.misconfig_type is MisconfigVerdict.M01


def test_lookup_controls_without_prior_check_misconfig_returns_handled_error(real_collection):
    finding = make_finding()
    chat_fn = make_chat_fn(
        [
            tool_call_response(("lookup_controls", {})),
            tool_call_response(("check_misconfig", {})),
            final_response(),
        ]
    )

    result = run_agent(finding, chat_fn=chat_fn, collection=real_collection)
    assert "error" in result.trace[0].result


# --- untrusted data -----------------------------------------------------------------


def test_finding_label_is_never_sent_to_the_llm():
    finding = make_finding()
    seen_messages = []

    def recording_chat_fn(messages, tools, model):
        seen_messages.append(messages)
        return tool_call_response(("check_misconfig", {}))

    run_agent(finding, chat_fn=recording_chat_fn, max_iterations=1)
    user_message = seen_messages[0][1]["content"]
    assert '"label"' not in user_message
