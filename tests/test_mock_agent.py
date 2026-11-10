import json

import chromadb
import pytest

from app.agent.loop import run_agent
from app.agent.mock import mock_chat_fn
from app.schemas import Finding, FindingSource, MisconfigLabel, MisconfigVerdict, ResourceType
from app.tools.retrieval import COLLECTION_NAME, HashingEmbeddingFunction
from kb.ingest import CONTROLS_PATH, build_index


def make_finding(resource_type=ResourceType.S3, config=None, label=MisconfigLabel.M01):
    return Finding(
        finding_id="f-001",
        resource_id="arn:aws:s3:::example-bucket",
        resource_type=resource_type,
        region="us-east-1",
        config=config if config is not None else {"BlockPublicAcls": False},
        tags={"Name": "example-bucket"},
        source=FindingSource.SYNTHETIC,
        label=label,
    )


@pytest.fixture
def real_collection(tmp_path):
    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    build_index(controls_path=CONTROLS_PATH, embedding_function=HashingEmbeddingFunction(), client=client)
    return client.get_collection(COLLECTION_NAME, embedding_function=HashingEmbeddingFunction())


def test_first_call_asks_for_check_misconfig():
    response = mock_chat_fn([{"role": "system", "content": ""}], [], "qwen2.5:7b")
    calls = response["message"]["tool_calls"]
    assert len(calls) == 1
    assert calls[0]["function"]["name"] == "check_misconfig"


def test_second_call_asks_for_controls_and_fix_together():
    messages = [
        {"role": "system", "content": ""},
        {
            "role": "tool",
            "name": "check_misconfig",
            "content": json.dumps({"misconfig_type": "M01", "severity": "High", "evidence": {"public_access_block_disabled": ["BlockPublicAcls"]}}),
        },
    ]
    response = mock_chat_fn(messages, [], "qwen2.5:7b")
    names = {c["function"]["name"] for c in response["message"]["tool_calls"]}
    assert names == {"lookup_controls", "get_fix_template"}


def test_compliant_skips_straight_to_final_json():
    messages = [
        {"role": "tool", "name": "check_misconfig", "content": json.dumps({"misconfig_type": "COMPLIANT", "severity": None, "evidence": {}})},
    ]
    response = mock_chat_fn(messages, [], "qwen2.5:7b")
    assert response["message"]["tool_calls"] == []
    payload = json.loads(response["message"]["content"])
    assert "compliant" in payload["explanation"].lower()


def test_final_call_produces_valid_json_mentioning_mock_mode():
    messages = [
        {"role": "tool", "name": "check_misconfig", "content": json.dumps({"misconfig_type": "M01", "severity": "High", "evidence": {"x": "y"}})},
        {"role": "tool", "name": "lookup_controls", "content": json.dumps({"matches": []})},
        {"role": "tool", "name": "get_fix_template", "content": json.dumps({"cli": "aws s3api put-public-access-block ..."})},
    ]
    response = mock_chat_fn(messages, [], "qwen2.5:7b")
    assert response["message"]["tool_calls"] == []
    payload = json.loads(response["message"]["content"])
    assert "Mock demo mode" in payload["explanation"]
    assert payload["confidence"] == "low"
    assert payload["remediation_steps"]


# --- full run_agent integration ---------------------------------------------------


def test_run_agent_end_to_end_with_mock_chat_fn(real_collection):
    finding = make_finding()
    result = run_agent(finding, chat_fn=mock_chat_fn, collection=real_collection)

    assert result.output.misconfig_type is MisconfigVerdict.M01
    assert result.output.requires_approval is True
    assert "Mock demo mode" in result.output.explanation
    assert result.output.fix_snippet
    assert result.output.control_ids


def test_run_agent_end_to_end_with_mock_chat_fn_on_compliant_finding(real_collection):
    finding = make_finding(
        config={
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
            "ServerSideEncryptionConfiguration": {"Rules": []},
        },
        label=MisconfigLabel.COMPLIANT,
    )
    result = run_agent(finding, chat_fn=mock_chat_fn, collection=real_collection)

    assert result.output.misconfig_type is MisconfigVerdict.COMPLIANT
    assert result.output.requires_approval is False
    assert result.output.fix_snippet is None
