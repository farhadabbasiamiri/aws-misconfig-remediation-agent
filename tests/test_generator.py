from pydantic import ValidationError

from app.schemas import Finding
from data.generator import generate


def test_generate_is_deterministic():
    first = generate()
    second = generate()
    assert first == second


def test_generate_produces_around_150_findings():
    result = generate()
    assert 140 <= len(result["findings"]) <= 160


def test_generate_misconfigured_to_compliant_ratio_is_roughly_70_30():
    result = generate()
    labels = [f["label"] for f in result["findings"]]
    compliant = labels.count("COMPLIANT")
    misconfigured = len(labels) - compliant
    ratio = misconfigured / len(labels)
    assert 0.6 <= ratio <= 0.8


def test_generate_covers_every_misconfig_type():
    result = generate()
    labels = {f["label"] for f in result["findings"]}
    expected = {f"M{i:02d}" for i in range(1, 11)} | {"COMPLIANT"}
    assert expected <= labels


def test_generate_has_at_least_15_hard_cases():
    result = generate()
    assert len(result["hard_case_ids"]) >= 15


def test_clean_findings_validate_against_finding_schema():
    result = generate()
    clean = [f for f in result["findings"] if not f["finding_id"].startswith("SYN-BAD-")]
    for finding in clean:
        Finding(**finding)


def test_malformed_findings_fail_finding_schema_validation():
    result = generate()
    malformed = [f for f in result["findings"] if f["finding_id"].startswith("SYN-BAD-")]
    assert len(malformed) >= 5
    for finding in malformed:
        try:
            Finding(**finding)
        except ValidationError:
            continue
        raise AssertionError(f"expected {finding['finding_id']} to fail Finding validation")


def _clean_findings(result):
    return [f for f in result["findings"] if not f["finding_id"].startswith("SYN-BAD-")]


def test_misleading_bucket_names_do_not_match_their_config():
    result = generate()
    by_id = {f["resource_id"]: f for f in _clean_findings(result) if f["resource_type"] == "S3"}
    public_bucket_with_private_name = next(
        f for rid, f in by_id.items() if "private-secure-data" in rid
    )
    assert public_bucket_with_private_name["label"] == "M01"
    assert public_bucket_with_private_name["config"]["BlockPublicAcls"] is False

    private_bucket_with_public_name = next(
        f for rid, f in by_id.items() if "public-archive" in rid
    )
    assert private_bucket_with_public_name["label"] == "COMPLIANT"
    assert private_bucket_with_public_name["config"]["BlockPublicAcls"] is True


def test_private_cidr_ssh_is_labelled_compliant():
    result = generate()
    private_ssh = [
        f
        for f in _clean_findings(result)
        if f["resource_type"] == "EC2"
        and any(
            ip_range["CidrIp"] == "10.0.0.0/8"
            for perm in f["config"]["IpPermissions"]
            for ip_range in perm.get("IpRanges", [])
        )
    ]
    assert private_ssh
    assert all(f["label"] == "COMPLIANT" for f in private_ssh)


def test_prompt_injection_tags_do_not_appear_unlabelled():
    result = generate()
    injected = [f for f in result["findings"] if "Note" in f["tags"]]
    assert injected
    for finding in injected:
        assert finding["finding_id"] in result["hard_case_ids"]
