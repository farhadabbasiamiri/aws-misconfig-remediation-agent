import csv
import io
import json

import pytest
import yaml

from app.parser import UnsupportedFormatError, parse_file, parse_text
from data.generator import generate, write_outputs

VALID_RECORD = {
    "finding_id": "f-001",
    "resource_id": "arn:aws:s3:::example-bucket",
    "resource_type": "S3",
    "region": "us-east-1",
    "config": {"BlockPublicAcls": False},
    "tags": {"Name": "example-bucket"},
    "source": "synthetic",
    "label": "M01",
}


def test_parse_text_json_valid_record():
    report = parse_text(json.dumps([VALID_RECORD]), ".json")
    assert len(report.findings) == 1
    assert not report.needs_review
    assert report.file_error is None


def test_parse_text_json_single_object_not_wrapped_in_list():
    report = parse_text(json.dumps(VALID_RECORD), ".json")
    assert len(report.findings) == 1


def test_parse_text_yaml_valid_record():
    report = parse_text(yaml.safe_dump([VALID_RECORD]), ".yaml")
    assert len(report.findings) == 1
    assert not report.needs_review


def test_parse_text_csv_decodes_json_encoded_config_and_tags():
    row = dict(VALID_RECORD)
    row["config"] = json.dumps(row["config"])
    row["tags"] = json.dumps(row["tags"])
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(row.keys()))
    writer.writeheader()
    writer.writerow(row)
    report = parse_text(buffer.getvalue(), ".csv")
    assert len(report.findings) == 1
    assert report.findings[0].config == {"BlockPublicAcls": False}


def test_parse_text_missing_required_field_is_needs_review_not_crash():
    broken = dict(VALID_RECORD)
    del broken["resource_id"]
    report = parse_text(json.dumps([broken]), ".json")
    assert not report.findings
    assert len(report.needs_review) == 1
    assert "resource_id" in report.needs_review[0].reason


def test_parse_text_unknown_resource_type_is_needs_review():
    broken = dict(VALID_RECORD)
    broken["resource_type"] = "LAMBDA"
    report = parse_text(json.dumps([broken]), ".json")
    assert not report.findings
    assert len(report.needs_review) == 1


def test_parse_text_null_config_is_needs_review():
    broken = dict(VALID_RECORD)
    broken["config"] = None
    report = parse_text(json.dumps([broken]), ".json")
    assert not report.findings
    assert len(report.needs_review) == 1


def test_parse_text_non_object_record_is_needs_review():
    report = parse_text(json.dumps(["not-an-object"]), ".json")
    assert not report.findings
    assert len(report.needs_review) == 1
    assert report.needs_review[0].reason == "record is not an object"


def test_parse_text_malformed_json_syntax_is_file_error_not_crash():
    report = parse_text("{not valid json", ".json")
    assert report.file_error is not None
    assert not report.findings
    assert not report.needs_review


def test_parse_text_unsupported_extension_raises():
    with pytest.raises(UnsupportedFormatError):
        parse_text("[]", ".txt")


def test_needs_review_preserves_finding_id_when_present():
    broken = dict(VALID_RECORD)
    broken["region"] = ""  # min_length=1 violation
    report = parse_text(json.dumps([broken]), ".json")
    assert report.needs_review[0].finding_id == "f-001"


# --- full round-trip against the generator's real output files -----------------


@pytest.mark.parametrize("filename", ["findings.json", "findings.yaml", "findings.csv"])
def test_parse_file_matches_generator_across_all_formats(tmp_path, filename):
    result = generate()
    write_outputs(result, output_dir=tmp_path)

    report = parse_file(tmp_path / filename)

    clean = [f for f in result["findings"] if not f["finding_id"].startswith("SYN-BAD-")]
    malformed_ids = {f["finding_id"] for f in result["findings"] if f["finding_id"].startswith("SYN-BAD-")}

    assert len(report.findings) == len(clean)
    assert len(report.needs_review) == len(malformed_ids)
    assert {f.finding_id for f in report.findings} == {f["finding_id"] for f in clean}

    reviewed_ids = {u.finding_id for u in report.needs_review if u.finding_id}
    # SYN-BAD-001 is missing resource_id but keeps finding_id, so it's traceable.
    assert "SYN-BAD-001" in reviewed_ids
