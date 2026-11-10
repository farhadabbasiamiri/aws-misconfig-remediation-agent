"""Upload (JSON/YAML/CSV) -> validated Finding.

Per CLAUDE.md: missing or misnamed fields are a handled error, flagged
"needs review", never a crash. A record that fails Finding validation is
kept as an UnparsableFinding with the reason -- never dropped silently,
and a broken file (bad JSON/YAML syntax) is reported as a file-level
error rather than raised.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml
from pydantic import ValidationError

from app.schemas import Finding

SUPPORTED_EXTENSIONS = {".json", ".yaml", ".yml", ".csv"}


class UnsupportedFormatError(ValueError):
    pass


@dataclass(frozen=True)
class UnparsableFinding:
    raw: dict[str, Any]
    reason: str
    finding_id: str | None = None


@dataclass(frozen=True)
class ParseReport:
    findings: list[Finding] = field(default_factory=list)
    needs_review: list[UnparsableFinding] = field(default_factory=list)
    file_error: str | None = None

    @property
    def total(self) -> int:
        return len(self.findings) + len(self.needs_review)


def _decode_json_field(value: Any) -> Any:
    """CSV stores config/tags as JSON text; JSON/YAML already give objects."""
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value  # leave as-is; Finding validation will reject the wrong type


def _normalise_csv_row(row: dict[str, Any]) -> dict[str, Any]:
    row = dict(row)
    for key in ("config", "tags"):
        if key in row:
            row[key] = _decode_json_field(row[key])
    return row


def _read_json(text: str) -> list[Any]:
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("expected a JSON object or array of findings")
    return data


def _read_yaml(text: str) -> list[Any]:
    data = yaml.safe_load(text)
    if data is None:
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("expected a YAML mapping or list of findings")
    return data


def _read_csv(text: str) -> list[Any]:
    reader = csv.DictReader(io.StringIO(text))
    return [_normalise_csv_row(row) for row in reader]


_READERS: dict[str, Callable[[str], list[Any]]] = {
    ".json": _read_json,
    ".yaml": _read_yaml,
    ".yml": _read_yaml,
    ".csv": _read_csv,
}


def _summarise_validation_error(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors():
        loc = ".".join(str(p) for p in error["loc"]) or "<record>"
        parts.append(f"{loc}: {error['msg']}")
    return "; ".join(parts)


def _build_findings(raw_records: list[Any]) -> tuple[list[Finding], list[UnparsableFinding]]:
    findings: list[Finding] = []
    needs_review: list[UnparsableFinding] = []
    for record in raw_records:
        if not isinstance(record, dict):
            needs_review.append(UnparsableFinding(raw={"value": record}, reason="record is not an object"))
            continue
        try:
            findings.append(Finding(**record))
        except ValidationError as exc:
            finding_id = record.get("finding_id")
            needs_review.append(
                UnparsableFinding(
                    raw=record,
                    reason=_summarise_validation_error(exc),
                    finding_id=finding_id if isinstance(finding_id, str) else None,
                )
            )
    return findings, needs_review


def parse_text(text: str, extension: str) -> ParseReport:
    extension = extension.lower()
    reader = _READERS.get(extension)
    if reader is None:
        raise UnsupportedFormatError(f"unsupported file extension: {extension!r}")

    try:
        raw_records = reader(text)
    except Exception as exc:  # a broken upload must not crash the app
        return ParseReport(file_error=f"could not parse {extension} file: {exc}")

    findings, needs_review = _build_findings(raw_records)
    return ParseReport(findings=findings, needs_review=needs_review)


def parse_file(path: str | Path) -> ParseReport:
    path = Path(path)
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise UnsupportedFormatError(f"unsupported file extension: {path.suffix!r}")
    return parse_text(path.read_text(), path.suffix)
