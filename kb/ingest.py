"""Chunk kb/controls.md and load it into Chroma for lookup_controls.

Run directly: python kb/ingest.py
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from app.tools.retrieval import COLLECTION_NAME, default_chroma_path, get_default_embedding_function

CONTROLS_PATH = Path(__file__).resolve().parent / "controls.md"

_SECTION_RE = re.compile(r"^## (M\d{2}) - (.+)$", re.MULTILINE)
_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


_HEADER_LINE_RE = re.compile(r"^- (Resource|Controls|MITRE ATT&CK):.*$", re.MULTILINE)


def _join_wrapped_lines(body: str) -> str:
    """A field's value may wrap onto indented continuation lines; join them back."""
    joined: list[str] = []
    for line in body.split("\n"):
        if line.startswith((" ", "\t")) and joined:
            joined[-1] = f"{joined[-1]} {line.strip()}"
        else:
            joined.append(line)
    return "\n".join(joined)


def _extract_field(body: str, label: str) -> str:
    match = re.search(rf"^- {re.escape(label)}:\s*(.+?)$", body, re.MULTILINE)
    if not match:
        raise ValueError(f"missing '- {label}:' field in a controls.md section")
    return match.group(1).strip()


def parse_controls_markdown(text: str) -> list[dict[str, Any]]:
    """Splits controls.md into one chunk per misconfiguration section."""
    matches = list(_SECTION_RE.finditer(text))
    sections = []
    for i, match in enumerate(matches):
        misconfig_type, title = match.group(1), match.group(2).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = _join_wrapped_lines(text[start:end].strip())

        controls_field = _extract_field(body, "Controls")
        mitre_field = _extract_field(body, "MITRE ATT&CK")
        resource_type = _extract_field(body, "Resource")

        # The structured header lines repeat the same boilerplate words
        # ("Resource", "Controls", "MITRE ATT&CK") in every section, which
        # would drown out each section's actually-distinguishing text in
        # retrieval; embed only the title and free-text body.
        narrative = _HEADER_LINE_RE.sub("", body).strip()
        narrative = re.sub(r"\n{3,}", "\n\n", narrative)

        sections.append(
            {
                "misconfig_type": misconfig_type,
                "title": title,
                "resource_type": resource_type,
                "control_ids": [c.strip() for c in re.split(r"[;,]", controls_field) if c.strip()],
                "mitre_techniques": _TECHNIQUE_RE.findall(mitre_field),
                "text": f"{misconfig_type} - {title}\n\n{narrative}",
            }
        )
    return sections


def build_index(
    *,
    controls_path: Path = CONTROLS_PATH,
    chroma_path: Path | None = None,
    embedding_function: Any = None,
    client: Any = None,
) -> int:
    sections = parse_controls_markdown(controls_path.read_text())

    if client is None:
        import chromadb

        client = chromadb.PersistentClient(path=str(chroma_path or default_chroma_path()))

    collection = client.get_or_create_collection(
        COLLECTION_NAME, embedding_function=embedding_function or get_default_embedding_function()
    )
    collection.upsert(
        ids=[s["misconfig_type"] for s in sections],
        documents=[s["text"] for s in sections],
        metadatas=[
            {
                "misconfig_type": s["misconfig_type"],
                "resource_type": s["resource_type"],
                "control_ids": ",".join(s["control_ids"]),
                "mitre_techniques": ",".join(s["mitre_techniques"]),
            }
            for s in sections
        ],
    )
    return len(sections)


def main() -> None:
    count = build_index()
    print(f"Ingested {count} control sections into Chroma at {default_chroma_path()}")


if __name__ == "__main__":
    main()
