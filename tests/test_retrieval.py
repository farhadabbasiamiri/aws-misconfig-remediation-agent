import chromadb
import pytest

from app.tools.retrieval import COLLECTION_NAME, HashingEmbeddingFunction, lookup_controls
from kb.ingest import build_index, parse_controls_markdown

try:
    import sentence_transformers  # noqa: F401

    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False

CONTROLS_MD = """\
# Control reference

## M01 - S3 bucket publicly readable

- Resource: S3
- Controls: AWS FSBP S3.1, S3.2
- MITRE ATT&CK: T1530

Public S3 buckets expose data to the entire internet without authentication.

## M03 - SSH or RDP open to the internet

- Resource: EC2
- Controls: AWS FSBP EC2.13; CIS 5.2
- MITRE ATT&CK: T1133, T1110

Open SSH or RDP ports are scanned and brute-forced within minutes.
"""


def _fresh_client(tmp_path):
    # EphemeralClient() instances share process-wide state in this chromadb
    # version (collections collide across tests by name), so each test gets
    # its own on-disk path via pytest's tmp_path for real isolation.
    return chromadb.PersistentClient(path=str(tmp_path / "chroma"))


@pytest.fixture
def populated_collection(tmp_path):
    controls_path = tmp_path / "controls.md"
    controls_path.write_text(CONTROLS_MD)
    client = _fresh_client(tmp_path)
    build_index(
        controls_path=controls_path,
        embedding_function=HashingEmbeddingFunction(),
        client=client,
    )
    return client.get_collection(COLLECTION_NAME, embedding_function=HashingEmbeddingFunction())


# --- parsing -----------------------------------------------------------------


def test_parse_controls_markdown_extracts_both_sections():
    sections = parse_controls_markdown(CONTROLS_MD)
    assert [s["misconfig_type"] for s in sections] == ["M01", "M03"]


def test_parse_controls_markdown_extracts_control_ids_and_mitre():
    sections = parse_controls_markdown(CONTROLS_MD)
    m01 = sections[0]
    assert m01["resource_type"] == "S3"
    assert m01["control_ids"] == ["AWS FSBP S3.1", "S3.2"]
    assert m01["mitre_techniques"] == ["T1530"]


def test_parse_controls_markdown_missing_field_raises():
    broken = "## M01 - Title\n\n- Resource: S3\n\nNo controls or mitre line.\n"
    with pytest.raises(ValueError):
        parse_controls_markdown(broken)


# --- retrieval -----------------------------------------------------------------


def test_build_index_returns_section_count(tmp_path):
    controls_path = tmp_path / "controls.md"
    controls_path.write_text(CONTROLS_MD)
    client = _fresh_client(tmp_path)
    count = build_index(controls_path=controls_path, embedding_function=HashingEmbeddingFunction(), client=client)
    assert count == 2


def test_lookup_controls_returns_matching_type_first(populated_collection):
    matches = lookup_controls("M03", "EC2", collection=populated_collection, top_k=1)
    assert len(matches) == 1
    assert matches[0].misconfig_type == "M03"
    assert matches[0].control_ids == ["AWS FSBP EC2.13", "CIS 5.2"]
    assert matches[0].mitre_techniques == ["T1133", "T1110"]
    assert "SSH" in matches[0].text or "brute-forced" in matches[0].text


def test_lookup_controls_respects_top_k(populated_collection):
    matches = lookup_controls("M01", "S3", collection=populated_collection, top_k=2)
    assert len(matches) == 2


def test_lookup_controls_on_empty_collection_returns_empty_list(tmp_path):
    client = _fresh_client(tmp_path)
    empty = client.get_or_create_collection("empty", embedding_function=HashingEmbeddingFunction())
    assert lookup_controls("M01", "S3", collection=empty) == []


def test_hashing_embedding_function_is_deterministic():
    embed = HashingEmbeddingFunction()
    first = [list(vec) for vec in embed(["public s3 bucket"])]
    second = [list(vec) for vec in embed(["public s3 bucket"])]
    assert first == second


# --- real controls.md ------------------------------------------------------------


def test_real_controls_md_parses_all_ten_misconfig_types():
    from kb.ingest import CONTROLS_PATH

    sections = parse_controls_markdown(CONTROLS_PATH.read_text())
    expected = {f"M{i:02d}" for i in range(1, 11)}
    assert {s["misconfig_type"] for s in sections} == expected


def test_real_controls_md_builds_with_hashing_embedder_returns_results_for_every_type(tmp_path):
    # Structural smoke test only -- the dependency-free hashing embedder has
    # no IDF weighting, so it isn't expected to rank the exact matching
    # section first on real, wordy prose. That correctness check is done
    # below with the production embedder.
    from kb.ingest import CONTROLS_PATH

    client = _fresh_client(tmp_path)
    build_index(controls_path=CONTROLS_PATH, embedding_function=HashingEmbeddingFunction(), client=client)
    collection = client.get_collection(COLLECTION_NAME, embedding_function=HashingEmbeddingFunction())

    for i in range(1, 11):
        matches = lookup_controls(f"M{i:02d}", "ANY", collection=collection, top_k=3)
        assert matches


@pytest.mark.skipif(not HAS_SENTENCE_TRANSFORMERS, reason="sentence-transformers not installed")
def test_real_controls_md_retrieves_correct_type_with_production_embedder(tmp_path):
    from app.tools.retrieval import get_default_embedding_function
    from kb.ingest import CONTROLS_PATH

    client = _fresh_client(tmp_path)
    embedding_function = get_default_embedding_function()
    build_index(controls_path=CONTROLS_PATH, embedding_function=embedding_function, client=client)
    collection = client.get_collection(COLLECTION_NAME, embedding_function=embedding_function)

    resource_type_by_misconfig = {
        "M01": "S3", "M02": "S3", "M03": "EC2", "M04": "IAM", "M05": "IAM",
        "M06": "IAM", "M07": "CloudTrail", "M08": "RDS", "M09": "RDS", "M10": "EBS",
    }
    for misconfig_type, resource_type in resource_type_by_misconfig.items():
        matches = lookup_controls(misconfig_type, resource_type, collection=collection, top_k=1)
        assert matches
        assert matches[0].misconfig_type == misconfig_type
