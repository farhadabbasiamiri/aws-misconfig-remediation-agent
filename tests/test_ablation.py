import chromadb
import pytest

from app.schemas import Finding
from data.generator import generate
from eval.ablation import ablation_study, run_full_system, run_rules_only
from app.tools.retrieval import COLLECTION_NAME, HashingEmbeddingFunction
from kb.ingest import CONTROLS_PATH, build_index


@pytest.fixture
def small_dataset():
    result = generate()
    clean = [f for f in result["findings"] if not f["finding_id"].startswith("SYN-BAD-")]
    # one of each misconfig type plus a couple of compliant ones, for speed
    seen_types = set()
    sample = []
    for record in clean:
        if record["label"] not in seen_types:
            sample.append(record)
            seen_types.add(record["label"])
    return [Finding(**r) for r in sample], [r["label"] for r in sample]


@pytest.fixture
def real_collection(tmp_path):
    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    build_index(controls_path=CONTROLS_PATH, embedding_function=HashingEmbeddingFunction(), client=client)
    return client.get_collection(COLLECTION_NAME, embedding_function=HashingEmbeddingFunction())


def test_run_rules_only_matches_labels(small_dataset):
    findings, labels = small_dataset
    predictions = run_rules_only(findings)
    assert predictions == labels


def test_run_full_system_with_mock_matches_labels(small_dataset, real_collection):
    findings, labels = small_dataset
    predictions = run_full_system(findings, collection=real_collection)
    assert predictions == labels


def test_ablation_study_reports_both_variants(small_dataset, real_collection):
    findings, labels = small_dataset
    results = ablation_study(findings, labels, collection=real_collection)

    assert set(results.keys()) == {"rules_only", "full_system_mock_llm"}
    assert results["rules_only"].metrics.accuracy == 1.0
    assert results["full_system_mock_llm"].metrics.accuracy == 1.0
    assert results["rules_only"].avg_seconds_per_finding >= 0
    assert results["full_system_mock_llm"].avg_seconds_per_finding >= 0


def test_ablation_study_on_empty_dataset_does_not_crash():
    results = ablation_study([], [])
    assert results["rules_only"].metrics.accuracy == 1.0
