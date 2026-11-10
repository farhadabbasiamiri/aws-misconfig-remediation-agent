"""lookup_controls: top-k retrieval of CIS/FSBP/MITRE control text from Chroma.

The embedding function is swappable so tests can run fully offline with a
lightweight, dependency-free embedder (HashingEmbeddingFunction); production
defaults to Sentence Transformers' BGE-small per CLAUDE.md's tech stack.
Nothing at import time requires torch/sentence-transformers to be installed.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import chromadb
from chromadb.api.types import EmbeddingFunction

COLLECTION_NAME = "controls"
DEFAULT_MODEL_NAME = "BAAI/bge-small-en-v1.5"


def default_chroma_path() -> Path:
    configured = os.environ.get("CHROMA_PATH")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parent.parent.parent / "kb" / "chroma"


class HashingEmbeddingFunction(EmbeddingFunction):
    """Deterministic, dependency-free bag-of-words embedding.

    Used by tests, and as a graceful fallback if sentence-transformers
    isn't installed -- production should prefer get_default_embedding_function().
    """

    def __init__(self, dims: int = 256):
        self.dims = dims

    @staticmethod
    def name() -> str:
        # "default" skips chromadb's persisted-embedding-function conflict
        # check, which otherwise requires a registered, serializable config.
        return "default"

    def get_config(self) -> dict[str, Any]:
        return {"dims": self.dims}

    @staticmethod
    def build_from_config(config: dict[str, Any]) -> "HashingEmbeddingFunction":
        return HashingEmbeddingFunction(dims=config.get("dims", 256))

    def __call__(self, input: list[str]) -> list[list[float]]:
        vectors = []
        for text in input:
            vector = [0.0] * self.dims
            for word in text.lower().split():
                index = int(hashlib.md5(word.encode()).hexdigest(), 16) % self.dims
                vector[index] += 1.0
            norm = sum(v * v for v in vector) ** 0.5 or 1.0
            vectors.append([v / norm for v in vector])
        return vectors


def get_default_embedding_function() -> Any:
    try:
        from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
    except ImportError:
        return HashingEmbeddingFunction()
    return SentenceTransformerEmbeddingFunction(model_name=DEFAULT_MODEL_NAME)


def get_collection(client: Any = None, embedding_function: Any = None) -> Any:
    client = client or chromadb.PersistentClient(path=str(default_chroma_path()))
    return client.get_or_create_collection(
        COLLECTION_NAME, embedding_function=embedding_function or get_default_embedding_function()
    )


@dataclass(frozen=True)
class ControlMatch:
    control_ids: list[str]
    mitre_techniques: list[str]
    misconfig_type: str
    resource_type: str
    text: str
    distance: float


def _split(value: str) -> list[str]:
    return [v for v in value.split(",") if v]


# Short, human-readable titles for each code, used only to build a more
# semantically specific query -- a bare code like "M02" carries little
# meaning to an embedding model on its own, and two S3 controls (M01, M02)
# are otherwise too close together in embedding space to tell apart.
MISCONFIG_TITLES: dict[str, str] = {
    "M01": "S3 bucket publicly readable",
    "M02": "S3 bucket missing default encryption",
    "M03": "security group allows SSH or RDP from the internet",
    "M04": "IAM policy allows all actions on all resources",
    "M05": "root account has no MFA",
    "M06": "IAM access key not rotated in over 90 days",
    "M07": "CloudTrail missing, stopped, or single-region",
    "M08": "RDS instance is publicly accessible",
    "M09": "RDS storage is not encrypted",
    "M10": "EBS volume is not encrypted",
}


def lookup_controls(
    misconfig_type: str,
    resource_type: str,
    *,
    collection: Any = None,
    top_k: int = 3,
) -> list[ControlMatch]:
    """Top-k retrieval of control text for a flagged misconfiguration.

    Does not set or influence the verdict itself (hard rule 1: only
    check_misconfig does that) -- this only retrieves supporting context
    for the LLM to explain the verdict with.
    """
    collection = collection if collection is not None else get_collection()
    available = collection.count()
    if available == 0:
        return []

    title = MISCONFIG_TITLES.get(misconfig_type, "misconfiguration")
    query_text = f"{misconfig_type}: {title} ({resource_type})"
    result = collection.query(query_texts=[query_text], n_results=min(top_k, available))

    matches = []
    ids = result.get("ids", [[]])[0]
    for i in range(len(ids)):
        metadata = result["metadatas"][0][i]
        matches.append(
            ControlMatch(
                control_ids=_split(metadata.get("control_ids", "")),
                mitre_techniques=_split(metadata.get("mitre_techniques", "")),
                misconfig_type=metadata.get("misconfig_type", ""),
                resource_type=metadata.get("resource_type", ""),
                text=result["documents"][0][i],
                distance=result["distances"][0][i],
            )
        )
    return matches
