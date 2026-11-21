"""Minimal auditable RAG: Ollama embeddings + scoped current-doc hybrid retrieval.

Stage 03 is a limited-corpus prototype, not a production authorization system.
Do not use RAG content as an approval, and do not ingest sensitive data without review.
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from math import sqrt
from pathlib import Path
import json
import re
import sqlite3
from typing import Any, Protocol

DB_PATH = Path(__file__).resolve().parent / 'data' / 'ila_rag_v03.sqlite3'


class EmbeddingProvider(Protocol):
    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...
    def embed_query(self, text: str) -> list[float]: ...


def _db(path: Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path), timeout=10)
    con.row_factory = sqlite3.Row
    return con


def init_rag(db_path: Path = DB_PATH) -> None:
    with closing(_db(db_path)) as con, con:
        con.execute(
            '''CREATE TABLE IF NOT EXISTS rag_docs (
            doc_id TEXT PRIMARY KEY, title TEXT NOT NULL, source_ref TEXT NOT NULL,
            scope TEXT NOT NULL, status TEXT NOT NULL, source_type TEXT NOT NULL,
            updated_at TEXT NOT NULL, content_sha256 TEXT NOT NULL,
            embedding_model TEXT NOT NULL
        )'''
        )
        con.execute(
            '''CREATE TABLE IF NOT EXISTS rag_chunks (
            chunk_id TEXT PRIMARY KEY, doc_id TEXT NOT NULL,
            chunk_text TEXT NOT NULL, embedding_json TEXT NOT NULL,
            FOREIGN KEY(doc_id) REFERENCES rag_docs(doc_id)
        )'''
        )
        con.execute('CREATE INDEX IF NOT EXISTS idx_rag_scope ON rag_docs(scope, status)')
        con.execute('CREATE INDEX IF NOT EXISTS idx_rag_doc_chunks ON rag_chunks(doc_id)')


def split_text(text: str, *, max_chars: int = 500, overlap: int = 80) -> list[str]:
    """Fixed-size first pass. Real ingestion needs heading-aware chunking later."""
    if max_chars <= 0 or not 0 <= overlap < max_chars:
        raise ValueError('Invalid chunk configuration')
    text = text.strip()
    if not text:
        raise ValueError('Empty document')
    step = max_chars - overlap
    return [
        text[i : i + max_chars]
        for i in range(0, len(text), step)
        if i < len(text) and (i == 0 or text[i:])
    ]


def index_documents(
    documents: list[dict[str, str]],
    *,
    embeddings: EmbeddingProvider,
    embedding_model: str,
    db_path: Path = DB_PATH,
) -> int:
    """Idempotent by doc_id + metadata + content hash; no external requests except embed_documents."""
    init_rag(db_path)
    changed = 0
    for doc in documents:
        required = (
            'doc_id',
            'title',
            'source_ref',
            'scope',
            'status',
            'source_type',
            'updated_at',
            'text',
        )
        for field in required:
            if not isinstance(doc.get(field), str) or not doc[field].strip():
                raise ValueError(f'Missing/empty document field: {field}')
        if doc['status'] not in ('ACTIVE', 'DRAFT', 'SUPERSEDED'):
            raise ValueError('Unknown doc status')
        identity = json.dumps({k: doc[k] for k in required}, sort_keys=True, ensure_ascii=False)
        fingerprint = sha256(identity.encode('utf-8')).hexdigest()
        with closing(_db(db_path)) as con:
            existing = con.execute(
                'SELECT content_sha256,embedding_model FROM rag_docs WHERE doc_id=?',
                (doc['doc_id'],),
            ).fetchone()
            if (
                existing
                and existing['content_sha256'] == fingerprint
                and existing['embedding_model'] == embedding_model
            ):
                continue
        chunks = split_text(doc['text'])
        vectors = embeddings.embed_documents(chunks)
        if len(vectors) != len(chunks) or not all(
            v and all(isinstance(x, (int, float)) for x in v) for v in vectors
        ):
            raise RuntimeError('Invalid embedding response')
        with closing(_db(db_path)) as con, con:
            con.execute('DELETE FROM rag_chunks WHERE doc_id=?', (doc['doc_id'],))
            con.execute(
                '''INSERT INTO rag_docs(doc_id,title,source_ref,scope,status,source_type,
                            updated_at,content_sha256,embedding_model)
                            VALUES(?,?,?,?,?,?,?,?,?)
                            ON CONFLICT(doc_id) DO UPDATE SET
                            title=excluded.title, source_ref=excluded.source_ref,
                            scope=excluded.scope, status=excluded.status,
                            source_type=excluded.source_type, updated_at=excluded.updated_at,
                            content_sha256=excluded.content_sha256,
                            embedding_model=excluded.embedding_model''',
                (
                    doc['doc_id'],
                    doc['title'],
                    doc['source_ref'],
                    doc['scope'],
                    doc['status'],
                    doc['source_type'],
                    doc['updated_at'],
                    fingerprint,
                    embedding_model,
                ),
            )
            for i, (chunk, vector) in enumerate(zip(chunks, vectors)):
                con.execute(
                    'INSERT INTO rag_chunks(chunk_id,doc_id,chunk_text,embedding_json) VALUES(?,?,?,?)',
                    (f"{doc['doc_id']}:{i}", doc['doc_id'], chunk, json.dumps(vector)),
                )
        changed += 1
    return changed


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Key concept to understand: query and document vectors must have the same dimension."""
    if len(a) != len(b) or not a:
        raise ValueError('Embedding dimension mismatch/empty vector')
    numerator = sum(x * y for x, y in zip(a, b))
    denom = sqrt(sum(x * x for x in a)) * sqrt(sum(y * y for y in b))
    return numerator / denom if denom else 0.0


def _lexical_overlap(question: str, text: str) -> float:
    """Small corpus: exact ASCII identifiers + Japanese question fragments.

    Not BM25. Scales poorly. Will be replaced by FTS5/other hybrid index.
    """
    q = question.casefold()
    t = text.casefold()
    identifiers = re.findall(r'[a-z][a-z0-9_.-]{2,}', q)
    exact = sum(2.0 for token in set(identifiers) if token in t)
    japanese = re.findall(r'[\u3040-\u30ff\u3400-\u9fff]{2,}', q)
    jp = sum(1.0 for word in set(japanese) if word in t)
    return exact + jp


def search_documents(
    question: str,
    *,
    embeddings: EmbeddingProvider,
    embedding_model: str,
    scope: str,
    top_k: int = 4,
    db_path: Path = DB_PATH,
) -> list[dict[str, Any]]:
    if (
        not question.strip()
        or not scope.strip()
        or not (top_k is None or (type(top_k) is int and top_k > 0))
    ):
        raise ValueError('Invalid search arguments')
    init_rag(db_path)
    # Scope and lifecycle status are enforced before ranking, not by the LLM prompt.
    with closing(_db(db_path)) as con:
        rows = con.execute(
            '''SELECT c.chunk_id,c.chunk_text,c.embedding_json,
            d.doc_id,d.title,d.source_ref,d.source_type,d.status,d.updated_at,d.embedding_model
            FROM rag_chunks c JOIN rag_docs d ON c.doc_id=d.doc_id
            WHERE d.scope=? AND d.status='ACTIVE' ORDER BY c.chunk_id''',
            (scope,),
        ).fetchall()
    if not rows:
        return []
    other_models = {r['embedding_model'] for r in rows if r['embedding_model'] != embedding_model}
    if other_models:
        raise RuntimeError('Embedding model mismatch; reindex documents with the same model')
    query_vector = embeddings.embed_query(question)
    candidates = []
    for row in rows:
        vector = json.loads(row['embedding_json'])
        candidates.append(
            (
                row,
                cosine_similarity(query_vector, vector),
                _lexical_overlap(question, row['title'] + ' ' + row['chunk_text']),
            )
        )
    vector_order = sorted(
        range(len(candidates)), key=lambda i: (-candidates[i][1], candidates[i][0]['chunk_id'])
    )
    lexical_order = [
        i
        for i in sorted(
            range(len(candidates)), key=lambda i: (-candidates[i][2], candidates[i][0]['chunk_id'])
        )
        if candidates[i][2] > 0
    ]
    vector_rank = {idx: rank for rank, idx in enumerate(vector_order, 1)}
    lexical_rank = {idx: rank for rank, idx in enumerate(lexical_order, 1)}
    scored = []
    for idx, (row, sim, lexical) in enumerate(candidates):
        # Reciprocal rank fusion: small demo heuristic, not a learned relevance model.
        score = 1 / (60 + vector_rank[idx])
        if idx in lexical_rank:
            score += 1 / (60 + lexical_rank[idx])
        scored.append(
            (
                score,
                row['chunk_id'],
                {
                    'chunk_id': row['chunk_id'],
                    'doc_id': row['doc_id'],
                    'title': row['title'],
                    'source_ref': row['source_ref'],
                    'source_type': row['source_type'],
                    'status': row['status'],
                    'updated_at': row['updated_at'],
                    'text': row['chunk_text'],
                    'cosine': round(sim, 4),
                    'lexical_score': lexical,
                },
            )
        )
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [data for _, _, data in scored[:top_k]]


import math


class OfflineHashEmbedding:
    """Stable lexical hashed vectors. Not an LLM or a semantic quality claim."""

    def __init__(self, dim=256):
        self.dim = dim

    def embed_query(self, text):
        counts = [0.0] * self.dim
        for token in re.findall(r'[A-Za-z][A-Za-z0-9_\-.]+|[\u3040-\u9fff]{2,}', text.casefold()):
            idx = int.from_bytes(sha256(token.encode()).digest()[:4], 'big') % self.dim
            counts[idx] += 1
        norm = math.sqrt(sum(x * x for x in counts))
        return [round(x / norm, 8) if norm else 0.0 for x in counts]

    def embed_documents(self, texts):
        return [self.embed_query(x) for x in texts]
