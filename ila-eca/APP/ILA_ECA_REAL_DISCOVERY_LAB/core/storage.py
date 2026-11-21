"""Shared SQLite evidence storage. Retired local probes and answer rewriting removed.

No LangChain imports. All DB handles explicitly closed (Windows-safe).
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import sqlite3
import uuid

DB_PATH = Path(__file__).resolve().parent / 'data' / 'ila_stage02.sqlite3'


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path), timeout=10)
    con.execute('PRAGMA busy_timeout=10000')
    return con


def init_db(db_path: Path = DB_PATH) -> None:
    with closing(connect(db_path)) as con:
        with con:
            con.execute(
                '''CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                observed_at TEXT NOT NULL,
                adapter TEXT NOT NULL,
                source TEXT NOT NULL,
                scope TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )'''
            )
            con.execute(
                '''CREATE TABLE IF NOT EXISTS decision_log (
                decision_id TEXT PRIMARY KEY,
                decided_at TEXT NOT NULL,
                question TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence_ids_json TEXT NOT NULL,
                public_answer TEXT NOT NULL
            )'''
            )


def save_evidence(
    *, adapter: str, source: str, scope: str, payload: dict[str, Any], db_path: Path = DB_PATH
) -> dict[str, Any]:
    """Persist real adapter result as an evidence record. Never invent values."""
    item = {
        'evidence_id': str(uuid.uuid4()),
        'observed_at': utc_now(),
        'adapter': adapter,
        'source': source,
        'scope': scope,
        'payload': payload,
    }
    init_db(db_path)
    with closing(connect(db_path)) as con:
        with con:
            con.execute(
                '''INSERT INTO evidence
                (evidence_id, observed_at, adapter, source, scope, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)''',
                (
                    item['evidence_id'],
                    item['observed_at'],
                    adapter,
                    source,
                    scope,
                    json.dumps(payload, ensure_ascii=False),
                ),
            )
    return item


