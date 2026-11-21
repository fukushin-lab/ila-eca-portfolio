"""Scoped observation validation and declared dependency extraction for the existing lifecycle."""

from __future__ import annotations
from contextlib import closing

from datetime import datetime, timezone

from pathlib import Path

from typing import Any

import json

import sqlite3

from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, init_db

SCOPE = 'ila-discovery-lab'

HTTP_ADAPTER = 'lab_http_health_v1'

DOCKER_ADAPTER = 'docker_compose_lab_v1'

MAX_EVIDENCE_AGE_SECONDS = 300


def _audit_row(db_path: Path, evidence_id: str) -> dict[str, Any]:
    if not isinstance(evidence_id, str) or not evidence_id:
        raise ValueError('Missing evidence identifier')
    init_db(db_path)
    with closing(connect(db_path)) as con:
        con.row_factory = sqlite3.Row
        row = con.execute('SELECT * FROM evidence WHERE evidence_id=?', (evidence_id,)).fetchone()
    if row is None:
        raise ValueError('Evidence not present in trusted audit database')
    record = dict(row)
    when = datetime.fromisoformat(record['observed_at'])
    if when.tzinfo is None:
        raise ValueError('Evidence timestamp lacks timezone')
    age = (datetime.now(timezone.utc) - when).total_seconds()
    if age < -60 or age > MAX_EVIDENCE_AGE_SECONDS:
        raise ValueError('Evidence is too old or from the future')
    record['payload'] = json.loads(record['payload_json'])
    if not isinstance(record['payload'], dict):
        raise ValueError('Evidence payload must be a dictionary')
    return record


def _verify_http(row: dict[str, Any]) -> dict[str, Any]:
    if (row['adapter'], row['source'], row['scope']) != (
        HTTP_ADAPTER,
        'local_http_health_v1',
        SCOPE,
    ):
        raise ValueError('Untrusted or cross-scope HTTP evidence')
    p = row['payload']
    if p.get('source') != 'local_http_health_v1' or p.get('scope') != SCOPE:
        raise ValueError('HTTP payload provenance mismatch')
    if p.get('url') != 'http://127.0.0.1:18080/health':
        raise ValueError('Unexpected HTTP endpoint')
    status, code = p.get('status'), p.get('http_status')
    if status == 'healthy':
        if (code, p.get('dependency_reachable'), p.get('service')) != (200, True, 'web'):
            raise ValueError('Invalid healthy observation')
    elif status == 'degraded':
        if (code, p.get('dependency_reachable'), p.get('service')) != (503, False, 'web'):
            raise ValueError('Invalid degraded observation')
    elif status == 'unknown':
        if code in (200, 503) and not p.get('error'):
            raise ValueError('Ambiguous unknown HTTP result')
    else:
        raise ValueError('Unsupported HTTP status')
    return p


def _verify_docker(row: dict[str, Any]) -> dict[str, Any]:
    if (row['adapter'], row['source'], row['scope']) != (
        DOCKER_ADAPTER,
        'docker_engine_via_readonly_cli',
        SCOPE,
    ):
        raise ValueError('Untrusted or cross-scope Docker evidence')
    p = row['payload']
    if (p.get('schema'), p.get('source'), p.get('scope')) != (
        'ila.docker.discovery.v1',
        'docker_engine_via_readonly_cli',
        SCOPE,
    ):
        raise ValueError('Docker payload provenance mismatch')
    services = p.get('services')
    if not isinstance(services, list) or len(services) != 2:
        raise ValueError('Expected exactly two scoped lab services')
    by_service: dict[str, dict[str, Any]] = {}
    for s in services:
        if not isinstance(s, dict) or s.get('service') not in ('web', 'cache'):
            raise ValueError('Unrecognized lab container')
        if s['service'] in by_service or s.get('status') not in (
            'running',
            'exited',
            'created',
            'paused',
            'restarting',
            'dead',
        ):
            raise ValueError('Invalid or duplicate container status')
        by_service[s['service']] = s
    if set(by_service) != {'web', 'cache'}:
        raise ValueError('Required containers missing')
    edges = p.get('declared_dependencies')
    expected = {'from': 'web', 'to': 'cache', 'basis': 'compose_label_declared'}
    if not isinstance(edges, list) or expected not in edges:
        raise ValueError('Declared dependency absent')
    return p


ALLOWED_TARGETS = frozenset({'cache', 'web'})


DEPENDENCY_BASIS = 'compose_label_declared'


def dependency_graph_from_discovery(docker: dict[str, Any]) -> list[dict[str, Any]]:
    """Only accept topology actually declared in the scoped Docker evidence."""
    services = docker['services']
    ids = [s['service'] for s in services]
    if len(ids) != len(set(ids)) or set(ids) != ALLOWED_TARGETS:
        raise ValueError('Unexpected lab service identities')
    deps: dict[str, set[str]] = {name: set() for name in ids}
    edges = docker['declared_dependencies']
    if not isinstance(edges, list):
        raise ValueError('Missing declared dependency list')
    for edge in edges:
        if not isinstance(edge, dict) or edge.get('basis') != DEPENDENCY_BASIS:
            raise ValueError('Dependency is not an accepted declaration')
        src, dst = edge.get('from'), edge.get('to')
        if src not in deps or dst not in deps or src == dst:
            raise ValueError('Dependency references unknown service or itself')
        deps[src].add(dst)
    return [{'id': name, 'depends_on': sorted(deps[name])} for name in sorted(ids)]


