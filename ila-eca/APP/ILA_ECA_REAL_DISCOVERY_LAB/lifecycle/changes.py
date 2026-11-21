"""ILA/ECA shared, *lab-scoped* change lifecycle.

Trust model:
- Reference baseline is an explicit demo fixture, NOT inferred from Docker and NOT a real CMDB.
- A change request, LLM-written design, completion report, and meeting statement have NO authority.
- GitLab-verified human DESIGN approval is a separate APPROVED state.
  It never substitutes for execution permission or formal infrastructure acceptance.
  The original LAB-only execution gate remains a simulation.
- No infrastructure mutation, approval API calls, mail delivery, or LLM-side execution.
- Activation is atomic + guarded by independent verification and optimistic version check.
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
import json
import re
import sqlite3
import uuid

from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, init_db
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle.observations import (
    dependency_graph_from_discovery,
    SCOPE,
    _audit_row,
    _verify_docker,
    _verify_http,
)

_ALLOWED_ORIGINS = {'AI', 'HUMAN', 'HUMAN_AI_ASSISTED', 'TEMPLATE'}
_ALLOWED_EXECUTORS = {'HUMAN', 'AGENT', 'AUTOMATION', 'HYBRID'}
_STATES = {
    'DRAFT',
    'AWAITING_REVIEW',
    'APPROVED',
    'APPROVED_TEST_ONLY',
    'APPROVED_LAB_ONLY',
    'IMPLEMENTING',
    'REPORTED_COMPLETE',
    'HOLD_VERIFICATION',
    'VERIFIED_LAB_ONLY',
    'EFFECTIVE_LAB_ONLY',
    'CANCELED',
    'WORK_FAILED',
    'ROLLBACK_REPORTED_UNVERIFIED',
}
_CHID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$')


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _serialize(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False
    )


def _hash(value: Any) -> str:
    return sha256(_serialize(value).encode('utf-8')).hexdigest()


def _nonblank(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 300:
        raise ValueError(f'Invalid {label}')


def _validate_spec(spec: dict[str, Any]) -> None:
    """Small demo canonical design contract, deliberately NOT an inventory autodiscovery."""
    if not isinstance(spec, dict) or spec.get('scope') != SCOPE:
        raise ValueError('Baseline scope mismatch')
    services = spec.get('services')
    if not isinstance(services, list) or not services:
        raise ValueError('Baseline services must be a nonempty list')
    ids = [x.get('id') if isinstance(x, dict) else None for x in services]
    if any(not isinstance(x, str) or not _CHID.fullmatch(x) for x in ids):
        raise ValueError('Invalid service identity')
    if len(set(ids)) != len(ids):
        raise ValueError('Duplicate service identity')
    for svc in services:
        # Fail closed on properties this lab's Docker evidence cannot independently verify.
        if set(svc) != {'id', 'depends_on'}:
            raise ValueError('Unsupported service design fields require a new verifier')
        deps = svc.get('depends_on')
        if (
            not isinstance(deps, list)
            or any(not isinstance(d, str) for d in deps)
            or len(deps) != len(set(deps))
            or any(d not in ids or d == svc['id'] for d in deps)
        ):
            raise ValueError('Invalid declared dependency')
    # Only this narrow LAB runtime setting is verified by the Docker change adapter.
    # Do not silently accept arbitrary infrastructure settings or LLM-provided code.
    if 'lab_runtime' in spec:
        runtime = spec['lab_runtime']
        if (
            not isinstance(runtime, dict)
            or set(runtime) != {'web'}
            or not isinstance(runtime['web'], dict)
            or set(runtime['web']) != {'color'}
            or runtime['web']['color'] not in ('blue', 'green')
        ):
            raise ValueError('Unsupported lab runtime configuration')
    docs = spec.get('documents')
    if not isinstance(docs, dict) or not isinstance(docs.get('architecture_revision'), str):
        raise ValueError('Baseline document revision is required')
    if not docs['architecture_revision'].strip():
        raise ValueError('Blank baseline document revision')


def _graph(spec: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        [{'id': s['id'], 'depends_on': sorted(s['depends_on'])} for s in spec['services']],
        key=lambda x: x['id'],
    )


def proposal_kind(change):
    return dict(change).get('proposal_kind', 'DOCKER_LAB')


def _require_executable(change):
    # Registering an observed product proposal never extends the Docker gate.
    if proposal_kind(change) != 'DOCKER_LAB':
        raise PermissionError('KUBERNETES_REVIEW_ONLY_NOT_EXECUTABLE')
    value = dict(change)
    if (
        value.get('scope') != SCOPE
        or type(value.get('base_version')) is not int
        or value['base_version'] < 1
        or value.get('proposal_context_json') is not None
    ):
        raise PermissionError('EXECUTION_CHANGE_TYPE_BINDING_INVALID')


def proposal_document_baseline(db_path, change):
    if proposal_kind(change) == 'DOCKER_LAB':
        return current_baseline(db_path)
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import verify_context

    with closing(connect(db_path)) as con:
        return verify_context(con, db_path, change)


def init_lifecycle(db_path: Path) -> None:
    init_db(db_path)
    with closing(connect(db_path)) as con, con:
        con.executescript(
            '''
        CREATE TABLE IF NOT EXISTS lifecycle_baseline_v1 (
            scope TEXT NOT NULL, version INTEGER NOT NULL,
            spec_json TEXT NOT NULL, origin TEXT NOT NULL,
            effective_at_utc TEXT NOT NULL, change_id TEXT,
            PRIMARY KEY(scope, version)
        );
        CREATE TABLE IF NOT EXISTS lifecycle_current_v1 (
            scope TEXT PRIMARY KEY, version INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS lifecycle_change_v1 (
            change_id TEXT PRIMARY KEY, scope TEXT NOT NULL, base_version INTEGER NOT NULL,
            requested_by TEXT NOT NULL, purpose TEXT NOT NULL,
            intended_spec_json TEXT NOT NULL,
            status TEXT NOT NULL, design_origin TEXT, design_author TEXT,
            design_text TEXT, design_sha256 TEXT, model_id TEXT,
            review_actor TEXT, implementation_mode TEXT, implementation_actor TEXT,
            report_json TEXT, verification_json TEXT,
            created_at_utc TEXT NOT NULL, updated_at_utc TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS lifecycle_event_v1 (
            event_id TEXT PRIMARY KEY, change_id TEXT NOT NULL, event_type TEXT NOT NULL,
            actor TEXT NOT NULL, details_json TEXT NOT NULL, at_utc TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS lifecycle_work_step_v1 (
            change_id TEXT NOT NULL, step_id TEXT NOT NULL, position INTEGER NOT NULL,
            description TEXT NOT NULL, operation_key TEXT NOT NULL, state TEXT NOT NULL,
            actor TEXT, result_json TEXT, updated_at_utc TEXT NOT NULL,
            PRIMARY KEY(change_id, step_id), UNIQUE(change_id, position)
        );
        '''
        )
        columns = {r[1] for r in con.execute('PRAGMA table_info(lifecycle_change_v1)')}
        for name, definition in (
            ('proposal_kind', "TEXT NOT NULL DEFAULT 'DOCKER_LAB'"),
            ('proposal_context_json', 'TEXT'),
        ):
            if name not in columns:
                con.execute(f'ALTER TABLE lifecycle_change_v1 ADD COLUMN {name} {definition}')


def _event(
    con: sqlite3.Connection, change_id: str, event_type: str, actor: str, details: dict[str, Any]
) -> None:
    con.execute(
        'INSERT INTO lifecycle_event_v1 VALUES (?,?,?,?,?,?)',
        (str(uuid.uuid4()), change_id, event_type, actor, _serialize(details), _now()),
    )


def _one(con: sqlite3.Connection, sql: str, args: tuple = ()) -> sqlite3.Row:
    con.row_factory = sqlite3.Row
    row = con.execute(sql, args).fetchone()
    if row is None:
        raise ValueError('Record not found')
    return row


def current_baseline(db_path: Path, scope: str = SCOPE) -> dict[str, Any]:
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con:
        row = _one(
            con,
            '''SELECT b.* FROM lifecycle_current_v1 h
             JOIN lifecycle_baseline_v1 b ON b.scope=h.scope AND b.version=h.version
             WHERE h.scope=?''',
            (scope,),
        )
        return {
            'scope': scope,
            'version': row['version'],
            'spec': json.loads(row['spec_json']),
            'origin': row['origin'],
            'effective_at_utc': row['effective_at_utc'],
            'change_id': row['change_id'],
        }


def seed_explicit_lab_baseline(db_path: Path, spec: dict[str, Any]) -> dict[str, Any]:
    """Only a fixture bootstrap. The fixture is NEVER labelled enterprise-approved."""
    _validate_spec(spec)
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con:
        with con:
            con.execute('BEGIN IMMEDIATE')
            prior = con.execute(
                'SELECT version FROM lifecycle_current_v1 WHERE scope=?', (SCOPE,)
            ).fetchone()
            if prior is not None:
                raise ValueError('Baseline already exists; refusing to reseed')
            con.execute(
                'INSERT INTO lifecycle_baseline_v1 VALUES (?,?,?,?,?,?)',
                (SCOPE, 1, _serialize(spec), 'EXPLICIT_LAB_FIXTURE_NOT_AUTHORITY', _now(), None),
            )
            con.execute('INSERT INTO lifecycle_current_v1 VALUES (?,?)', (SCOPE, 1))
    return current_baseline(db_path)


def get_change(db_path: Path, change_id: str) -> dict[str, Any]:
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con:
        row = dict(_one(con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,)))
        for name in (
            'intended_spec_json',
            'report_json',
            'verification_json',
            'proposal_context_json',
        ):
            row[name[:-5]] = json.loads(row[name]) if row[name] else None
        if row['status'] in {'APPROVED', 'APPROVED_TEST_ONLY'}:
            row.update(
                approval_scope='DESIGN_REVIEW_ONLY',
                approval_granted=False,
                formal_approval_status='REQUIRES_FRESH_GITLAB_VERIFICATION',
                execution_allowed=False,
            )
            if row['status'] == 'APPROVED_TEST_ONLY':
                row.update(
                    test_only=True, test_approval_recorded=True, approval_scope='ACCOUNT_TEST_ONLY'
                )
        return row


def _modify(
    db_path: Path,
    change_id: str,
    allowed: tuple[str, ...],
    new_status: str,
    actor: str,
    details: dict[str, Any],
    fields: dict[str, Any] | None = None,
    _connection: sqlite3.Connection | None = None,
) -> None:
    if new_status not in _STATES:
        raise ValueError('Unknown lifecycle state')

    def apply(con):
        r = _one(con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,))
        if r['status'] not in allowed:
            raise ValueError(f'Invalid transition: {r["status"]} -> {new_status}')
        if proposal_kind(r) != 'DOCKER_LAB' and new_status not in {'AWAITING_REVIEW', 'CANCELED'}:
            _require_executable(r)
        _assert_integrity(con, r, db_path)
        if new_status in ('APPROVED_LAB_ONLY', 'IMPLEMENTING', 'VERIFIED_LAB_ONLY'):
            head = _one(
                con, 'SELECT version FROM lifecycle_current_v1 WHERE scope=?', (r['scope'],)
            )
            if head['version'] != r['base_version']:
                raise ValueError('Baseline changed during transition')
        updates = {**(fields or {}), 'status': new_status, 'updated_at_utc': _now()}
        if any(
            k
            not in {
                'status',
                'updated_at_utc',
                'design_origin',
                'design_author',
                'design_text',
                'design_sha256',
                'model_id',
                'review_actor',
                'implementation_mode',
                'implementation_actor',
                'report_json',
                'verification_json',
            }
            for k in updates
        ):
            raise ValueError('Invalid change field')
        clause = ', '.join(f'{k}=?' for k in updates)
        con.execute(
            f'UPDATE lifecycle_change_v1 SET {clause} WHERE change_id=?',
            (*updates.values(), change_id),
        )
        event_details = dict(details)
        if new_status == 'AWAITING_REVIEW':
            submitted = _one(
                con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,)
            )
            event_details['binding_sha256'] = _binding(con, submitted)
        _event(con, change_id, new_status, actor, event_details)

    if _connection is not None:
        if not _connection.in_transaction:
            raise ValueError('Caller transaction required')
        apply(_connection)
    else:
        init_lifecycle(db_path)
        with closing(connect(db_path)) as con, con:
            con.execute('BEGIN IMMEDIATE')
            apply(con)


def _binding(con, change):
    typed = proposal_kind(change) != 'DOCKER_LAB'
    if typed:
        from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import validate_spec

        intended = json.loads(change['intended_spec_json'])
        validate_spec(intended)
        # Version zero is an unbound observed snapshot, never a Baseline row.
        base = {'spec_json': _serialize({**intended, 'after': intended['before']})}
    else:
        base = _one(
            con,
            'SELECT spec_json FROM lifecycle_baseline_v1 WHERE scope=? AND version=?',
            (change['scope'], change['base_version']),
        )
    plan = [
        dict(row)
        for row in con.execute(
            'SELECT step_id,position,description,operation_key FROM lifecycle_work_step_v1 WHERE change_id=? ORDER BY position',
            (change['change_id'],),
        ).fetchall()
    ]
    material = {
        k: change[k]
        for k in (
            'change_id',
            'scope',
            'base_version',
            'purpose',
            'intended_spec_json',
            'design_text',
            'design_sha256',
            'design_origin',
            'design_author',
            'model_id',
        )
    } | {'baseline_spec_json': base['spec_json'], 'work_plan': plan}
    if typed:
        material.update(
            proposal_kind=proposal_kind(change),
            proposal_context_json=change['proposal_context_json'],
            requested_by=change['requested_by'],
        )
    return _hash(material)


def _assert_integrity(con, change, db_path):
    """Bind the existing approval to its content; this is not a second approval."""
    events = con.execute(
        'SELECT event_type,details_json FROM lifecycle_event_v1 WHERE change_id=?',
        (change['change_id'],),
    ).fetchall()
    proposed = [json.loads(e[1]) for e in events if e[0] == 'CHANGE_PROPOSED']
    if (
        len(proposed) != 1
        or proposed[0]['intended_hash'] != _hash(json.loads(change['intended_spec_json']))
        or proposed[0]['base_version'] != change['base_version']
    ):
        raise ValueError('Proposed design or input baseline changed')
    if proposal_kind(change) == 'DOCKER_LAB' and (
        proposed[0].get('proposal_kind', 'DOCKER_LAB') != 'DOCKER_LAB'
        or change['scope'] != SCOPE
        or change['base_version'] < 1
        or dict(change).get('proposal_context_json') is not None
    ):
        raise ValueError('CHANGE_PROPOSAL_KIND_BINDING_CHANGED')
    if proposal_kind(change) != 'DOCKER_LAB':
        from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import KIND
        from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import verify_context

        if (
            proposal_kind(change) != KIND
            or change['base_version'] != 0
            or change['scope'] != 'lab'
            or change['status']
            not in {'DRAFT', 'AWAITING_REVIEW', 'APPROVED', 'APPROVED_TEST_ONLY', 'CANCELED'}
            or proposed[0].get('proposal_kind') != KIND
            or proposed[0].get('requested_by') != change['requested_by']
            or proposed[0].get('purpose_sha256') != _hash(change['purpose'])
            or proposed[0].get('proposal_context_sha256')
            != _hash(json.loads(change['proposal_context_json']))
        ):
            raise ValueError('KUBERNETES_REVIEW_CONTEXT_OR_STATE_CHANGED')
        verify_context(con, db_path, change)
    if change['status'] == 'DRAFT':
        return
    actual_sha = sha256(change['design_text'].encode('utf-8')).hexdigest()
    submitted = [json.loads(e[1]) for e in events if e[0] == 'AWAITING_REVIEW']
    if (
        len(submitted) != 1
        or actual_sha != change['design_sha256']
        or submitted[0]['design_sha256'] != actual_sha
    ):
        raise ValueError('Submitted design digest changed')
    if submitted[0].get('binding_sha256') and submitted[0]['binding_sha256'] != _binding(
        con, change
    ):
        raise ValueError('Submitted design binding changed')
    # Prior artifacts keep their byte check; new revisions also bind JSON and spec.
    if con.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='lifecycle_design_artifact_v2'"
    ).fetchone():
        from ILA_ECA_REAL_DISCOVERY_LAB.design.change import verify_artifact_content

        rows = con.execute(
            'SELECT * FROM lifecycle_design_artifact_v2 WHERE change_id=?', (change['change_id'],)
        ).fetchall()
        for row in rows:
            if (
                row['document_sha256'] != actual_sha
                or row['base_version'] != change['base_version']
                or row['proposed_spec_sha256'] != _hash(json.loads(change['intended_spec_json']))
                or not verify_artifact_content(Path(db_path), row)
            ):
                raise ValueError('Design artifact or structured data changed')
            if 'record_json' in row.keys() and row['record_json']:
                registered = con.execute(
                    'SELECT record_json FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? AND revision=?',
                    (
                        'CLOSED_LAB' if proposal_kind(change) == 'DOCKER_LAB' else 'lab',
                        change['change_id'],
                        row['revision'],
                    ),
                ).fetchone()
                if not registered or registered[0] != row['record_json']:
                    raise ValueError('Design document registry changed')
                material = json.loads(
                    (
                        Path(db_path).resolve().parent
                        / 'design_drafts_lab'
                        / row['structured_path']
                    ).read_bytes()
                )
                if material['details'].get('incident_investigation_binding'):
                    from ILA_ECA_REAL_DISCOVERY_LAB.incident.artifacts import verify_repair_binding

                    verify_repair_binding(
                        con, db_path, material['details']['incident_investigation_binding'], change
                    )
                if material['details'].get('document_reviews'):
                    from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import (
                        verify_attached_document_from_connection,
                    )

                    bindings = material['details'].get('document_review_bindings', [])
                    if [{k: r[k] for k in ('design_id', 'revision')} for r in bindings] != material[
                        'details'
                    ]['document_reviews']:
                        raise ValueError('DOCUMENT_REVIEW_BINDINGS_MISSING')
                    for review in bindings:
                        bound = verify_attached_document_from_connection(
                            con, db_path, review['design_id'], review['revision'], change['scope']
                        )
                        if bound['record']['artifact_sha256'] != review['artifact_sha256']:
                            raise ValueError('DOCUMENT_REVIEW_BINDINGS_CHANGED')
                collected = material['details'].get('collected_evidence', {}).get('evidence', [])
                for selection in collected:
                    if selection['state'] != 'COLLECTED_AT_RECORDED_TIME':
                        continue
                    source = _one(
                        con,
                        'SELECT * FROM evidence WHERE evidence_id=?',
                        (selection['evidence_id'],),
                    )
                    if (
                        source['scope'] != change['scope']
                        or _hash(dict(source)) != selection['record_sha256']
                    ):
                        raise ValueError('Design source evidence changed')


def assert_change_integrity(db_path: Path, change_id: str) -> None:
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con:
        change = _one(con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,))
        _assert_integrity(con, change, db_path)


def propose_change(
    db_path: Path, *, change_id: str, requested_by: str, purpose: str, intended_spec: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(change_id, str) or not _CHID.fullmatch(change_id):
        raise ValueError('Invalid change ID')
    _nonblank(requested_by, 'requester')
    _nonblank(purpose, 'purpose')
    _validate_spec(intended_spec)
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con:
        with con:
            con.execute('BEGIN IMMEDIATE')
            head = _one(con, 'SELECT version FROM lifecycle_current_v1 WHERE scope=?', (SCOPE,))
            now = _now()
            con.execute(
                '''INSERT INTO lifecycle_change_v1
                (change_id,scope,base_version,requested_by,purpose,intended_spec_json,
                 status,created_at_utc,updated_at_utc) VALUES (?,?,?,?,?,?,?,?,?)''',
                (
                    change_id,
                    SCOPE,
                    head['version'],
                    requested_by,
                    purpose,
                    _serialize(intended_spec),
                    'DRAFT',
                    now,
                    now,
                ),
            )
            _event(
                con,
                change_id,
                'CHANGE_PROPOSED',
                requested_by,
                {
                    'base_version': head['version'],
                    'intended_hash': _hash(intended_spec),
                    'authority': 'UNVERIFIED_REQUEST',
                },
            )
    return get_change(db_path, change_id)


def propose_review_change(
    db_path, *, change_id, requested_by, purpose, intended_spec, proposal_context
):
    """A typed product request in the existing queue; does not create a Baseline."""
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import KIND
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import validate_spec
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import validate_context
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import verify_context

    if not isinstance(change_id, str) or not _CHID.fullmatch(change_id):
        raise ValueError('Invalid change ID')
    _nonblank(requested_by, 'requester')
    if not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 500:
        raise ValueError('Invalid purpose')
    validate_spec(intended_spec)
    validate_context(proposal_context)
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con, con:
        con.execute('BEGIN IMMEDIATE')
        existing = con.execute(
            'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,)
        ).fetchone()
        if existing:
            con.row_factory = sqlite3.Row
            existing = _one(
                con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,)
            )
            if (
                proposal_kind(existing) != KIND
                or existing['requested_by'] != requested_by
                or existing['purpose'] != purpose
                or existing['intended_spec_json'] != _serialize(intended_spec)
                or existing['proposal_context_json'] != _serialize(proposal_context)
            ):
                raise ValueError('KUBERNETES_CHANGE_ID_CONFLICT')
            _assert_integrity(con, existing, db_path)
        else:
            trial = {
                'change_id': change_id,
                'scope': 'lab',
                'base_version': 0,
                'proposal_kind': KIND,
                'intended_spec_json': _serialize(intended_spec),
                'proposal_context_json': _serialize(proposal_context),
                'status': 'DRAFT',
            }
            verify_context(con, db_path, trial)
            now = _now()
            con.execute(
                '''INSERT INTO lifecycle_change_v1
                (change_id,scope,base_version,requested_by,purpose,intended_spec_json,status,created_at_utc,updated_at_utc,proposal_kind,proposal_context_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                (
                    change_id,
                    'lab',
                    0,
                    requested_by,
                    purpose,
                    _serialize(intended_spec),
                    'DRAFT',
                    now,
                    now,
                    KIND,
                    _serialize(proposal_context),
                ),
            )
            _event(
                con,
                change_id,
                'CHANGE_PROPOSED',
                requested_by,
                {
                    'base_version': 0,
                    'intended_hash': _hash(intended_spec),
                    'proposal_kind': KIND,
                    'requested_by': requested_by,
                    'purpose_sha256': _hash(purpose),
                    'proposal_context_sha256': _hash(proposal_context),
                    'authority': 'UNVERIFIED_REVIEW_REQUEST_NO_EFFECTIVE_BASELINE',
                },
            )
    return get_change(db_path, change_id)


def list_pending_reviews(db_path, *, scope=None):
    """Return actual submitted requests after checking their immutable bindings."""
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT * FROM lifecycle_change_v1 WHERE status='AWAITING_REVIEW'"
            + (' AND scope=?' if scope is not None else '')
            + ' ORDER BY created_at_utc,change_id',
            (scope,) if scope is not None else (),
        ).fetchall()
        for row in rows:
            _assert_integrity(con, row, db_path)
        return [dict(row) for row in rows]


def submit_design(
    db_path: Path,
    *,
    change_id: str,
    design_text: str,
    design_origin: str,
    author: str,
    model_id: str | None = None,
    _connection: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    if design_origin not in _ALLOWED_ORIGINS:
        raise ValueError('Unknown design origin')
    _nonblank(author, 'design author')
    if not isinstance(design_text, str) or len(design_text.strip()) < 40:
        raise ValueError('Design document is incomplete')
    if len(design_text) > 300_000:
        raise ValueError('Design document exceeds demo limit')
    if model_id is not None and (not isinstance(model_id, str) or len(model_id) > 120):
        raise ValueError('Invalid model ID')
    _modify(
        db_path,
        change_id,
        ('DRAFT',),
        'AWAITING_REVIEW',
        author,
        {
            'design_sha256': sha256(design_text.encode('utf-8')).hexdigest(),
            'design_origin': design_origin,
            'authority': 'DOCUMENT_DRAFT_ONLY',
        },
        {
            'design_text': design_text,
            'design_sha256': sha256(design_text.encode('utf-8')).hexdigest(),
            'design_origin': design_origin,
            'design_author': author,
            'model_id': model_id,
        },
        _connection=_connection,
    )
    if _connection is not None:
        return dict(
            _one(_connection, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,))
        )
    return get_change(db_path, change_id)


def check_review_binding(db_path: Path, *, change_id: str, reviewer: str, design_sha256: str):
    """Shared content/independence/current-Baseline checks; grants no authority."""
    _nonblank(reviewer, 'reviewer')
    ch = get_change(db_path, change_id)
    _require_executable(ch)
    if reviewer == ch['design_author']:
        raise ValueError('Separate design reviewer required in this lab')
    if design_sha256 != ch['design_sha256']:
        raise ValueError('Reviewed artifact digest does not match current design')
    if current_baseline(db_path)['version'] != ch['base_version']:
        raise ValueError('Baseline changed before design review')


def lab_attest_review(
    db_path: Path,
    *,
    change_id: str,
    reviewer: str,
    design_sha256: str,
    explicit_lab_simulation: bool = False,
) -> dict[str, Any]:
    """No ITSM authority. Explicitly TEST/LAB ONLY; never satisfies enterprise approval."""
    if not explicit_lab_simulation:
        raise PermissionError('No formal approval connector; only explicit LAB simulation allowed')
    check_review_binding(
        db_path, change_id=change_id, reviewer=reviewer, design_sha256=design_sha256
    )
    _modify(
        db_path,
        change_id,
        ('AWAITING_REVIEW',),
        'APPROVED_LAB_ONLY',
        reviewer,
        {'reviewed_digest': design_sha256, 'authority': 'LAB_SIMULATION_NOT_FORMAL_APPROVAL'},
        {'review_actor': reviewer},
    )
    return get_change(db_path, change_id)


def begin_implementation(
    db_path: Path, *, change_id: str, executor: str, execution_mode: str
) -> dict[str, Any]:
    if execution_mode not in _ALLOWED_EXECUTORS:
        raise ValueError('Unknown execution mode')
    _nonblank(executor, 'executor')
    ch = get_change(db_path, change_id)
    _require_executable(ch)
    assert_change_integrity(db_path, change_id)
    if ch['status'] == 'IMPLEMENTING' and (executor, execution_mode) == (
        ch['implementation_actor'],
        ch['implementation_mode'],
    ):
        if current_baseline(db_path)['version'] != ch['base_version']:
            raise ValueError('Baseline changed before implementation')
        return ch
    if current_baseline(db_path)['version'] != ch['base_version']:
        raise ValueError('Baseline changed before implementation')
    _modify(
        db_path,
        change_id,
        ('APPROVED_LAB_ONLY',),
        'IMPLEMENTING',
        executor,
        {
            'execution_mode': execution_mode,
            'design_digest': ch['design_sha256'],
            'authority': 'LAB_SIMULATION_ONLY',
        },
        {'implementation_mode': execution_mode, 'implementation_actor': executor},
    )
    return get_change(db_path, change_id)


def report_completion(
    db_path: Path,
    *,
    change_id: str,
    reporter: str,
    summary: str,
    work_references: list[str],
    actual_design_sha256: str,
) -> dict[str, Any]:
    _nonblank(reporter, 'reporter')
    _nonblank(summary, 'summary')
    if (
        not isinstance(work_references, list)
        or not work_references
        or any(
            not isinstance(ref, str) or not ref.strip() or len(ref) > 256 for ref in work_references
        )
    ):
        raise ValueError('Work record references required')
    ch = get_change(db_path, change_id)
    if ch['status'] != 'IMPLEMENTING':
        raise ValueError('Invalid transition: implementation must have started')
    if reporter != ch['implementation_actor']:
        raise ValueError('Reporter must be the declared implementation actor')
    _assert_work_complete(db_path, change_id)
    report = {
        'reported_by': reporter,
        'summary': summary,
        'work_references': work_references,
        'actual_design_sha256': actual_design_sha256,
        'reported_at_utc': _now(),
        'verification_claim': 'NOT_INDEPENDENTLY_VERIFIED',
    }
    _modify(
        db_path,
        change_id,
        ('IMPLEMENTING',),
        'REPORTED_COMPLETE',
        reporter,
        {'work_references': work_references, 'verification': 'PENDING'},
        {'report_json': _serialize(report)},
    )
    return get_change(db_path, change_id)


def report_work_failure(
    db_path: Path,
    *,
    change_id: str,
    reporter: str,
    failure_summary: str,
    work_references: list[str],
) -> dict[str, Any]:
    """Failed implementation cannot become effective; rollback remains unverified."""
    _nonblank(reporter, 'reporter')
    _nonblank(failure_summary, 'failure summary')
    if not isinstance(work_references, list) or not work_references:
        raise ValueError('Work log reference required')
    ch = get_change(db_path, change_id)
    if reporter != ch['implementation_actor']:
        raise ValueError('Reporter must be the implementation actor')
    report = {
        'outcome': 'FAILED',
        'reported_by': reporter,
        'failure_summary': failure_summary,
        'work_references': work_references,
        'rollback_status': 'NOT_VERIFIED',
        'reported_at_utc': _now(),
    }
    _modify(
        db_path,
        change_id,
        ('IMPLEMENTING',),
        'WORK_FAILED',
        reporter,
        {'failure_summary': failure_summary, 'rollback_status': 'NOT_VERIFIED'},
        {'report_json': _serialize(report)},
    )
    return get_change(db_path, change_id)


def report_rollback(
    db_path: Path, *, change_id: str, reporter: str, work_references: list[str]
) -> dict[str, Any]:
    """Rollback report never establishes recovery, acceptance or effective baseline."""
    _nonblank(reporter, 'reporter')
    if not isinstance(work_references, list) or not work_references:
        raise ValueError('Rollback evidence refs required')
    ch = get_change(db_path, change_id)
    if reporter != ch['implementation_actor']:
        raise ValueError('Rollback reporter is not assigned implementer')
    report = dict(ch['report'] or {})
    report['rollback_status'] = 'REPORTED_UNVERIFIED'
    report['rollback_references'] = work_references
    report['rollback_reported_at_utc'] = _now()
    _modify(
        db_path,
        change_id,
        ('WORK_FAILED',),
        'ROLLBACK_REPORTED_UNVERIFIED',
        reporter,
        {'rollback_references': work_references, 'verification': 'REQUIRED_SEPARATELY'},
        {'report_json': _serialize(report)},
    )
    return get_change(db_path, change_id)


def verify_implementation(
    db_path: Path,
    *,
    change_id: str,
    verifier: str,
    docker_evidence_id: str,
    http_evidence_id: str,
    verified_design_path: Path | None = None,
) -> dict[str, Any]:
    """Observe live lab; compare declared topology+health to proposed spec.

    Does NOT verify unobservable design fields, test procedures, documents or the
    legitimacy of a reviewer. Hence status says VERIFIED_LAB_ONLY, never production acceptance.
    """
    _nonblank(verifier, 'verifier')
    ch = get_change(db_path, change_id)
    if ch['status'] not in ('REPORTED_COMPLETE', 'HOLD_VERIFICATION'):
        raise ValueError('Completion report required before independent verification')
    if verifier == ch['implementation_actor']:
        raise ValueError('Independent verifier must differ from implementer')
    expected = ch['intended_spec']
    report = ch['report']
    reasons: list[str] = []
    if report['actual_design_sha256'] != ch['design_sha256']:
        reasons.append('reported_design_digest_mismatch')
    if docker_evidence_id == http_evidence_id:
        raise ValueError('Two independent observation IDs are required')
    drow = _audit_row(Path(db_path), docker_evidence_id)
    hrow = _audit_row(Path(db_path), http_evidence_id)
    docker = _verify_docker(drow)
    http = _verify_http(hrow)
    dt = datetime.fromisoformat(drow['observed_at'])
    ht = datetime.fromisoformat(hrow['observed_at'])
    report_time = datetime.fromisoformat(report['reported_at_utc'])
    if dt < report_time or ht < report_time:
        raise ValueError('Independent observations must occur AFTER completion report')
    if abs((dt - ht).total_seconds()) > 30:
        raise ValueError('Snapshot observation timestamps differ by >30s')
    actual_graph = dependency_graph_from_discovery(docker)
    if _graph(expected) != actual_graph:
        reasons.append('live_topology_mismatch')
    if any(s['status'] != 'running' or s.get('health') != 'healthy' for s in docker['services']):
        reasons.append('docker_not_healthy')
    if not (
        http['status'] == 'healthy'
        and http['http_status'] == 200
        and http.get('dependency_reachable') is True
    ):
        reasons.append('http_not_healthy')
    # The lab can VERIFY ONLY its topology/health contract.
    # A change in other design content requires a real verification adapter.
    base = current_baseline(db_path)
    with closing(connect(db_path)) as con:
        row = _one(
            con,
            '''SELECT spec_json FROM lifecycle_baseline_v1
                          WHERE scope=? AND version=?''',
            (SCOPE, ch['base_version']),
        )
    previous = json.loads(row['spec_json'])
    if expected.get('documents') != previous.get('documents'):
        # A separately verified published document can prove the DEMO design
        # artifact is in place, but cannot prove infrastructure state by itself.
        verified = False
        if verified_design_path is not None:
            root = (Path(db_path).resolve().parent / 'verified_artifacts').resolve()
            path = Path(verified_design_path).resolve()
            if path.is_relative_to(root) and path.is_file() and path.stat().st_size < 300_001:
                verified = (
                    sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
                    == ch['design_sha256']
                )
        if not verified:
            reasons.append('design_document_revision_not_independently_verified')
    for k in set(expected) | set(previous):
        if k not in {'scope', 'services', 'documents'} and expected.get(k) != previous.get(k):
            reasons.append(f'field_{k}_cannot_be_verified_by_lab')
    if base['version'] != ch['base_version']:
        reasons.append('current_baseline_advanced')
    verification = {
        'verifier': verifier,
        'verified_at_utc': _now(),
        'evidence_ids': [docker_evidence_id, http_evidence_id],
        'expected_topology': _graph(expected),
        'observed_topology': actual_graph,
        'reasons': sorted(set(reasons)),
        'status': 'PASS_LAB_ONLY' if not reasons else 'HOLD',
        'authority': 'READ_ONLY_LAB_OBSERVATIONS_NOT_FORMAL_ACCEPTANCE',
        'report_sha256': _hash(report),
        'observation_sha256': {
            docker_evidence_id: _hash({k: v for k, v in drow.items() if k != 'payload'}),
            http_evidence_id: _hash({k: v for k, v in hrow.items() if k != 'payload'}),
        },
    }
    new_status = 'VERIFIED_LAB_ONLY' if not reasons else 'HOLD_VERIFICATION'
    _modify(
        db_path,
        change_id,
        ('REPORTED_COMPLETE', 'HOLD_VERIFICATION'),
        new_status,
        verifier,
        {
            'status': verification['status'],
            'reasons': verification['reasons'],
            'evidence_ids': verification['evidence_ids'],
        },
        {'verification_json': _serialize(verification)},
    )
    return get_change(db_path, change_id)


def lab_accept_and_activate(
    db_path: Path, *, change_id: str, acceptor: str, explicit_lab_simulation: bool = False
) -> dict[str, Any]:
    if not explicit_lab_simulation:
        raise PermissionError('Formal enterprise acceptance/activation connector is absent')
    _nonblank(acceptor, 'acceptor')
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con:
        with con:
            con.execute('BEGIN IMMEDIATE')
            ch = _one(con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,))
            _assert_integrity(con, ch, db_path)
            if ch['status'] != 'VERIFIED_LAB_ONLY':
                raise ValueError('Independent verification PASS required before activation')
            verification = json.loads(ch['verification_json'])
            if verification['status'] != 'PASS_LAB_ONLY':
                raise ValueError('Verification has unresolved findings')
            if con.execute(
                "SELECT 1 FROM sqlite_master WHERE name='lifecycle_design_artifact_v2'"
            ).fetchone():
                for artifact in con.execute(
                    'SELECT structured_path FROM lifecycle_design_artifact_v2 WHERE change_id=?',
                    (change_id,),
                ):
                    if not artifact[0]:
                        continue
                    material = json.loads(
                        (
                            Path(db_path).resolve().parent / 'design_drafts_lab' / artifact[0]
                        ).read_bytes()
                    )
                    if material['details'].get('incident_investigation_binding'):
                        from ILA_ECA_REAL_DISCOVERY_LAB.incident.artifacts import (
                            assert_symptom_resolved,
                        )

                        assert_symptom_resolved(
                            db_path, material['details']['incident_investigation_binding'], ch
                        )
            if verification.get('report_sha256') and verification['report_sha256'] != _hash(
                json.loads(ch['report_json'])
            ):
                raise ValueError('Completion report changed after verification')
            for evidence_id, expected_sha in verification.get('observation_sha256', {}).items():
                observed = _one(con, 'SELECT * FROM evidence WHERE evidence_id=?', (evidence_id,))
                if _hash(dict(observed)) != expected_sha:
                    raise ValueError('Observation changed after verification')
            if con.execute(
                "SELECT 1 FROM lifecycle_work_step_v1 WHERE change_id=? AND state!='COMPLETED'",
                (change_id,),
            ).fetchone():
                raise ValueError('Work plan remains incomplete')
            if acceptor in {ch['implementation_actor'], ch['design_author']}:
                raise ValueError('Acceptance must be independent of implementation/design')
            head = _one(con, 'SELECT version FROM lifecycle_current_v1 WHERE scope=?', (SCOPE,))
            if head['version'] != ch['base_version']:
                raise ValueError('Concurrent baseline update: stale change blocked')
            next_version = head['version'] + 1
            con.execute(
                'INSERT INTO lifecycle_baseline_v1 VALUES (?,?,?,?,?,?)',
                (
                    SCOPE,
                    next_version,
                    ch['intended_spec_json'],
                    'LAB_SIMULATED_ACCEPTED_NOT_ENTERPRISE_AUTHORITY',
                    _now(),
                    change_id,
                ),
            )
            cur = con.execute(
                '''UPDATE lifecycle_current_v1 SET version=?
                                 WHERE scope=? AND version=?''',
                (next_version, SCOPE, head['version']),
            )
            if cur.rowcount != 1:
                raise ValueError('Baseline pointer changed concurrently')
            con.execute(
                'UPDATE lifecycle_change_v1 SET status=?, updated_at_utc=? WHERE change_id=?',
                ('EFFECTIVE_LAB_ONLY', _now(), change_id),
            )
            _event(
                con,
                change_id,
                'BASELINE_ACTIVATED_LAB_ONLY',
                acceptor,
                {
                    'prior_version': head['version'],
                    'new_version': next_version,
                    'design_sha256': ch['design_sha256'],
                    'verification_evidence_ids': verification['evidence_ids'],
                    'authority': 'LAB_SIMULATION_NOT_ENTERPRISE_APPROVAL',
                },
            )
    return current_baseline(db_path)


def list_change_events(db_path: Path, change_id: str) -> list[dict[str, Any]]:
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            '''SELECT event_id,event_type,actor,details_json,at_utc
            FROM lifecycle_event_v1 WHERE change_id=? ORDER BY at_utc,event_id''',
            (change_id,),
        ).fetchall()
    return [{**dict(r), 'details': json.loads(r['details_json'])} for r in rows]


def register_work_plan(db_path: Path, change_id: str, steps: list[dict]) -> list[dict]:
    """Record authored steps before submission. A plan records no permission."""
    if not isinstance(steps, list) or not steps:
        raise ValueError('Nonempty work plan required')
    for step in steps:
        if not isinstance(step, dict) or set(step) != {'step_id', 'description'}:
            raise ValueError('Invalid work plan step')
        if not isinstance(step['step_id'], str) or not _CHID.fullmatch(step['step_id']):
            raise ValueError('Invalid work step ID')
        _nonblank(step['description'], 'work description')
    if len({s['step_id'] for s in steps}) != len(steps):
        raise ValueError('Duplicate work step')
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con, con:
        con.execute('BEGIN IMMEDIATE')
        ch = _one(con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,))
        _assert_integrity(con, ch, db_path)
        old = con.execute(
            'SELECT step_id,description FROM lifecycle_work_step_v1 WHERE change_id=? ORDER BY position',
            (change_id,),
        ).fetchall()
        if old:
            if [dict(r) for r in old] != steps:
                raise ValueError(
                    'Work plan already bound; create a new change for a different plan'
                )
        else:
            if ch['status'] != 'DRAFT':
                raise ValueError('Work plan must precede submitted design')
            for position, step in enumerate(steps):
                con.execute(
                    'INSERT INTO lifecycle_work_step_v1 VALUES (?,?,?,?,?,?,?,?,?)',
                    (
                        change_id,
                        step['step_id'],
                        position,
                        step['description'],
                        _hash([change_id, step]),
                        'PENDING',
                        None,
                        None,
                        _now(),
                    ),
                )
            _event(
                con,
                change_id,
                'WORK_PLAN_REGISTERED',
                ch['requested_by'],
                {'plan_sha256': _hash(steps)},
            )
    return work_progress(db_path, change_id)


def work_progress(db_path: Path, change_id: str) -> list[dict]:
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con:
        _one(con, 'SELECT change_id FROM lifecycle_change_v1 WHERE change_id=?', (change_id,))
        con.row_factory = sqlite3.Row
        return [
            {**dict(row), 'result': json.loads(row['result_json']) if row['result_json'] else None}
            for row in con.execute(
                'SELECT * FROM lifecycle_work_step_v1 WHERE change_id=? ORDER BY position',
                (change_id,),
            )
        ]


def claim_work_step(db_path: Path, change_id: str, step_id: str, *, actor: str) -> dict:
    """Durable claim BEFORE dispatch. In-flight or completed work is never redispatched.

    The caller must honor dispatch=False and pass operation_key to tools supporting
    idempotency. A crash after external dispatch requires reconciling the tool's
    receipt; it cannot be solved with blind automatic retries.
    """
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con, con:
        con.execute('BEGIN IMMEDIATE')
        ch = _one(con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,))
        _assert_integrity(con, ch, db_path)
        if ch['status'] != 'IMPLEMENTING' or actor != ch['implementation_actor']:
            raise ValueError('Assigned active implementer required')
        head = _one(con, 'SELECT version FROM lifecycle_current_v1 WHERE scope=?', (ch['scope'],))
        if head['version'] != ch['base_version']:
            raise ValueError('Baseline changed before work dispatch')
        step = _one(
            con,
            'SELECT * FROM lifecycle_work_step_v1 WHERE change_id=? AND step_id=?',
            (change_id, step_id),
        )
        if step['state'] != 'PENDING':
            return {
                'dispatch': False,
                'state': step['state'],
                'operation_key': step['operation_key'],
            }
        if con.execute(
            "SELECT 1 FROM lifecycle_work_step_v1 WHERE change_id=? AND position<? AND state!='COMPLETED'",
            (change_id, step['position']),
        ).fetchone():
            raise ValueError('Previous work remains incomplete')
        con.execute(
            "UPDATE lifecycle_work_step_v1 SET state='RUNNING',actor=?,updated_at_utc=? WHERE change_id=? AND step_id=?",
            (actor, _now(), change_id, step_id),
        )
        _event(
            con,
            change_id,
            'WORK_STEP_CLAIMED',
            actor,
            {'step_id': step_id, 'operation_key': step['operation_key']},
        )
        return {'dispatch': True, 'state': 'RUNNING', 'operation_key': step['operation_key']}


def record_work_step(
    db_path: Path,
    change_id: str,
    step_id: str,
    *,
    actor: str,
    outcome: str,
    work_references: list[str],
) -> dict:
    """Store human/tool receipts; they are reported work, not independent verification."""
    if outcome not in {'COMPLETED', 'FAILED', 'INTERRUPTED', 'NOT_APPLIED'}:
        raise ValueError('Invalid work outcome')
    if not isinstance(work_references, list) or not work_references:
        raise ValueError('Work evidence required')
    for ref in work_references:
        _nonblank(ref, 'work reference')
    result = {'outcome': outcome, 'work_references': work_references}
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con, con:
        con.execute('BEGIN IMMEDIATE')
        ch = _one(con, 'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change_id,))
        _assert_integrity(con, ch, db_path)
        if ch['status'] != 'IMPLEMENTING' or actor != ch['implementation_actor']:
            raise ValueError('Assigned active implementer required')
        step = _one(
            con,
            'SELECT * FROM lifecycle_work_step_v1 WHERE change_id=? AND step_id=?',
            (change_id, step_id),
        )
        if step['state'] == outcome and step['result_json'] == _serialize(result):
            return result
        if step['state'] not in {'RUNNING', 'INTERRUPTED'}:
            raise ValueError('Work result conflicts with current step')
        state = 'PENDING' if outcome == 'NOT_APPLIED' else outcome
        con.execute(
            'UPDATE lifecycle_work_step_v1 SET state=?,result_json=?,updated_at_utc=? WHERE change_id=? AND step_id=?',
            (state, _serialize(result), _now(), change_id, step_id),
        )
        _event(con, change_id, 'WORK_STEP_REPORTED', actor, {'step_id': step_id, **result})
    return result


def _assert_work_complete(db_path: Path, change_id: str) -> None:
    progress = work_progress(db_path, change_id)
    if any(step['state'] != 'COMPLETED' for step in progress):
        raise ValueError('Work plan remains incomplete; completion cannot be reported')


def evaluate_structured_meeting_claim(
    db_path: Path, *, subject: str, dependency: str, claims_dependency: bool
) -> dict[str, Any]:
    """Rule check on structured, *untrusted* statement; no transcript NLP or approval.

    A false assertion is not an approved change. Pending approved changes are shown
    separately from current effective baseline; no statement is automatically rejected.
    """
    _nonblank(subject, 'subject')
    _nonblank(dependency, 'dependency')
    base = current_baseline(db_path)
    services = {s['id']: s for s in base['spec']['services']}
    if subject not in services or dependency not in services:
        return {
            'status': 'UNKNOWN_COMPONENT_REVIEW',
            'baseline_version': base['version'],
            'candidates': [],
            'automatic_task_or_approval': False,
        }
    actual = dependency in services[subject]['depends_on']
    with closing(connect(db_path)) as con:
        con.row_factory = sqlite3.Row
        pending = con.execute(
            '''SELECT change_id, status, intended_spec_json FROM lifecycle_change_v1
                   WHERE scope=? AND status IN ('APPROVED_LAB_ONLY','IMPLEMENTING',
                     'REPORTED_COMPLETE','HOLD_VERIFICATION','VERIFIED_LAB_ONLY')''',
            (SCOPE,),
        ).fetchall()
    possible = []
    for ch in pending:
        future = {s['id']: s for s in json.loads(ch['intended_spec_json'])['services']}
        if subject in future and dependency in future:
            possible.append(
                {
                    'change_id': ch['change_id'],
                    'status': ch['status'],
                    'future_claim': dependency in future[subject]['depends_on'],
                }
            )
    return {
        'status': (
            'CONFLICT_WITH_EFFECTIVE_BASELINE'
            if actual != claims_dependency
            else 'CONSISTENT_WITH_EFFECTIVE_BASELINE'
        ),
        'baseline_version': base['version'],
        'subject': subject,
        'dependency': dependency,
        'claim': claims_dependency,
        'baseline_fact': actual,
        'pending_changes': possible,
        'automatic_task_or_approval': False,
        'authority': 'UNTRUSTED_STRUCTURED_MEETING_CLAIM_ONLY',
    }
