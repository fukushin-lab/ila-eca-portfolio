"""Small integration receipts in the existing audit DB; never a new case service."""

from contextlib import closing
from pathlib import Path
from datetime import datetime, timezone
import json
import sqlite3
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, init_db
from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import Principal, timestamp, _SENSITIVE
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import _save


def safe(value):
    if _SENSITIVE.search(canonical_json(value)):
        raise PermissionError('SERVICE_SECRET_MATERIAL_DENIED')
    return value


def authorize(config, operation, case_id, *, payload_sha256=None):
    if not isinstance(config, dict):
        raise PermissionError('CONNECTION_CONFIG_TYPE_INVALID')
    allowed = {
        'schema',
        'actor',
        'scope',
        'approved_by',
        'expires_at',
        'allowed_operations',
        'allowed_case_ids',
        'classification',
        'external_send_permitted',
        'allowed_export_sha256',
        'google',
        'gitlab',
        'http_options',
    }
    if set(config) - allowed:
        raise PermissionError('CONNECTION_CONFIG_UNKNOWN_OR_CREDENTIAL_FIELD')
    for field in ('allowed_operations', 'allowed_case_ids', 'allowed_export_sha256'):
        if not isinstance(config.get(field, []), list) or any(
            type(x) is not str or not x for x in config.get(field, [])
        ):
            raise PermissionError('CONNECTION_ALLOWLIST_TYPE_INVALID')
    for field in ('google', 'gitlab', 'http_options'):
        if not isinstance(config.get(field, {}), dict):
            raise PermissionError('CONNECTION_CONFIG_TYPE_INVALID')
    calendars = config.get('google', {}).get('calendar_ids', [])
    if not isinstance(calendars, list) or any(type(x) is not str or not x for x in calendars):
        raise PermissionError('CONNECTION_ALLOWLIST_TYPE_INVALID')
    if set(config.get('google', {})) - {'calendar_ids', 'mcp'} or set(config.get('gitlab', {})) - {
        'base_url',
        'project_id',
        'target_branch',
        'required_rule_ids',
        'reviewer_identities',
        'review_only',
        'mcp',
    }:
        raise PermissionError('CONNECTION_CONFIG_UNKNOWN_OR_CREDENTIAL_FIELD')
    from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.mcp import validate_settings

    for provider in ('google', 'gitlab'):
        validate_settings(config.get(provider, {}).get('mcp', {}), provider)
    if type(config.get('gitlab', {}).get('review_only', False)) is not bool:
        raise PermissionError('GITLAB_REVIEW_ONLY_FLAG_TYPE_INVALID')
    Principal(config.get('actor', ''), scope=config.get('scope')).check()
    if (
        config.get('schema') != 'ila.eca.collaboration-connection.v1'
        or config.get('approved_by', '').strip() == ''
        or timestamp(config['expires_at']) <= datetime.now(timezone.utc)
        or operation not in config.get('allowed_operations', [])
        or case_id not in config.get('allowed_case_ids', [])
    ):
        raise PermissionError('SERVICE_SCOPE_PERMISSION_OR_EXPIRY_DENIED')
    if operation == 'gitlab_submit':
        if (
            config.get('classification') not in {'SYNTHETIC_ONLINE', 'OPERATOR_CARRIED_ONLINE'}
            or config.get('external_send_permitted') is not True
            or payload_sha256 not in config.get('allowed_export_sha256', [])
        ):
            raise PermissionError('SERVICE_EXPORT_PACKET_NOT_AUTHORIZED')


class Store:
    def __init__(self, db):
        self.db = Path(db)
        init_db(db)
        with self.open() as c, c:
            c.execute(
                'CREATE TABLE IF NOT EXISTS collaboration_link_v1 (case_id TEXT NOT NULL, kind TEXT NOT NULL, external_key TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(case_id,kind,external_key))'
            )
            c.execute(
                'CREATE TABLE IF NOT EXISTS collaboration_material_v1 (receipt_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL, result_json TEXT)'
            )
            c.execute(
                'CREATE TABLE IF NOT EXISTS collaboration_submission_v1 (submission_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, state TEXT NOT NULL, payload_json TEXT NOT NULL)'
            )

    def open(self):
        c = connect(self.db)
        c.row_factory = sqlite3.Row
        return closing(c)

    def case(self, case_id):
        # Only attach to an already-owned request or change; never fabricate a case.
        with self.open() as c:
            for table, key in [
                ('phase1_request_v1', 'request_id'),
                ('lifecycle_change_v1', 'change_id'),
            ]:
                if not c.execute('SELECT 1 FROM sqlite_master WHERE name=?', (table,)).fetchone():
                    continue
                r = c.execute(
                    'SELECT * FROM ' + table + ' WHERE ' + key + '=?', (case_id,)
                ).fetchone()
                if r:
                    if r['scope'] not in {'lab', 'ila-discovery-lab'}:
                        raise PermissionError('SERVICE_CASE_SCOPE_DENIED')
                    return dict(r)
        raise ValueError('EXISTING_CASE_REQUIRED')

    def link(self, case_id, kind, key, payload):
        self.case(case_id)
        safe(payload)
        with self.open() as c, c:
            c.execute(
                'INSERT INTO collaboration_link_v1 VALUES(?,?,?,?) ON CONFLICT(case_id,kind,external_key) DO UPDATE SET payload_json=excluded.payload_json',
                (case_id, kind, key, canonical_json(payload)),
            )

    def get_link(self, case_id, kind, key):
        self.case(case_id)
        with self.open() as c:
            r = c.execute(
                'SELECT payload_json FROM collaboration_link_v1 WHERE case_id=? AND kind=? AND external_key=?',
                (case_id, kind, key),
            ).fetchone()
        if not r:
            raise ValueError('SERVICE_LINK_NOT_FOUND')
        return json.loads(r[0])

    def evidence(self, case_id, kind, payload):
        self.case(case_id)
        safe(payload)
        return _save(self.db, 'lab', 'collaboration://' + case_id, kind, payload)

    def material(self, case_id, payload, raw, suffix):
        self.case(case_id)
        safe(payload)
        receipt = data_digest(
            {
                'case_id': case_id,
                'source': payload['source'],
                'version': payload['version'],
                'sha256': payload['sha256'],
            }
        )
        folder = self.db.parent / 'collaboration_materials'
        folder.mkdir(exist_ok=True)
        path = folder / (receipt + suffix)
        if path.is_symlink():
            raise PermissionError('MATERIAL_PATH_DENIED')
        if path.exists() and path.read_bytes() != raw:
            raise ValueError('MATERIAL_CONTENT_CHANGED')
        if not path.exists():
            with path.open('xb') as f:
                f.write(raw)
        value = {**payload, 'path': str(path), 'receipt_id': receipt, 'case_id': case_id}
        with self.open() as c, c:
            c.execute(
                'INSERT OR IGNORE INTO collaboration_material_v1 VALUES(?,?,?,\'READY\',NULL)',
                (receipt, case_id, canonical_json(value)),
            )
            row = c.execute(
                'SELECT payload_json,state,result_json FROM collaboration_material_v1 WHERE receipt_id=?',
                (receipt,),
            ).fetchone()
            original = json.loads(row[0])
            if any(
                original[k] != value[k] for k in ('source', 'version', 'sha256', 'kind', 'case_id')
            ):
                raise ValueError('MATERIAL_RECEIPT_CHANGED')
        from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import reserve

        binding = {k: v for k, v in original.items() if k != 'receipt_evidence_id'}
        eid, _ = reserve(
            self.db,
            'lab',
            'collaboration-material://' + receipt,
            'collaboration_material_receipt_v1',
            binding,
        )
        original['receipt_evidence_id'] = eid
        with self.open() as c, c:
            c.execute(
                'UPDATE collaboration_material_v1 SET payload_json=? WHERE receipt_id=?',
                (canonical_json(original), receipt),
            )
        return {**original, 'state': row[1], 'result': json.loads(row[2]) if row[2] else None}

    def receipt(self, rid):
        with self.open() as c:
            r = c.execute(
                'SELECT * FROM collaboration_material_v1 WHERE receipt_id=?', (rid,)
            ).fetchone()
        if not r:
            raise ValueError('RECEIPT_NOT_FOUND')
        payload = json.loads(r['payload_json'])
        from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import load_evidence

        if not payload.get('receipt_evidence_id'):
            raise ValueError('MATERIAL_METADATA_PENDING_RECONCILE_IMPORT')
        _, bound = load_evidence(self.db, payload['receipt_evidence_id'], 'lab')
        if bound != {k: v for k, v in payload.items() if k != 'receipt_evidence_id'}:
            raise ValueError('MATERIAL_RECEIPT_CHANGED')
        return {
            **payload,
            'state': r['state'],
            'result': json.loads(r['result_json']) if r['result_json'] else None,
        }

    def submission(self, sid):
        with self.open() as c:
            r = c.execute(
                'SELECT * FROM collaboration_submission_v1 WHERE submission_id=?', (sid,)
            ).fetchone()
        if not r:
            raise ValueError('SUBMISSION_NOT_FOUND')
        return {**json.loads(r['payload_json']), 'state': r['state']}

    def update(self, sid, old_state, new_state, payload):
        safe(payload)
        with self.open() as c, c:
            n = c.execute(
                'UPDATE collaboration_submission_v1 SET state=?,payload_json=? WHERE submission_id=? AND state=?',
                (
                    new_state,
                    canonical_json({k: v for k, v in payload.items() if k != 'state'}),
                    sid,
                    old_state,
                ),
            ).rowcount
            if n != 1:
                raise ValueError('SUBMISSION_CONCURRENT_UPDATE_NO_SEND')

    def status(self, case_id):
        self.case(case_id)
        with self.open() as c:
            return {
                'case_id': case_id,
                'links': [
                    {
                        **json.loads(r['payload_json']),
                        'link_kind': r['kind'],
                        'link_key': r['external_key'],
                    }
                    for r in c.execute(
                        'SELECT * FROM collaboration_link_v1 WHERE case_id=?', (case_id,)
                    )
                ],
                'materials': [
                    self.receipt(r[0])
                    for r in c.execute(
                        'SELECT receipt_id FROM collaboration_material_v1 WHERE case_id=?',
                        (case_id,),
                    )
                ],
                'reviews': [
                    self.submission(r[0])
                    for r in c.execute(
                        'SELECT submission_id FROM collaboration_submission_v1 WHERE case_id=?',
                        (case_id,),
                    )
                ],
                'approval_granted': False,
                'baseline_updated': False,
            }
