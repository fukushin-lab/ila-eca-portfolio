"""ILA/ECA v4: passive intake of external change-workflow records.

Read-only for external sources. Never promotes a baseline, verifies an identity,
considers a JSON assertion a signature, or sends data externally. The sole
purpose is immutable-ish local intake with binding and reconciliation.
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import re
import sqlite3
import uuid

from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle.changes import (
    SCOPE,
    get_change,
    current_baseline,
    init_lifecycle,
)

SCHEMA = 'ila.external-work-record.v1'
KINDS = {
    'DESIGN_REVIEW',
    'IMPLEMENTATION_LOG',
    'COMPLETION_REPORT',
    'INDEPENDENT_VERIFICATION',
    'FINAL_ACCEPTANCE',
    'ROLLBACK_REPORT',
}
ROLE = {
    'DESIGN_REVIEW': 'REVIEWER',
    'IMPLEMENTATION_LOG': 'IMPLEMENTER',
    'COMPLETION_REPORT': 'IMPLEMENTER',
    'INDEPENDENT_VERIFICATION': 'VERIFIER',
    'FINAL_ACCEPTANCE': 'ACCEPTOR',
    'ROLLBACK_REPORT': 'IMPLEMENTER',
}
_SAFE_NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$')
_SHA = re.compile(r'^[0-9a-f]{64}$')
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_ATTACHMENT_BYTES = 1024 * 1024


def _now():
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _hash(data: bytes):
    return sha256(data).hexdigest()


def _read_exact(path: Path, maximum: int) -> bytes:
    if path.is_symlink():
        raise ValueError('Symlink sources not supported')
    with path.open('rb') as f:
        b = f.read(maximum + 1)
    if len(b) > maximum:
        raise ValueError('Evidence file exceeds maximum size')
    return b


def init_external(db_path: Path) -> None:
    init_lifecycle(db_path)
    with closing(connect(db_path)) as con, con:
        con.execute(
            '''CREATE TABLE IF NOT EXISTS external_record_v4 (
            record_id TEXT PRIMARY KEY, change_id TEXT NOT NULL,
            kind TEXT NOT NULL, source_system TEXT NOT NULL, external_id TEXT NOT NULL,
            actor_claim TEXT NOT NULL, role_claim TEXT NOT NULL,
            issued_at_utc TEXT NOT NULL, received_at_utc TEXT NOT NULL,
            base_version INTEGER NOT NULL, design_sha256 TEXT NOT NULL,
            claimed_result TEXT NOT NULL, manifest_sha256 TEXT NOT NULL,
            content_sha256 TEXT, content_bytes BLOB,
            details_json TEXT NOT NULL, linkage_status TEXT NOT NULL,
            UNIQUE(source_system, external_id)
        )'''
        )
        con.execute(
            '''CREATE TABLE IF NOT EXISTS meeting_claim_v4 (
            claim_id TEXT PRIMARY KEY, change_id TEXT,
            statement_json TEXT NOT NULL, assessment_json TEXT NOT NULL,
            assessed_at_utc TEXT NOT NULL
        )'''
        )


def _safe_import_path(root: Path, name: str) -> Path:
    if not isinstance(name, str) or not _SAFE_NAME.fullmatch(name) or name in ('.', '..'):
        raise ValueError('Only simple filenames in the inbound folder are permitted')
    folder = root.resolve(strict=True)
    path = root / name
    if path.is_symlink():
        raise ValueError('Symlink source denied')
    if not path.resolve(strict=True).is_relative_to(folder) or not path.is_file():
        raise ValueError('Input outside allowed inbox or missing')
    return path


def _parse_manifest(manifest: dict):
    required = {
        'schema',
        'change_id',
        'scope',
        'kind',
        'source_system',
        'external_id',
        'actor_claim',
        'role_claim',
        'issued_at_utc',
        'base_version',
        'design_sha256',
        'claimed_result',
        'details',
        'attachment_filename',
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ValueError('Unsupported work record schema/fields')
    if manifest['schema'] != SCHEMA or manifest['scope'] != SCOPE:
        raise ValueError('Unknown schema or cross-scope input')
    if manifest['kind'] not in KINDS or manifest['role_claim'] != ROLE[manifest['kind']]:
        raise ValueError('Evidence kind/role mismatch')
    for key in ('source_system', 'external_id', 'actor_claim', 'claimed_result'):
        v = manifest[key]
        if not isinstance(v, str) or not v.strip() or len(v) > 128:
            raise ValueError('Invalid ' + key)
    if (
        not isinstance(manifest['base_version'], int)
        or isinstance(manifest['base_version'], bool)
        or manifest['base_version'] < 1
    ):
        raise ValueError('Invalid baseline version')
    if not isinstance(manifest['design_sha256'], str) or not _SHA.fullmatch(
        manifest['design_sha256']
    ):
        raise ValueError('Invalid design digest')
    if (
        not isinstance(manifest['details'], dict)
        or len(_canonical(manifest['details']).encode('utf8')) > 16000
    ):
        raise ValueError('Record details invalid or excessive')
    attachment = manifest['attachment_filename']
    if attachment is not None and (
        not isinstance(attachment, str) or not _SAFE_NAME.fullmatch(attachment)
    ):
        raise ValueError('Invalid attachment filename')
    try:
        when = datetime.fromisoformat(manifest['issued_at_utc'])
    except (ValueError, TypeError) as e:
        raise ValueError('Invalid issued timestamp') from e
    if when.tzinfo is None or when.utcoffset() is None:
        raise ValueError('Issued time must contain timezone')
    if when > datetime.now(timezone.utc).astimezone(when.tzinfo):
        raise ValueError('Future issue date cannot be accepted')


def import_record(db_path: Path, inbox: Path, manifest_filename: str) -> dict:
    """Import record and optional file snapshot; assertions remain UNAUTHENTICATED.

    Never writes to inbox/source. Idempotent for identical manifest/content and
    fails closed on replay of a different content under the same external ID.
    """
    inbox = Path(inbox)
    manifest_path = _safe_import_path(inbox, manifest_filename)
    raw = _read_exact(manifest_path, _MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(raw.decode('utf-8-sig'))
    except (UnicodeError, json.JSONDecodeError) as e:
        raise ValueError('Invalid UTF-8 JSON manifest') from e
    _parse_manifest(manifest)
    init_external(db_path)
    ch = get_change(db_path, manifest['change_id'])
    if ch['scope'] != SCOPE:
        raise ValueError('Existing change is out of scope')
    doc = None
    if manifest['attachment_filename']:
        path = _safe_import_path(inbox, manifest['attachment_filename'])
        doc = _read_exact(path, _MAX_ATTACHMENT_BYTES)
    content_hash = _hash(doc) if doc is not None else None
    manifest_hash = _hash(_canonical(manifest).encode('utf-8'))
    reasons = []
    if ch['base_version'] != manifest['base_version']:
        reasons.append('record_base_version_mismatch')
    if ch['design_sha256'] is None:
        reasons.append('design_not_submitted')
    elif ch['design_sha256'] != manifest['design_sha256']:
        reasons.append('design_digest_mismatch')
    if current_baseline(db_path)['version'] != ch['base_version']:
        reasons.append('current_baseline_changed')
    if manifest['kind'] == 'DESIGN_REVIEW' and manifest['actor_claim'] == ch['design_author']:
        reasons.append('review_actor_same_as_author')
    if manifest['kind'] in ('INDEPENDENT_VERIFICATION', 'FINAL_ACCEPTANCE') and (
        manifest['actor_claim'] in (ch['implementation_actor'], ch['design_author'])
    ):
        reasons.append('actor_separation_claim_conflict')
    if manifest['kind'] == 'DESIGN_REVIEW' and doc is not None:
        # A locally attached copy of the design is useful for consistency,
        # but is NOT proof that the external source authorized it.
        text_bytes = ch['design_text'].encode('utf-8') if ch['design_text'] else b''
        if doc.replace(b'\r\n', b'\n') != text_bytes.replace(b'\r\n', b'\n'):
            reasons.append('reviewed_attachment_differs_from_design')
    if manifest['kind'] == 'COMPLETION_REPORT' and manifest['claimed_result'] != 'COMPLETE':
        reasons.append('not_a_completion_claim')
    if manifest['kind'] == 'ROLLBACK_REPORT':
        reasons.append('rollback_unverified')
    kind_status = 'CONFLICT_HOLD' if reasons else 'RECEIVED_UNAUTHENTICATED'
    with closing(connect(db_path)) as con:
        with con:
            con.execute('BEGIN IMMEDIATE')
            row = con.execute(
                '''SELECT record_id, manifest_sha256, content_sha256, linkage_status
                FROM external_record_v4 WHERE source_system=? AND external_id=?''',
                (manifest['source_system'], manifest['external_id']),
            ).fetchone()
            if row is not None:
                if row[1] != manifest_hash or row[2] != content_hash:
                    raise ValueError('Conflicting external ID replay: immutable evidence preserved')
                return {
                    'record_id': row[0],
                    'status': row[3],
                    'idempotent': True,
                    'no_authority_granted': True,
                }
            record_id = str(uuid.uuid4())
            con.execute(
                '''INSERT INTO external_record_v4 VALUES
                (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (
                    record_id,
                    manifest['change_id'],
                    manifest['kind'],
                    manifest['source_system'],
                    manifest['external_id'],
                    manifest['actor_claim'],
                    manifest['role_claim'],
                    manifest['issued_at_utc'],
                    _now(),
                    manifest['base_version'],
                    manifest['design_sha256'],
                    manifest['claimed_result'],
                    manifest_hash,
                    content_hash,
                    doc,
                    _canonical({'details': manifest['details'], 'reasons': reasons}),
                    kind_status,
                ),
            )
    return {
        'record_id': record_id,
        'status': kind_status,
        'idempotent': False,
        'reasons': reasons,
        'attachment_sha256': content_hash,
        'no_authority_granted': True,
    }


def record_summary(db_path: Path, change_id: str) -> dict:
    """Human review dossier. Complete paperwork is not authenticated approval."""
    init_external(db_path)
    ch = get_change(db_path, change_id)
    base = current_baseline(db_path)
    with closing(connect(db_path)) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            '''SELECT record_id,kind,source_system,external_id,actor_claim,
             role_claim,issued_at_utc,base_version,design_sha256,claimed_result,
             content_sha256,details_json,linkage_status
             FROM external_record_v4 WHERE change_id=? ORDER BY issued_at_utc,record_id''',
            (change_id,),
        ).fetchall()
    items = []
    for r in rows:
        item = dict(r)
        item['details'] = json.loads(item.pop('details_json'))
        items.append(item)
    required = (
        'DESIGN_REVIEW',
        'IMPLEMENTATION_LOG',
        'COMPLETION_REPORT',
        'INDEPENDENT_VERIFICATION',
        'FINAL_ACCEPTANCE',
    )
    kinds = {i['kind'] for i in items if i['linkage_status'] == 'RECEIVED_UNAUTHENTICATED'}
    missing = [x for x in required if x not in kinds]
    problems = sorted({reason for i in items for reason in i['details']['reasons']})
    for kind in (
        'DESIGN_REVIEW',
        'IMPLEMENTATION_LOG',
        'COMPLETION_REPORT',
        'INDEPENDENT_VERIFICATION',
        'FINAL_ACCEPTANCE',
    ):
        claimed = [
            r
            for r in items
            if r['kind'] == kind and r['linkage_status'] == 'RECEIVED_UNAUTHENTICATED'
        ]
        if len(claimed) > 1:
            problems.append(f'ambiguous_multiple_{kind.lower()}')

    def _actor(kind):
        a = [
            i
            for i in items
            if i['kind'] == kind and i['linkage_status'] == 'RECEIVED_UNAUTHENTICATED'
        ]
        return a[0]['actor_claim'] if len(a) == 1 else None

    author = ch['design_author']
    implementer = _actor('COMPLETION_REPORT') or _actor('IMPLEMENTATION_LOG')
    if (
        _actor('IMPLEMENTATION_LOG')
        and _actor('COMPLETION_REPORT')
        and _actor('IMPLEMENTATION_LOG') != _actor('COMPLETION_REPORT')
    ):
        problems.append('implementation_actor_claim_conflict')
    for label, who in [
        ('reviewer', _actor('DESIGN_REVIEW')),
        ('verifier', _actor('INDEPENDENT_VERIFICATION')),
        ('acceptor', _actor('FINAL_ACCEPTANCE')),
    ]:
        if who and (
            (label == 'reviewer' and who == author)
            or (label in ('verifier', 'acceptor') and who in (author, implementer))
        ):
            problems.append(f'{label}_claimed_role_separation_failed')
    chronology = {
        k: [
            i['issued_at_utc']
            for i in items
            if i['kind'] == k and i['linkage_status'] == 'RECEIVED_UNAUTHENTICATED'
        ]
        for k in required
    }
    if not missing and all(len(chronology[k]) == 1 for k in required):
        times = [
            datetime.fromisoformat(chronology[k][0]).astimezone(timezone.utc) for k in required
        ]
        if times != sorted(times):
            problems.append('claimed_workflow_order_conflict')
    if ch['base_version'] != base['version']:
        problems.append('baseline_head_version_advanced')
    return {
        'change_id': change_id,
        'status': (
            'HOLD_CONFLICT_REVIEW'
            if problems
            else ('INCOMPLETE_RECORDS' if missing else 'RECORDS_ALIGNED_AUTHENTICATION_REQUIRED')
        ),
        'record_count': len(items),
        'missing_record_types': missing,
        'problems': sorted(set(problems)),
        'records': items,
        'baseline_current_version': base['version'],
        'change_base_version': ch['base_version'],
        'change_lifecycle_state': ch['status'],
        'design_sha256': ch['design_sha256'],
        'real_approval_verified': False,
        'real_completion_verified': False,
        'baseline_updated': False,
        'read_only_external_systems': True,
        'next_required': 'Integrate authoritative ITSM identity/approval and independent verification connectors',
    }
