"""Domain-local shared rendering and draft artifact registry. No model/network/actions.

A document record is not a Baseline, an identity signature, technical approval,
or permission to transfer data. Each domain uses its own connection and files.
"""

from __future__ import annotations
import hashlib
import json
import re
import sqlite3
from string import Template
from pathlib import Path

SCHEMA = 'ila.eca.design-document.v1'
AUTHORITY = 'DRAFT_UNAPPROVED_NOT_EFFECTIVE_BASELINE'
TOKEN = re.compile(r'[A-Za-z0-9_.:-]{1,120}')
HEX = re.compile(r'[0-9a-f]{64}')


def canonical_json(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False
    )


def digest(data: bytes):
    return hashlib.sha256(data).hexdigest()


def data_digest(value):
    return digest(canonical_json(value).encode('utf-8'))


def render_template(
    template: bytes, fields: dict, *, template_version: str, provenance: dict | None = None
):
    """The legacy A renderer's byte, template and provenance contract, reused by G."""
    if not isinstance(template, bytes) or not TOKEN.fullmatch(template_version):
        raise ValueError('DOCUMENT_TEMPLATE_INVALID')
    content = (
        Template(template.decode('utf-8')).substitute(fields).replace('\r\n', '\n').encode('utf-8')
    )
    metadata = {
        **(provenance or {}),
        'template_version': template_version,
        'template_sha256': digest(template),
        'document_sha256': digest(content),
        'document_format': 'text/markdown; charset=utf-8',
        'authority': AUTHORITY,
    }
    return content, metadata


def init_registry(con: sqlite3.Connection):
    # execute, not executescript: do not implicitly commit a caller's transaction.
    con.execute(
        '''CREATE TABLE IF NOT EXISTS design_document_artifact_v1 (
        domain_id TEXT NOT NULL,design_id TEXT NOT NULL,revision INTEGER NOT NULL,
        material_sha256 TEXT NOT NULL,document_sha256 TEXT NOT NULL,
        record_json TEXT NOT NULL,relative_path TEXT NOT NULL,
        PRIMARY KEY(domain_id,design_id,revision))'''
    )


def validate_record(record: dict, *, content: bytes, structured_data=None):
    keys = {
        'schema',
        'domain_id',
        'design_id',
        'revision',
        'document_kind',
        'template_version',
        'template_sha256',
        'document_sha256',
        'structured_data_sha256',
        'baseline_ref',
        'change_request_ref',
        'evidence_assessment',
        'review_state',
        'authority',
        'approval_granted',
        'baseline_updated',
        'artifact_sha256',
    }
    if type(record) is not dict or set(record) != keys:
        raise ValueError('DOCUMENT_RECORD_SCHEMA_INVALID')
    if not (
        record['schema'] == SCHEMA
        and type(record['revision']) is int
        and record['revision'] >= 1
        and all(
            type(record[k]) is str and TOKEN.fullmatch(record[k])
            for k in ('domain_id', 'design_id', 'document_kind', 'template_version')
        )
        and all(
            type(record[k]) is str and HEX.fullmatch(record[k])
            for k in (
                'template_sha256',
                'document_sha256',
                'structured_data_sha256',
                'artifact_sha256',
            )
        )
        and record['review_state'] == 'AWAITING_REVIEW'
        and record['authority'] == AUTHORITY
        and record['approval_granted'] is False
        and record['baseline_updated'] is False
        and (record['baseline_ref'] is None or type(record['baseline_ref']) is dict)
        and (record['change_request_ref'] is None or type(record['change_request_ref']) is str)
        and type(record['evidence_assessment']) is str
        and 1 <= len(record['evidence_assessment']) <= 100
    ):
        raise ValueError('DOCUMENT_RECORD_METADATA_INVALID')
    if record['document_sha256'] != digest(content):
        raise ValueError('DOCUMENT_BYTES_CHANGED')
    if structured_data is not None and record['structured_data_sha256'] != data_digest(
        structured_data
    ):
        raise ValueError('DOCUMENT_STRUCTURED_DATA_CHANGED')
    if record['artifact_sha256'] != data_digest(
        {k: v for k, v in record.items() if k != 'artifact_sha256'}
    ):
        raise ValueError('DOCUMENT_RECORD_DIGEST_CHANGED')
    return record


def register_document(
    con: sqlite3.Connection,
    *,
    domain_id: str,
    design_id: str,
    document_kind: str,
    content: bytes,
    structured_data,
    render_metadata: dict,
    relative_path: str,
    baseline_ref=None,
    change_request_ref=None,
    evidence_assessment='NOT_ASSESSED',
):
    """Append a draft revision, or reuse the identical latest revision.

    The caller owns the local DB, directory permissions and transaction. Keeping
    material revision order serialized requires BEGIN IMMEDIATE at the boundary.
    """
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or relative_path.startswith(('/', '\\'))
        or '\\' in relative_path
        or any(p in ('', '..', '.') for p in relative_path.split('/'))
    ):
        raise ValueError('DOCUMENT_RELATIVE_PATH_INVALID')
    if not con.in_transaction:
        raise ValueError('DOCUMENT_REGISTRY_TRANSACTION_REQUIRED')
    init_registry(con)
    material = {
        'schema': SCHEMA,
        'domain_id': domain_id,
        'design_id': design_id,
        'document_kind': document_kind,
        'template_version': render_metadata['template_version'],
        'template_sha256': render_metadata['template_sha256'],
        'document_sha256': digest(content),
        'structured_data_sha256': data_digest(structured_data),
        'baseline_ref': baseline_ref,
        'change_request_ref': change_request_ref,
        'evidence_assessment': evidence_assessment,
        'review_state': 'AWAITING_REVIEW',
        'authority': AUTHORITY,
        'approval_granted': False,
        'baseline_updated': False,
    }
    if render_metadata['document_sha256'] != material['document_sha256']:
        raise ValueError('DOCUMENT_RENDER_METADATA_CHANGED')
    material_sha = data_digest(material)
    old = con.execute(
        '''SELECT revision,material_sha256,record_json,relative_path FROM design_document_artifact_v1
        WHERE domain_id=? AND design_id=? ORDER BY revision DESC LIMIT 1''',
        (domain_id, design_id),
    ).fetchone()
    if old and old[1] == material_sha:
        record = json.loads(old[2])
        validate_record(record, content=content, structured_data=structured_data)
        if old[3] != relative_path:
            raise ValueError('DOCUMENT_LOCATION_CHANGED_WITHOUT_REVISION')
        return record
    revision = old[0] + 1 if old else 1
    record = {**material, 'revision': revision}
    record['artifact_sha256'] = data_digest(record)
    validate_record(record, content=content, structured_data=structured_data)
    con.execute(
        'INSERT INTO design_document_artifact_v1 VALUES(?,?,?,?,?,?,?)',
        (
            domain_id,
            design_id,
            revision,
            material_sha,
            record['document_sha256'],
            canonical_json(record),
            relative_path,
        ),
    )
    if con.execute("SELECT 1 FROM sqlite_master WHERE name='lifecycle_change_v1'").fetchone():
        if con.execute(
            "SELECT 1 FROM lifecycle_change_v1 WHERE status IN ('APPROVED','APPROVED_TEST_ONLY') LIMIT 1"
        ).fetchone():
            from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.approval import invalidate_document

            previous_factory = con.row_factory
            try:
                invalidate_document(con, domain_id, design_id, revision)
            finally:
                con.row_factory = previous_factory
    return record


def document_paths(db, relative):
    root = Path(db).resolve().parent
    path = (root / relative).resolve()
    if (
        not path.is_relative_to(root)
        or Path(relative).is_absolute()
        or '..' in Path(relative).parts
    ):
        raise ValueError('REVIEW_ARTIFACT_PATH_INVALID')
    return path, path.with_suffix('.json')



def valid_document_id(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r'[A-Za-z0-9_.:-]{1,120}', value)
        and value not in {'.', '..'}
    )



def verify_attached_document_from_connection(con, db, design_id, revision, scope):
    """Dispatch the same immutable annex binding for source reviews and AI designs."""
    from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle.changes import SCOPE

    registry_scope = scope
    row = con.execute(
        'SELECT record_json FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? AND revision=?',
        (scope, design_id, revision),
    ).fetchone()
    # Incident records use Phase1's lab namespace. Only the existing isolated
    # LAB lifecycle may attach that exact record across its legacy namespace.
    if row is None and scope == SCOPE:
        incident = con.execute(
            'SELECT record_json FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? AND revision=?',
            ('lab', design_id, revision),
        ).fetchone()
        if incident is not None and json.loads(incident[0]).get('document_kind') in {
            'INCIDENT_INVESTIGATION',
            'AWS_LOCAL_DESIGN',
        }:
            row = incident
            registry_scope = 'lab'
    if row is None:
        if scope == SCOPE:
            from ILA_ECA_REAL_DISCOVERY_LAB.design.route_documents import verify_route_document

            return verify_route_document(con, db, design_id, revision, scope)
        raise ValueError('ATTACHED_DOCUMENT_NOT_FOUND')
    record = json.loads(row[0])
    kind = record.get('document_kind')
    if kind == 'INCIDENT_INVESTIGATION':
        if (
            scope not in {'lab', SCOPE}
            or registry_scope != 'lab'
            or record.get('domain_id') != 'lab'
        ):
            raise PermissionError('INCIDENT_REPORT_SCOPE_MISMATCH')
        from ILA_ECA_REAL_DISCOVERY_LAB.incident.artifacts import verify_report

        return verify_report(con, db, design_id, revision)
    if kind == 'AWS_LOCAL_DESIGN':
        from ILA_ECA_REAL_DISCOVERY_LAB.design.aws import verify

        if scope not in {'lab', SCOPE} or registry_scope != 'lab':
            raise PermissionError('AWS_DESIGN_REVIEW_SCOPE_MISMATCH')
        return verify(con, db, design_id, revision, registry_scope)
    if kind == 'FULL_ROUTE_DRAFT':
        from ILA_ECA_REAL_DISCOVERY_LAB.design.route_documents import verify_route_document

        return verify_route_document(con, db, design_id, revision, scope)
    if kind == 'LLM_NON_AWS_DESIGN':
        from ILA_ECA_REAL_DISCOVERY_LAB.design.non_aws import verify_proposal_from_connection

        return verify_proposal_from_connection(con, db, design_id, revision, scope)
    if kind == 'MEETING_AUDIO_REVIEW':
        from ILA_ECA_REAL_DISCOVERY_LAB.meeting.review import verify_audio_review

        return verify_audio_review(con, db, design_id, revision, scope)
    if kind == 'RECEIVED_DOCUMENT_REVIEW':
        from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.review import verify_review_from_connection

        return verify_review_from_connection(con, db, design_id, revision, scope)
    raise ValueError('ATTACHED_DOCUMENT_KIND_UNSUPPORTED')



def parse_json(raw, *, duplicate_error, nonfinite_error):
    """One strict JSON policy; each boundary retains its existing reason codes."""

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(duplicate_error)
            value[key] = item
        return value

    def invalid(_):
        raise ValueError(nonfinite_error)

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def validate_model_shape(value, rule, *, error_prefix):
    """The shared A/D/E/H structural subset; business evidence checks stay local."""
    kind = rule["type"]
    if kind == "object":
        if type(value) is not dict or set(value) != set(rule["required"]):
            raise ValueError(error_prefix + "_FIELDS_INVALID")
        for key, child_rule in rule["properties"].items():
            validate_model_shape(value[key], child_rule, error_prefix=error_prefix)
    elif kind == "array":
        if type(value) is not list or not rule.get("minItems", 0) <= len(value) <= rule.get(
            "maxItems", float("inf")
        ):
            raise ValueError(error_prefix + "_ARRAY_INVALID")
        for index, child in enumerate(value):
            child_rule = rule["items"][index] if isinstance(rule["items"], list) else rule["items"]
            validate_model_shape(child, child_rule, error_prefix=error_prefix)
    elif kind == "string":
        if type(value) is not str or not rule.get("minLength", 0) <= len(value) <= rule.get(
            "maxLength", float("inf")
        ):
            raise ValueError(error_prefix + "_TEXT_INVALID")
    elif kind == "boolean":
        if type(value) is not bool:
            raise ValueError(error_prefix + "_BOOLEAN_INVALID")
    if "enum" in rule and value not in rule["enum"]:
        raise ValueError(error_prefix + "_ENUM_INVALID")
