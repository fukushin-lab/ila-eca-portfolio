"""Existing case registration and evidence boundary; no legacy scenario executor."""

from __future__ import annotations
from contextlib import closing
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
import json
import re
import sqlite3
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, save_evidence

TYPES = {
    'DESIGN',
    'CHANGE',
    'INCIDENT',
    'QUESTION',
    'MEETING_ASSERTION',
    'NO_ACTION',
    'CLOUD_LIFT',
    'SECURITY_EVENT',
}


EFFECTS = {'ADVISE', 'READ', 'LAB_CHANGE', 'AWS_APPLY', 'PROD_WRITE', 'CLOUD_WRITE', 'ISOLATE'}


SAFE_ACTIONS = {'READ', 'ADVISE', 'LAB_CHANGE_EXECUTE'}


CANON = lambda value: json.dumps(
    value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), default=str
)


_DIGEST = lambda value: sha256(CANON(value).encode('utf-8')).hexdigest()


_SENSITIVE = re.compile(
    r'(?i)(?:AKIA[0-9A-Z]{16}|-----BEGIN\s+(?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*\S+)'
)


_ID = re.compile(r'^[\w.-]{3,100}$', re.ASCII)


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def timestamp(x: str) -> datetime:
    if not isinstance(x, str):
        raise ValueError('Timestamp is not text')
    t = datetime.fromisoformat(x.replace('Z', '+00:00'))
    if t.tzinfo is None:
        raise ValueError('Timezone required')
    return t.astimezone(timezone.utc)


@dataclass(frozen=True)
class Principal:
    ref: str
    scope: str = 'lab'
    actions: tuple[str, ...] = ('READ', 'ADVISE')
    environment: str = 'ISOLATED_LAB'
    clearance: str = 'LAB_SYNTHETIC'

    def check(self) -> None:
        if not isinstance(self.ref, str) or not _ID.fullmatch(self.ref):
            raise ValueError('Invalid requester identity')
        if self.environment != 'ISOLATED_LAB' or self.scope != 'lab':
            raise PermissionError('UNAUTHORIZED_SCOPE_OR_ENVIRONMENT')
        if not isinstance(self.actions, (list, tuple)) or any(
            a not in SAFE_ACTIONS for a in self.actions
        ):
            raise PermissionError('PRIVILEGE_ESCALATION_DENIED')
        if self.clearance != 'LAB_SYNTHETIC':
            raise PermissionError('CLASSIFICATION_NOT_AUTHORIZED')


@dataclass(frozen=True)
class Request:
    request_id: str
    request_type: str
    subject_id: str
    scope: str
    received_at: str
    requester_ref: str
    untrusted_text: str
    requested_effect: str
    correlation_id: str
    details: dict[str, Any] = field(default_factory=dict)

    def check(self) -> None:
        if not all(
            isinstance(getattr(self, k), str) and _ID.fullmatch(getattr(self, k))
            for k in ('request_id', 'subject_id', 'requester_ref', 'correlation_id')
        ):
            raise ValueError('Invalid request or subject identifiers')
        if self.request_type not in TYPES or self.requested_effect not in EFFECTS:
            raise ValueError('Unrecognized request type or effect')
        if self.scope != 'lab':
            raise PermissionError('CROSS_SCOPE_REQUEST_DENIED')
        if not isinstance(self.untrusted_text, str) or len(self.untrusted_text) > 4096:
            raise ValueError('Untrusted text size invalid')
        if not isinstance(self.details, dict) or len(CANON(self.details)) > 16000:
            raise ValueError('Details malformed or too large')
        if timestamp(self.received_at) > datetime.now(timezone.utc):
            raise ValueError('Request received in the future')


class UnifiedPhase1:
    def __init__(self, db):
        from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle.changes import init_lifecycle

        self.db = Path(db)
        init_lifecycle(self.db)
        self._schema()

    def _schema(self) -> None:
        """Add *extensions* to existing Stage02 audit DB, anchored to original IDs."""
        with closing(connect(self.db)) as con, con:
            con.executescript(
                '''
              CREATE TABLE IF NOT EXISTS phase1_request_v1 (
                request_id TEXT PRIMARY KEY, request_type TEXT NOT NULL, subject_id TEXT NOT NULL,
                scope TEXT NOT NULL, received_at TEXT NOT NULL, requester_ref TEXT NOT NULL,
                text_sha256 TEXT NOT NULL, requested_effect TEXT NOT NULL,
                correlation_id TEXT NOT NULL, details_sha256 TEXT NOT NULL, payload_sha256 TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS phase1_evidence_metadata_v1 (
                evidence_id TEXT PRIMARY KEY REFERENCES evidence(evidence_id),
                origin TEXT NOT NULL, source_type TEXT NOT NULL, subject_id TEXT NOT NULL,
                scope TEXT NOT NULL, known_at TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
                trust_status TEXT NOT NULL, classification TEXT NOT NULL,
                envelope_sha256 TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS phase1_decision_ext_v1 (
                decision_id TEXT PRIMARY KEY REFERENCES decision_log(decision_id),
                request_id TEXT NOT NULL REFERENCES phase1_request_v1(request_id),
                disposition TEXT NOT NULL, reasons_json TEXT NOT NULL, policy_version TEXT NOT NULL,
                risk TEXT NOT NULL, missing_json TEXT NOT NULL, authority_status TEXT NOT NULL,
                subject_scope TEXT NOT NULL, recheck_json TEXT NOT NULL, target_adapter TEXT NOT NULL,
                proposal_json TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS phase1_action_v1 (
                action_id TEXT PRIMARY KEY, decision_id TEXT UNIQUE NOT NULL REFERENCES decision_log(decision_id),
                execution_mode TEXT NOT NULL, executor_ref TEXT NOT NULL, adapter TEXT NOT NULL,
                approved_design_sha256 TEXT, started_at TEXT NOT NULL, ended_at TEXT NOT NULL,
                result_status TEXT NOT NULL, before_json TEXT NOT NULL, after_json TEXT NOT NULL,
                command_refs_json TEXT NOT NULL, independent_verify_ref TEXT,
                result_json TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS phase1_execution_claim_v11 (
                change_id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE
                    REFERENCES phase1_request_v1(request_id),
                scope TEXT NOT NULL, subject_id TEXT NOT NULL,
                status TEXT NOT NULL, reserved_at TEXT NOT NULL, finished_at TEXT);
              CREATE UNIQUE INDEX IF NOT EXISTS phase1_one_active_subject_v11
                ON phase1_execution_claim_v11(scope,subject_id) WHERE status='RESERVED';
              CREATE TABLE IF NOT EXISTS phase1_followup_v11 (
                receipt_id TEXT PRIMARY KEY, request_id TEXT NOT NULL REFERENCES phase1_request_v1(request_id),
                decision_id TEXT NOT NULL REFERENCES phase1_decision_ext_v1(decision_id),
                scope TEXT NOT NULL, subject_id TEXT NOT NULL,
                source_system TEXT NOT NULL, external_event_id TEXT NOT NULL,
                execution_mode TEXT NOT NULL, actor_claim TEXT NOT NULL,
                claimed_status TEXT NOT NULL, observed_at TEXT NOT NULL,
                received_at TEXT NOT NULL, content_sha256 TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL, evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                authority_status TEXT NOT NULL,
                UNIQUE(source_system,external_event_id));
              CREATE INDEX IF NOT EXISTS phase1_followup_request_idx_v11 ON phase1_followup_v11(request_id);
              CREATE INDEX IF NOT EXISTS phase1_subject_idx ON phase1_request_v1(subject_id,scope);
              CREATE INDEX IF NOT EXISTS phase1_decision_request_idx ON phase1_decision_ext_v1(request_id);
            '''
            )

    def register_only(self, req: Request, principal: Principal) -> dict:
        """Explicit intake in the existing registry; no decision, model or action."""
        req.check()
        principal.check()
        if principal.scope != req.scope or principal.ref != req.requester_ref:
            raise PermissionError('REQUESTER_SCOPE_OR_IDENTITY_MISMATCH')
        if _SENSITIVE.search(CANON(asdict(req))):
            raise PermissionError('UNTRUSTED_TEXT_CONTAINS_SECRET')
        with closing(connect(self.db)) as con:
            old = con.execute(
                'SELECT payload_sha256 FROM phase1_request_v1 WHERE request_id=?', (req.request_id,)
            ).fetchone()
        if old:
            if old[0] != _DIGEST(asdict(req)):
                raise PermissionError('REQUEST_ID_REPLAY_WITH_CHANGED_PAYLOAD')
        else:
            self._audit(req)
        return {'request_id': req.request_id, 'state': 'RECEIVED_NOT_EXECUTED'}

    def _audit(self, req: Request) -> None:
        # Never persist raw meeting text, untrusted instructions, or credentials in intake.
        with closing(connect(self.db)) as con, con:
            con.execute(
                '''INSERT INTO phase1_request_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                (
                    req.request_id,
                    req.request_type,
                    req.subject_id,
                    req.scope,
                    req.received_at,
                    req.requester_ref,
                    sha256(req.untrusted_text.encode()).hexdigest(),
                    req.requested_effect,
                    req.correlation_id,
                    _DIGEST(req.details),
                    _DIGEST(asdict(req)),
                ),
            )

    def _metadata(
        self,
        evidence_id: str,
        subject: str,
        *,
        origin: str,
        trust: str,
        known_at: str | None = None,
    ) -> dict:
        """Pin original evidence payload hash and source; old Stage04 rows remain authoritative."""
        with closing(connect(self.db)) as con:
            con.row_factory = sqlite3.Row
            row = con.execute(
                'SELECT * FROM evidence WHERE evidence_id=?', (evidence_id,)
            ).fetchone()
            if row is None or row['scope'] != 'lab':
                raise PermissionError('EVIDENCE_SCOPE_MISMATCH_OR_ABSENT')
            payload = json.loads(row['payload_json'])
            digest = _DIGEST(payload)
            envelope_digest = _DIGEST(
                {
                    'evidence_id': evidence_id,
                    'observed_at': row['observed_at'],
                    'adapter': row['adapter'],
                    'source': row['source'],
                    'scope': row['scope'],
                    'payload': payload,
                }
            )
            if _SENSITIVE.search(CANON(payload)):
                raise PermissionError('SENSITIVE_EVIDENCE_REQUIRES_REDACTION')
            existing = con.execute(
                'SELECT * FROM phase1_evidence_metadata_v1 WHERE evidence_id=?', (evidence_id,)
            ).fetchone()
            if existing:
                if (
                    existing['payload_sha256'] != digest
                    or existing['scope'] != row['scope']
                    or existing['envelope_sha256'] != envelope_digest
                ):
                    raise PermissionError('EVIDENCE_TAMPER_DETECTED')
                return dict(existing)
        known_at = known_at or utc()
        if timestamp(row['observed_at']) > timestamp(known_at):
            raise ValueError('Known-at predates observed-at')
        with closing(connect(self.db)) as con, con:
            con.execute(
                '''INSERT INTO phase1_evidence_metadata_v1 VALUES(?,?,?,?,?,?,?,?,?,?)''',
                (
                    evidence_id,
                    origin,
                    row['adapter'],
                    subject,
                    row['scope'],
                    known_at,
                    digest,
                    trust,
                    'LAB_SYNTHETIC',
                    envelope_digest,
                ),
            )
        return self._metadata(evidence_id, subject, origin=origin, trust=trust)

    def _evidence(
        self,
        req: Request,
        *,
        adapter: str,
        source: str,
        payload: dict,
        origin='EXISTING_LOCAL_ADAPTER',
        trust='SYNTHETIC_LAB',
    ) -> str:
        evidence = save_evidence(
            adapter=adapter, source=source, scope=req.scope, payload=payload, db_path=self.db
        )
        self._metadata(evidence['evidence_id'], req.subject_id, origin=origin, trust=trust)
        return evidence['evidence_id']

    def verify_evidence(
        self, evidence_id: str, *, principal: Principal, as_of: str | None = None
    ) -> dict:
        principal.check()
        with closing(connect(self.db)) as con:
            con.row_factory = sqlite3.Row
            row = con.execute(
                '''SELECT e.*,m.*,e.scope AS original_scope,
                m.scope AS meta_scope FROM evidence e JOIN phase1_evidence_metadata_v1 m
                ON e.evidence_id=m.evidence_id WHERE e.evidence_id=?''',
                (evidence_id,),
            ).fetchone()
        if (
            row is None
            or row['scope'] != principal.scope
            or row['original_scope'] != row['meta_scope']
            or row['classification'] != principal.clearance
        ):
            raise PermissionError('EVIDENCE_ACCESS_DENIED')
        if as_of and (
            timestamp(row['known_at']) > timestamp(as_of)
            or timestamp(row['observed_at']) > timestamp(as_of)
        ):
            raise PermissionError('EVIDENCE_FUTURE_LEAKAGE_DENIED')
        payload = json.loads(row['payload_json'])
        if (
            _DIGEST(payload) != row['payload_sha256']
            or _DIGEST(
                {
                    'evidence_id': evidence_id,
                    'observed_at': row['observed_at'],
                    'adapter': row['adapter'],
                    'source': row['source'],
                    'scope': row['original_scope'],
                    'payload': payload,
                }
            )
            != row['envelope_sha256']
        ):
            raise PermissionError('EVIDENCE_TAMPER_DETECTED')
        return {
            'evidence_id': evidence_id,
            'origin': row['origin'],
            'source_type': row['source_type'],
            'subject_id': row['subject_id'],
            'scope': row['scope'],
            'observed_at': row['observed_at'],
            'known_at': row['known_at'],
            'content_sha256': row['payload_sha256'],
            'trust_status': row['trust_status'],
            'classification': row['classification'],
        }
