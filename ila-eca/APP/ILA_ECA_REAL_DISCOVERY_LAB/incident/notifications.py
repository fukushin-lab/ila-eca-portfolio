"""Authenticated local notifications -> durable queue -> existing C. No repair."""

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import copy
import json
import hmac
import sqlite3
import threading
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, init_db, utc_now
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import timestamp
from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import _save


def initialize(db):
    init_db(db)
    with closing(connect(db)) as con, con:
        con.execute(
            'CREATE TABLE IF NOT EXISTS notification_case_v1 (event_key TEXT PRIMARY KEY,config_sha TEXT NOT NULL,manifest TEXT NOT NULL,state TEXT NOT NULL,result_json TEXT)'
        )
        con.execute(
            'CREATE TABLE IF NOT EXISTS notification_receipt_v1 (receipt_id INTEGER PRIMARY KEY,event_key TEXT NOT NULL,evidence_id TEXT NOT NULL,status TEXT NOT NULL,received_at TEXT NOT NULL)'
        )


def validate_config(config):
    if (
        set(config)
        != {'schema', 'source_id', 'product', 'bindings', 'profile', 'max_steps', 'max_calls'}
        or config['schema'] != 'ila.eca.notification-intake.v1'
    ):
        raise ValueError('NOTIFICATION_CONFIG_INVALID')
    if (
        config['product'] not in {'ALERTMANAGER', 'AWX'}
        or not isinstance(config['source_id'], str)
        or not config['source_id']
    ):
        raise ValueError('NOTIFICATION_SOURCE_INVALID')
    if (
        not config['bindings']
        or not 1 <= config['max_steps'] <= 32
        or not 1 <= config['max_calls'] <= 64
    ):
        raise ValueError('NOTIFICATION_LIMITS_INVALID')
    from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import IncidentModelProfile

    if config['profile']:
        IncidentModelProfile.from_dict(config['profile'])
    for b in config['bindings']:
        if (
            set(b) != {'match', 'target_ref', 'operations'}
            or not isinstance(b['match'], dict)
            or not b['match']
            or not isinstance(b['operations'], list)
        ):
            raise ValueError('NOTIFICATION_BINDING_INVALID')
        if any(
            v is None or not isinstance(v, (str, int)) or isinstance(v, bool)
            for v in b['match'].values()
        ):
            raise ValueError('NOTIFICATION_MATCH_VALUE_REQUIRED')
        import re

        if not re.fullmatch(r'[A-Za-z0-9_.-]{3,100}', b['target_ref']):
            raise ValueError('NOTIFICATION_TARGET_INVALID')
        # Same allowlist as the normal C entry; notification content never supplies tools.
        for op in b['operations']:
            if op.get('kind') not in {'AUDIT_FIELDS', 'HTTP_GET_LOOPBACK'}:
                raise PermissionError('NOTIFICATION_OPERATION_DENIED')
    return config


def normalize(payload, product):
    if not isinstance(payload, dict):
        raise ValueError('NOTIFICATION_OBJECT_REQUIRED')
    if product == 'ALERTMANAGER':
        rows = payload.get('alerts')
        if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
            raise ValueError('NOTIFICATION_ALERTS_REQUIRED')
        events = []
        for a in rows:
            if (
                a.get('status') not in {'firing', 'resolved'}
                or not isinstance(a.get('labels'), dict)
                or not a['labels']
            ):
                raise ValueError('NOTIFICATION_ALERT_INVALID')
            when = a['startsAt']
            timestamp(when)
            # Labels + start identify an episode, not annotations or the receiver's clock.
            events.append(
                {
                    'identity': data_digest([a['labels'], when]),
                    'status': a['status'],
                    'time': when,
                    'labels': a['labels'],
                    'event': a,
                }
            )
        return events
    if product == 'AWX':
        if (
            type(payload.get('id')) is not int
            or payload['id'] <= 0
            or payload.get('status') not in {'failed', 'error', 'canceled', 'successful'}
        ):
            raise ValueError('NOTIFICATION_JOB_INVALID')
        when = payload.get('started') or payload.get('finished')
        timestamp(when)
        return [
            {
                'identity': str(payload['id']),
                'status': 'firing' if payload['status'] in {'failed', 'error'} else 'resolved',
                'time': when,
                'labels': {
                    k: payload[k]
                    for k in ['job_template', 'name', 'inventory', 'project']
                    if k in payload
                },
                'event': payload,
            }
        ]
    raise ValueError('NOTIFICATION_PRODUCT_INVALID')


def ingest(db, payload, config):
    config = copy.deepcopy(validate_config(config))
    events = normalize(payload, config['product'])
    initialize(db)
    results = []
    # Refuse ambiguous/unmapped targets before accepting any event in the batch.
    matches = []
    for e in events:
        selected = [
            b
            for b in config['bindings']
            if all(k in e['labels'] and e['labels'][k] == v for k, v in b['match'].items())
        ]
        if len(selected) != 1:
            raise PermissionError('NOTIFICATION_EXACT_TARGET_BINDING_REQUIRED')
        matches.append(selected[0])
    for e, b in zip(events, matches):
        key = data_digest([config['source_id'], config['product'], e['identity']])
        cid = 'CASE-NOTIFY-' + key[:32]
        evidence = _save(
            db,
            'lab',
            'notification://' + config['source_id'] + '/' + key,
            'monitoring_notification_v1',
            {
                'event': e['event'],
                'basis_type': 'UNVERIFIED_REPORT',
                'source_observed_at': e['time'],
                'source_id': config['source_id'],
                'coverage': 'Reported monitoring event, not measured cause or recovery',
                'config_sha256': data_digest(config),
            },
        )
        now = utc_now()
        start = timestamp(e['time'])
        end = max(start, datetime.now(timezone.utc)) + timedelta(minutes=30)
        manifest = {
            'schema': 'ila.eca.incident-request.v1',
            'request': {
                'request_id': cid,
                'request_type': 'INCIDENT',
                'subject_id': b['target_ref'],
                'scope': 'lab',
                'received_at': now,
                'requester_ref': 'NOTIFICATION-OPERATOR',
                'untrusted_text': 'Monitoring reports an abnormal event; cause is not established.',
                'requested_effect': 'READ',
                'correlation_id': cid,
                'details': {'notification_evidence_id': evidence, 'notification_key': key},
            },
            'incident': {
                'symptom': 'Monitoring reports '
                + config['product']
                + ' event '
                + e['identity']
                + '. Read the attached original notification; root cause is unknown.',
                'occurred_at': e['time'],
                'window': {
                    'start': (start - timedelta(minutes=5)).isoformat(),
                    'end': end.isoformat(),
                },
                'targets': [b['target_ref']],
                'unknowns': [
                    'Notification is unverified; root cause and recovery require observations.'
                ],
                'baseline_ref': None,
                'evidence_selections': [
                    {
                        'evidence_id': evidence,
                        'paths': ['/event'],
                        'subject_ref': 'notification://' + config['source_id'] + '/' + key,
                    }
                ],
            },
            'operations': b['operations'],
            'max_steps': config['max_steps'],
            'max_calls': config['max_calls'],
        }
        with closing(connect(db)) as con, con:
            con.execute('BEGIN IMMEDIATE')
            old = con.execute(
                'SELECT config_sha,state FROM notification_case_v1 WHERE event_key=?', (key,)
            ).fetchone()
            if old and old[0] != data_digest(config):
                raise ValueError('NOTIFICATION_EXISTING_CASE_CONFIG_CHANGED')
            if not old:
                state = 'RECEIVED' if e['status'] == 'firing' else 'RESOLVED_NOTIFICATION_ONLY'
                con.execute(
                    'INSERT INTO notification_case_v1 VALUES(?,?,?,?,NULL)',
                    (key, data_digest(config), canonical_json(manifest), state),
                )
            # A resolved notification never closes a case or declares successful recovery.
            con.execute(
                'INSERT INTO notification_receipt_v1(event_key,evidence_id,status,received_at) VALUES(?,?,?,?)',
                (key, evidence, e['status'], now),
            )
            state = old[1] if old else state
        results.append(
            {
                'event_key': key,
                'case_id': cid,
                'state': state,
                'duplicate': old is not None,
                'evidence_id': evidence,
            }
        )
    return results


def drain_one(db, config, *, request_runner=None):
    """Durable claim before model work. Crashed claims require explicit review."""
    validate_config(config)
    initialize(db)
    with closing(connect(db)) as con, con:
        con.execute('BEGIN IMMEDIATE')
        row = con.execute(
            "SELECT event_key,manifest FROM notification_case_v1 WHERE state='RECEIVED' AND config_sha=? ORDER BY rowid LIMIT 1",
            (data_digest(config),),
        ).fetchone()
        if row is None:
            return None
        con.execute("UPDATE notification_case_v1 SET state='CLAIMED' WHERE event_key=?", (row[0],))
    key, manifest = row
    path = Path(db).parent / 'notification_inputs' / (key + '.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.is_symlink() or not path.resolve().is_relative_to(Path(db).parent.resolve()):
            raise PermissionError('NOTIFICATION_MANIFEST_PATH_DENIED')
        if path.exists() and path.read_text(encoding='utf-8') != manifest:
            raise ValueError('NOTIFICATION_MANIFEST_CHANGED')
        if not path.exists():
            with path.open('x', encoding='utf-8') as f:
                f.write(manifest)
        from ILA_ECA_REAL_DISCOVERY_LAB.run_structured_design_v2 import dispatch

        result = (request_runner or dispatch)(
            db,
            {
                'schema': 'ila.eca.full-route-request.v1',
                'request_id': 'FULL-NOTIFY-' + key[:32],
                'route': 'C',
                'scope': 'lab',
                'profile': config['profile'],
                'payload': {'provider': 'LOCAL8B', 'incident_request': str(path)},
            },
        )
        state = 'DONE' if not result.get('result', {}).get('pending') else 'REVIEW_REQUIRED'
    except BaseException as exc:
        state = 'REVIEW_REQUIRED'
        result = {'status': 'HOLD', 'error_type': type(exc).__name__, 'automatic_retry': False}
        with closing(connect(db)) as con, con:
            con.execute(
                'UPDATE notification_case_v1 SET state=?,result_json=? WHERE event_key=?',
                (state, canonical_json(result), key),
            )
        if not isinstance(exc, Exception):
            raise
        return result
    with closing(connect(db)) as con, con:
        con.execute(
            'UPDATE notification_case_v1 SET state=?,result_json=? WHERE event_key=?',
            (state, canonical_json(result), key),
        )
    return result


def make_server(db, config, *, token, port=0):
    """Loopback POST endpoint only. Token comes from host env, never request JSON."""
    from http.server import BaseHTTPRequestHandler, HTTPServer

    validate_config(config)
    if not isinstance(token, str) or len(token) < 24:
        raise PermissionError('NOTIFICATION_STRONG_HOST_TOKEN_REQUIRED')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            if self.path != '/incidents':
                self.send_error(404)
                return
            if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + token):
                self.send_error(401)
                return
            try:
                if self.headers.get('Transfer-Encoding'):
                    raise ValueError('NOTIFICATION_TRANSFER_ENCODING_DENIED')
                n = int(self.headers['Content-Length'])
                if not 0 < n <= 1048576:
                    raise ValueError('NOTIFICATION_BODY_LIMIT')
                from ILA_ECA_REAL_DISCOVERY_LAB.llm.cloud import parse

                data = self.rfile.read(n)
                if len(data) != n:
                    raise ValueError('NOTIFICATION_BODY_INCOMPLETE')
                rows = ingest(db, parse(data), config)
            except Exception:
                self.send_error(400, 'Notification rejected')
                return
            body = canonical_json(
                {'accepted': rows, 'cause_confirmed': False, 'repair_executed': False}
            ).encode()
            self.send_response(202)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

    return HTTPServer(('127.0.0.1', port), Handler)


def serve(db, config, *, token, port):
    server = make_server(db, config, token=token, port=port)
    stop = threading.Event()

    def worker():
        while not stop.is_set():
            try:
                result = drain_one(db, config)
            except Exception as exc:
                import sys

                print(
                    'NOTIFICATION_WORKER_FAILED:' + type(exc).__name__, file=sys.stderr, flush=True
                )
                return
            if result is None:
                stop.wait(1)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    print(
        'Notification listener: http://127.0.0.1:' + str(server.server_port) + '/incidents',
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        stop.set()
        server.server_close()
        thread.join(timeout=1)
