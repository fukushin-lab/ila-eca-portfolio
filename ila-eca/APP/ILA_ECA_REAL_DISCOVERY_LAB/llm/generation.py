"""One scoped local model attempt per A-H input, with original exchanges in Evidence."""

from contextlib import closing
from pathlib import Path
from time import perf_counter
from urllib.error import HTTPError
import base64
import copy
import hashlib
import inspect
import json
import sqlite3
import sys
import uuid
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, init_db, save_evidence, utc_now
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import (
    IncidentModelProfile,
    generate,
    metrics,
    open_local,
    deny_external_egress,
)


def _origin(adapter, payload):
    if not adapter.startswith('cloud_route_'):
        return 'LOCAL_FULL_ROUTE'
    kind = payload.get('execution_kind', payload.get('condition', {}).get('execution_kind'))
    return (
        'CLOUD_GENERATION_' + kind
        if kind in {'LIVE', 'HISTORICAL_REPLAY', 'MOCK'}
        else 'CLOUD_GENERATION_UNVERIFIED'
    )


def _save(db, scope, source, adapter, payload):
    item = save_evidence(db_path=db, scope=scope, source=source, adapter=adapter, payload=payload)
    if scope == 'lab':
        from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import UnifiedPhase1

        UnifiedPhase1(db)._metadata(
            item['evidence_id'],
            source,
            origin=_origin(adapter, payload),
            trust='UNVERIFIED_MODEL_OR_INPUT',
        )
    return item['evidence_id']


def reserve(db, scope, source, adapter, payload):
    """Only the creator dispatches. Existing unfinished attempts are never resent."""
    init_db(db)
    with closing(connect(db)) as con, con:
        con.execute('BEGIN IMMEDIATE')
        rows = con.execute(
            'SELECT evidence_id,payload_json FROM evidence WHERE scope=? AND source=? AND adapter=?',
            (scope, source, adapter),
        ).fetchall()
        if len(rows) > 1:
            raise ValueError('ROUTE_INPUT_RECONCILIATION_AMBIGUOUS')
        if rows:
            if json.loads(rows[0][1]) != payload:
                raise ValueError('ROUTE_CHANGED_REQUEST_REPLAY')
            return rows[0][0], False
        eid = str(uuid.uuid4())
        con.execute(
            'INSERT INTO evidence(evidence_id,observed_at,adapter,source,scope,payload_json) VALUES(?,?,?,?,?,?)',
            (eid, utc_now(), adapter, source, scope, canonical_json(payload)),
        )
    if scope == 'lab':
        from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import UnifiedPhase1

        UnifiedPhase1(db)._metadata(
            eid, source, origin=_origin(adapter, payload), trust='UNVERIFIED_MODEL_OR_INPUT'
        )
    return eid, True


def load_evidence(db, eid, scope):
    with closing(connect(db)) as con:
        con.row_factory = sqlite3.Row
        row = con.execute('SELECT * FROM evidence WHERE evidence_id=?', (eid,)).fetchone()
    if not row or row['scope'] != scope:
        raise PermissionError('ROUTE_EVIDENCE_SCOPE_MISMATCH')
    if scope == 'lab':
        from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import UnifiedPhase1
        from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import Principal

        UnifiedPhase1(db).verify_evidence(eid, principal=Principal('FULL-ROUTE-READER'))
    return dict(row), json.loads(row['payload_json'])


def metadata_ready(db, eid, scope):
    if scope != 'lab':
        return True
    with closing(connect(db)) as con:
        exists = con.execute(
            "SELECT 1 FROM sqlite_master WHERE name='phase1_evidence_metadata_v1'"
        ).fetchone()
        if (
            not exists
            or not con.execute(
                'SELECT 1 FROM phase1_evidence_metadata_v1 WHERE evidence_id=?', (eid,)
            ).fetchone()
        ):
            return False
    load_evidence(db, eid, scope)  # Existing bad metadata is an integrity error, never pending.
    return True


def _validator_identity(validator):
    if validator is None:
        return None
    module = sys.modules.get(getattr(validator, '__module__', ''))
    path = getattr(module, '__file__', None)
    return {
        'function': getattr(validator, '__qualname__', type(validator).__name__),
        'module_sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest() if path else None,
    }


def verify_saved_exchange(saved, input_record, input_row, validator=None):
    """Check original bytes and input binding on replay and before document output."""
    if saved['input_record_sha256'] != data_digest(input_row):
        raise ValueError('ROUTE_INPUT_BINDING_CHANGED')
    condition = input_record['condition']
    trace = saved['trace']
    exchange = trace.get('exchange', {})
    request = exchange.get('request')
    if request:
        if (
            request.get('prompt') != condition['prompt']
            or request.get('model') != condition['profile']['model']
            or request.get('options') != condition['profile']['options']
            or request.get('format') != condition['schema']
            or trace.get('profile') != condition['profile']
        ):
            raise ValueError('ROUTE_ORIGINAL_REQUEST_CHANGED')
    body = exchange.get('response_body')
    if body:
        try:
            raw = base64.b64decode(body['base64'], validate=True)
        except (ValueError, TypeError):
            raise ValueError('ROUTE_ORIGINAL_RESPONSE_CHANGED') from None
        if hashlib.sha256(raw).hexdigest() != body['sha256']:
            raise ValueError('ROUTE_ORIGINAL_RESPONSE_CHANGED')
    if saved['status'] != 'GENERATED':
        return saved
    if not request or not body or not body.get('complete_response'):
        raise ValueError('ROUTE_ORIGINAL_RESPONSE_INCOMPLETE')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('ROUTE_DUPLICATE_JSON_KEY')
            result[key] = value
        return result

    envelope = json.loads(raw, object_pairs_hook=unique)
    if (
        envelope != exchange.get('response')
        or envelope.get('done') is not True
        or envelope.get('done_reason') not in (None, 'stop')
    ):
        raise ValueError('ROUTE_MODEL_ENVELOPE_CHANGED')
    original = (
        envelope['response']
        if condition['schema'] is None
        else json.loads(envelope['response'], object_pairs_hook=unique)
    )
    if original != saved['value']:
        raise ValueError('ROUTE_MODEL_OUTPUT_CHANGED')
    expected = condition['profile'].get('expected_digest')
    if trace.get('model') != condition['profile']['model'] or (
        expected and trace.get('model_digest') != expected
    ):
        raise ValueError('ROUTE_MODEL_IDENTITY_CHANGED')
    if saved.get('metrics') != metrics(trace):
        raise ValueError('ROUTE_MODEL_METRICS_CHANGED')
    if validator:
        value = copy.deepcopy(original)
        before = canonical_json(value)
        checked = validator(value)
        if canonical_json(value) != before or (
            checked is not None and canonical_json(checked) != before
        ):
            raise ValueError('ROUTE_VALIDATOR_CHANGED_MODEL_OUTPUT')
    return saved


def infer(
    db, *, scope, route, request_id, instruction, input_data, schema, validator=None, profile=None
):
    profile = profile or IncidentModelProfile(model='qwen3:8b')
    profile = IncidentModelProfile.from_dict(profile.as_dict())
    if (
        route not in 'ABCDEFGH'
        or len(route) != 1
        or not isinstance(request_id, str)
        or not 1 <= len(request_id) <= 200
    ):
        raise ValueError('ROUTE_REQUEST_INVALID')
    init_db(db)
    source = f'full-route://{route}/{request_id}'
    prompt = (
        instruction
        + '\n<untrusted_route_input>\n'
        + canonical_json(input_data)
        + '\n</untrusted_route_input>'
    )
    condition = {
        'route': route,
        'request_id': request_id,
        'instruction': instruction,
        'input': copy.deepcopy(input_data),
        'prompt': prompt,
        'schema': copy.deepcopy(schema),
        'profile': profile.as_dict(),
        'validator': _validator_identity(validator),
        'adapter_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    condition['runtime_sha256'] = hashlib.sha256(
        Path(sys.modules[generate.__module__].__file__).read_bytes()
    ).hexdigest()
    input_id, is_new = reserve(
        db,
        scope,
        source,
        'route_model_input_v1',
        {'condition': condition, 'condition_sha256': data_digest(condition)},
    )
    if not is_new:
        if not metadata_ready(db, input_id, scope):
            return {
                'status': 'HOLD',
                'value': None,
                'route': route,
                'input_evidence_id': input_id,
                'evidence_id': input_id,
                'actual_llm_calls': None,
                'cache_hit': True,
                'record_state': 'INPUT_METADATA_PENDING',
                'error_code': 'ROUTE_INPUT_METADATA_PENDING_NO_RESEND',
            }
        input_row, old = load_evidence(db, input_id, scope)
        if old['condition'] != condition:
            raise ValueError('ROUTE_CHANGED_REQUEST_REPLAY')
        with closing(connect(db)) as con:
            results = con.execute(
                "SELECT evidence_id FROM evidence WHERE scope=? AND source=? AND adapter='route_model_result_v1' AND json_extract(payload_json,'$.input_evidence_id')=?",
                (scope, source, input_id),
            ).fetchall()
        if len(results) > 1:
            raise ValueError('ROUTE_RESULT_RECONCILIATION_AMBIGUOUS')
        if results:
            if not metadata_ready(db, results[0][0], scope):
                return {
                    'status': 'HOLD',
                    'value': None,
                    'route': route,
                    'input_evidence_id': input_id,
                    'input_record_sha256': data_digest(input_row),
                    'evidence_id': input_id,
                    'actual_llm_calls': None,
                    'cache_hit': True,
                    'record_state': 'INPUT_METADATA_PENDING',
                    'error_code': 'ROUTE_RESULT_METADATA_PENDING_NO_RESEND',
                }
            _, saved = load_evidence(db, results[0][0], scope)
            verify_saved_exchange(saved, old, input_row, validator)
            return {**saved, 'evidence_id': results[0][0], 'actual_llm_calls': 0, 'cache_hit': True}
        # A killed process may have dispatched a request. Do not silently resend.
        saved = {
            'status': 'HOLD',
            'value': None,
            'route': route,
            'input_evidence_id': input_id,
            'input_record_sha256': data_digest(input_row),
            'trace': {'model': profile.model, 'profile': profile.as_dict(), 'exchange': {}},
            'actual_llm_calls': None,
            'error_code': 'ROUTE_INTERRUPTED_RESULT_UNKNOWN_NO_RESEND',
            'failure_category': 'UNDETERMINED',
            'elapsed_seconds': None,
        }
        saved['metrics'] = metrics(saved['trace'], failure_stage='INTERRUPTED_RESULT_UNKNOWN')
        return {
            **saved,
            'evidence_id': input_id,
            'cache_hit': True,
            'record_state': 'RESERVED_RESULT_NOT_RECEIVED',
        }
    input_row, _ = load_evidence(db, input_id, scope)
    exchange = {}
    fingerprint = None
    stage = 'MODEL_IDENTITY'
    started = perf_counter()
    value = None

    def retain(raw, *, status=200, complete=True):
        exchange['http_status'] = status
        exchange['response_body'] = {
            'base64': base64.b64encode(raw).decode(),
            'sha256': hashlib.sha256(raw).hexdigest(),
            'received_bytes': len(raw),
            'complete_response': complete and len(raw) <= profile.max_http_bytes,
        }
        try:
            exchange['response'] = json.loads(raw)
        except (ValueError, UnicodeError):
            pass

    def capture(req, timeout):
        exchange['request'] = json.loads(req.data)
        try:
            response = open_local(req, timeout)
        except HTTPError as exc:
            retain(exc.read(profile.max_http_bytes + 1), status=exc.code)
            exc.close()
            raise

        class Response:
            def __enter__(self):
                return self

            def read(self, limit):
                try:
                    raw = response.read(limit)
                except BaseException as exc:
                    if isinstance(getattr(exc, 'partial', None), bytes):
                        retain(exc.partial[:limit], complete=False)
                    raise
                retain(raw)
                return raw

            def __exit__(self, *_):
                response.close()

        return Response()

    try:
        from ILA_ECA_REAL_DISCOVERY_LAB.design.non_aws import _model_digest

        with deny_external_egress():
            fingerprint = _model_digest(profile.model)
        if profile.expected_digest and fingerprint != profile.expected_digest:
            raise ValueError('INCIDENT_MODEL_VERSION_CHANGED')
        stage = 'TRANSPORT_AND_PARSE'
        with deny_external_egress():
            value = generate(
                profile=profile,
                prompt=prompt,
                schema=schema,
                opener=capture,
                text_output=schema is None,
            )
        stage = 'RESPONSE_VALIDATION'
        env = exchange['response']
        if env.get('done') is not True or env.get('done_reason') not in (None, 'stop'):
            raise ValueError('ROUTE_MODEL_INCOMPLETE')

        def unique(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError('ROUTE_DUPLICATE_JSON_KEY')
                result[key] = item
            return result

        envelope = json.loads(
            base64.b64decode(exchange['response_body']['base64']), object_pairs_hook=unique
        )
        original = (
            envelope['response']
            if schema is None
            else json.loads(envelope['response'], object_pairs_hook=unique)
        )
        if original != value:
            raise ValueError('ROUTE_MODEL_PARSE_CHANGED')
        before = canonical_json(value)
        if validator:
            checked = validator(value)
            if canonical_json(value) != before or (
                checked is not None and canonical_json(checked) != before
            ):
                raise ValueError('ROUTE_VALIDATOR_CHANGED_MODEL_OUTPUT')
        with deny_external_egress():
            after_digest = _model_digest(profile.model)
        if after_digest != fingerprint:
            raise ValueError('INCIDENT_MODEL_VERSION_CHANGED')
        trace = {
            'model': profile.model,
            'model_digest': fingerprint,
            'profile': profile.as_dict(),
            'exchange': exchange,
        }
        saved = {
            'status': 'GENERATED',
            'value': value,
            'route': route,
            'input_evidence_id': input_id,
            'input_record_sha256': data_digest(input_row),
            'trace': trace,
            'actual_llm_calls': 1,
            'metrics': metrics(trace),
            'elapsed_seconds': round(perf_counter() - started, 3),
        }
    except BaseException as exc:
        trace = {
            'model': profile.model,
            'model_digest': fingerprint,
            'profile': profile.as_dict(),
            'exchange': exchange,
        }
        code = (
            str(exc)
            if str(exc).startswith(
                (
                    'ROUTE_',
                    'INCIDENT_',
                    'OLLAMA_',
                    'LOCAL_',
                    'V8_',
                    'PLAN_',
                    'ANSWER_',
                    'SECURITY_',
                    'AWS_DESIGN_',
                )
            )
            else type(exc).__name__
        )
        category = (
            'CODE'
            if code in {'ROUTE_VALIDATOR_CHANGED_MODEL_OUTPUT', 'ROUTE_MODEL_PARSE_CHANGED'}
            else (
                'UNDETERMINED'
                if not isinstance(exc, Exception)
                else (
                    'MODEL_OUTPUT'
                    if stage == 'RESPONSE_VALIDATION' or code.startswith('OLLAMA_FINAL_')
                    else 'RUNTIME'
                )
            )
        )
        saved = {
            'status': 'HOLD',
            'value': None,
            'rejected_value': value,
            'route': route,
            'input_evidence_id': input_id,
            'input_record_sha256': data_digest(input_row),
            'trace': trace,
            'actual_llm_calls': int('request' in exchange),
            'metrics': metrics(trace, failure_stage=stage),
            'elapsed_seconds': round(perf_counter() - started, 3),
            'error_code': code,
            'error_message': str(exc)[:4096],
            'error_type': type(exc).__name__,
            'failure_category': category,
        }
        if not isinstance(exc, Exception):
            _save(db, scope, source, 'route_model_result_v1', saved)
            raise
    eid = _save(db, scope, source, 'route_model_result_v1', saved)
    return {**saved, 'evidence_id': eid, 'cache_hit': False}
