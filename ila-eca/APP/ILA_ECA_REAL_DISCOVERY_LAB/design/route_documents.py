"""Immutable A-H draft annexes in the existing common document registry."""

from contextlib import closing
from hashlib import sha256
from pathlib import Path
import copy
import inspect
import json
import re
import sqlite3
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import (
    canonical_json,
    data_digest,
    render_template,
    register_document,
    validate_record,
    init_registry,
)
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import document_paths
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle import changes as lifecycle

TEMPLATE = (
    '# ILA/ECA $route 経路の記録\n\n記録ID: `$design_id` / 版: $revision\n\n'
    '未承認の草案・判断記録。形式適合、意味の正しさ、承認、実環境での成功は別の状態です。\n\n$body\n'
).encode('utf-8')


def _row(con, db, eid, scope, *, require_envelope=True):
    con.row_factory = sqlite3.Row
    row = con.execute('SELECT * FROM evidence WHERE evidence_id=?', (eid,)).fetchone()
    if row is None or row['scope'] != scope:
        raise PermissionError('FULL_ROUTE_EVIDENCE_SCOPE_MISMATCH')
    if scope == 'lab' and (
        require_envelope
        or con.execute(
            'SELECT 1 FROM phase1_evidence_metadata_v1 WHERE evidence_id=?', (eid,)
        ).fetchone()
    ):
        from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import UnifiedPhase1
        from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import Principal

        gateway = UnifiedPhase1.__new__(UnifiedPhase1)
        gateway.db = Path(db)
        gateway.verify_evidence(eid, principal=Principal('FULL-ROUTE-DOCUMENT-READER'))
    if row['adapter'] == 'received_document_search_v1':
        from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.intake import verify_search_evidence

        verify_search_evidence(con, eid, scope)
    return dict(row), json.loads(row['payload_json'])


def _execution_result(result):
    if type(result) is not dict:
        raise ValueError('FULL_ROUTE_RESULT_INVALID')
    if isinstance(result.get('evidence_id'), str):
        return result
    if isinstance(result.get('call'), dict) and isinstance(result['call'].get('evidence_id'), str):
        return result['call']
    raise ValueError('FULL_ROUTE_RESULT_EVIDENCE_REQUIRED')


def _stable_result(result, raw, eid):
    result = copy.deepcopy(result)
    execution = _execution_result(result)
    if execution['evidence_id'] != eid:
        raise ValueError('FULL_ROUTE_RESULT_BINDING_CHANGED')
    for key, value in raw.items():
        if key == 'actual_llm_calls':
            continue
        if key in execution and execution[key] != value:
            raise ValueError('FULL_ROUTE_MODEL_RESULT_CHANGED')
    execution.pop('cache_hit', None)
    execution['actual_llm_calls'] = raw.get('actual_llm_calls')
    result.pop('cache_hit', None)
    if 'actual_llm_calls' in result:
        result['actual_llm_calls'] = raw.get('actual_llm_calls')
    return result


def _source_pairs(result, raw, model_input):
    sources = []
    for container in (result, raw, model_input.get('condition', {}).get('input', {})):
        if not isinstance(container, dict):
            continue
        for name in ('source_bindings', 'search_bindings'):
            for item in container.get(name, []):
                if isinstance(item, dict) and {'evidence_id', 'record_sha256'} <= item.keys():
                    sources.append((item['evidence_id'], item['record_sha256']))
        input_data = container.get('input_data', container)
        if isinstance(input_data, dict):
            for name in ('evidence', 'selected_evidence'):
                for item in input_data.get(name, []):
                    if (
                        isinstance(item, dict)
                        and item.get('state') == 'COLLECTED_AT_RECORDED_TIME'
                        and {'evidence_id', 'record_sha256'} <= item.keys()
                    ):
                        sources.append((item['evidence_id'], item['record_sha256']))
    return sorted(set(sources))


def _check_lifecycle_bindings(con, result, raw):
    base = raw.get('baseline_binding')
    if base:
        row = con.execute(
            'SELECT spec_json,origin FROM lifecycle_baseline_v1 WHERE scope=? AND version=?',
            (base['scope'], base['version']),
        ).fetchone()
        if (
            not row
            or data_digest(json.loads(row['spec_json'])) != base['spec_sha256']
            or row['origin'] != base['origin']
        ):
            raise ValueError('FULL_ROUTE_BASELINE_BINDING_CHANGED')
    change = result.get('binding')
    if isinstance(change, dict) and 'approved_design_sha256' in change:
        row = con.execute(
            'SELECT * FROM lifecycle_change_v1 WHERE change_id=?', (change['change_id'],)
        ).fetchone()
        if (
            not row
            or row['scope'] != change['scope']
            or row['base_version'] != change['base_version']
            or row['design_sha256'] != change['approved_design_sha256']
            or data_digest(json.loads(row['intended_spec_json'])) != change['intended_spec_sha256']
        ):
            raise ValueError('FULL_ROUTE_APPROVED_CHANGE_BINDING_CHANGED')


def _material(con, db, scope, route, request_id, design_id, revision, result):
    execution = _execution_result(result)
    eid = execution['evidence_id']
    row, raw = _row(con, db, eid, scope)
    expected_source = (
        'full-request://' if row['adapter'] == 'full_route_failure_v1' else f'full-route://{route}/'
    ) + request_id
    if row['source'] != expected_source:
        raise ValueError('FULL_ROUTE_REQUEST_BINDING_CHANGED')
    if row['adapter'] not in {
        'route_model_input_v1',
        'route_model_result_v1',
        'full_context_route_input_v1',
        'full_context_no_action_v1',
        'full_route_failure_v1',
        'full_route_execution_v1',
        'cloud_route_result_v1',
    }:
        raise ValueError('FULL_ROUTE_RESULT_ADAPTER_UNSUPPORTED')
    pending = row['adapter'] == 'route_model_input_v1'
    if pending:
        if (
            execution.get('status') != 'HOLD'
            or execution.get('value') is not None
            or execution.get('record_state') != 'RESERVED_RESULT_NOT_RECEIVED'
            or execution.get('input_evidence_id') != eid
            or execution.get('input_record_sha256') != data_digest(row)
        ):
            raise ValueError('FULL_ROUTE_PENDING_SNAPSHOT_INVALID')
        if raw.get('condition', {}).get('route') != route:
            raise ValueError('FULL_ROUTE_RESULT_ROUTE_CHANGED')
    elif raw.get('route') != route:
        raise ValueError('FULL_ROUTE_RESULT_ROUTE_CHANGED')
    stable = _stable_result(result, raw, eid)
    bindings = [{'role': 'RESULT', 'evidence_id': eid, 'record_sha256': data_digest(row)}]
    model_input = {}
    if pending:
        model_input = raw
        condition = raw['condition']
        if condition.get('request_id') != request_id:
            raise ValueError('FULL_ROUTE_REQUEST_BINDING_CHANGED')
        if 'input_data' in stable and stable['input_data'] != condition['input']:
            raise ValueError('FULL_ROUTE_WRAPPER_INPUT_CHANGED')
    elif row['adapter'] == 'route_model_result_v1':
        input_row, model_input = _row(con, db, raw['input_evidence_id'], scope)
        if data_digest(input_row) != raw['input_record_sha256']:
            raise ValueError('FULL_ROUTE_MODEL_INPUT_CHANGED')
        from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import verify_saved_exchange

        verify_saved_exchange(raw, model_input, input_row, validator=None)
        condition = model_input['condition']
        if condition['route'] != route or condition['request_id'] != request_id:
            raise ValueError('FULL_ROUTE_REQUEST_BINDING_CHANGED')
        if 'input_data' in stable and stable['input_data'] != condition['input']:
            raise ValueError('FULL_ROUTE_WRAPPER_INPUT_CHANGED')
        bindings.append(
            {
                'role': 'MODEL_INPUT',
                'evidence_id': input_row['evidence_id'],
                'record_sha256': data_digest(input_row),
            }
        )
    elif row['adapter'] == 'cloud_route_result_v1':
        if route != 'G':
            raise ValueError('FULL_ROUTE_CLOUD_G_ONLY')
        input_row, model_input = _row(con, db, raw['input_evidence_id'], scope)
        if input_row['adapter'] != 'cloud_route_input_v1' or input_row['source'] != row['source']:
            raise ValueError('FULL_ROUTE_CLOUD_INPUT_BINDING_CHANGED')
        from ILA_ECA_REAL_DISCOVERY_LAB.llm.cloud import verify_exchange

        verify_exchange(raw, model_input, input_row)
        condition = model_input['condition']
        if condition['route'] != route or condition['request_id'] != request_id:
            raise ValueError('FULL_ROUTE_REQUEST_BINDING_CHANGED')
        bindings.append(
            {
                'role': 'MODEL_INPUT',
                'evidence_id': input_row['evidence_id'],
                'record_sha256': data_digest(input_row),
            }
        )
    elif row['adapter'] in {'full_context_route_input_v1', 'full_context_no_action_v1'}:
        if stable.get('value') is not None and stable['value'] != raw:
            raise ValueError('FULL_ROUTE_NON_MODEL_RESULT_CHANGED')
        if stable.get('input_data') != raw.get('input'):
            raise ValueError('FULL_ROUTE_NON_MODEL_INPUT_CHANGED')
    for source_id, expected_sha in _source_pairs(stable, raw, model_input):
        source, _ = _row(con, db, source_id, scope, require_envelope=False)
        if data_digest(source) != expected_sha:
            raise ValueError('FULL_ROUTE_SELECTED_SOURCE_CHANGED')
        bindings.append(
            {'role': 'SELECTED_SOURCE', 'evidence_id': source_id, 'record_sha256': expected_sha}
        )

    def explicit_ids(container):
        for key in (
            'request_evidence_id',
            'audio_evidence_id',
            'original_failure_evidence_id',
            'plan_evidence_id',
            'incident_head_evidence_id',
        ):
            if isinstance(container.get(key), str):
                yield key, container[key]
        if isinstance(container.get('call'), dict):
            yield from explicit_ids(container['call'])

    for role, source_id in sorted(set(explicit_ids(stable))):
        source, payload = _row(con, db, source_id, scope, require_envelope=False)
        if role == 'audio_evidence_id':
            from ILA_ECA_REAL_DISCOVERY_LAB.meeting.review import _validate_asr

            _validate_asr(payload)
            if stable.get('audio_sha256') != payload['result']['audio_sha256']:
                raise ValueError('FULL_ROUTE_AUDIO_BINDING_CHANGED')
        bindings.append(
            {'role': role.upper(), 'evidence_id': source_id, 'record_sha256': data_digest(source)}
        )
    _check_lifecycle_bindings(con, stable, raw)
    if stable.get('upstream_binding') is not None:
        from ILA_ECA_REAL_DISCOVERY_LAB.design.cloud_draft import verify_upstream

        if verify_upstream(stable['upstream_binding']) != stable['upstream_binding']:
            raise ValueError('FULL_ROUTE_UPSTREAM_BINDING_CHANGED')
    review_binding = {
        'source_scope': scope,
        'review_scope': lifecycle.SCOPE if scope == 'lab' else scope,
        'origin': 'EXPLICIT_ISOLATED_LAB_GATEWAY_ONLY' if scope == 'lab' else 'SAME_SCOPE',
    }
    return {
        'schema': 'ila.eca.full-route-draft.v1',
        'scope': scope,
        'route': route,
        'request_id': request_id,
        'design_id': design_id,
        'revision': revision,
        'route_result': stable,
        'evidence_bindings': bindings,
        'result_evidence_id': eid,
        'review_scope_binding': review_binding,
        'review_state': 'AWAITING_REVIEW',
        'formal_validation_is_semantic_proof': False,
        'approval_granted': False,
        'baseline_updated': False,
        'template_sha256': sha256(TEMPLATE).hexdigest(),
        'renderer_sha256': sha256(
            (inspect.getsource(_body) + inspect.getsource(_render)).encode()
        ).hexdigest(),
    }


def _body(data):
    def block(value, language='json'):
        text = (
            value
            if isinstance(value, str) and language == 'text'
            else json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
        )
        fence = '`' * max(3, max((len(x) for x in re.findall(r'`+', text)), default=0) + 1)
        return fence + language + '\n' + text + ('' if text.endswith('\n') else '\n') + fence

    result = data['route_result']
    execution = _execution_result(result)
    parts = [
        '## 保存済みの経路出力（補正なし）',
        block(result),
        '## 根拠・入力の同一性',
        block(data['evidence_bindings']),
    ]
    parts += [
        '## レビューの扱い',
        block(
            {
                'review_state': data['review_state'],
                'review_scope_binding': data['review_scope_binding'],
                'approval_granted': False,
                'baseline_updated': False,
                'formal_validation_is_semantic_proof': False,
            }
        ),
    ]
    return '\n\n'.join(parts)


def _render(data):
    content, meta = render_template(
        TEMPLATE,
        {
            'route': data['route'],
            'design_id': data['design_id'],
            'revision': data['revision'],
            'body': _body(data),
        },
        template_version='full-route-draft-v1',
    )
    value = _execution_result(data['route_result']).get('value')
    if isinstance(value, str):
        # The shared renderer normalizes CRLF in template fields. Compose this
        # raw block after that layout step so the saved model text is byte-exact.
        fence = '`' * max(3, max((len(x) for x in re.findall(r'`+', value)), default=0) + 1)
        raw = (
            '\n## モデル本文（保存文字列をそのまま表示）\n\n'
            + fence
            + 'text\n'
            + value
            + ('' if value.endswith('\n') else '\n')
            + fence
            + '\n'
        )
        content += raw.encode('utf-8')
        meta = {**meta, 'document_sha256': sha256(content).hexdigest()}
    return content, meta


def verify_route_document(con, db, design_id, revision, scope):
    con.row_factory = sqlite3.Row
    row = con.execute(
        'SELECT relative_path,record_json FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? AND revision=?',
        (scope, design_id, revision),
    ).fetchone()
    source_scope = scope
    if row is None and scope == lifecycle.SCOPE:
        candidate = con.execute(
            'SELECT relative_path,record_json FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? AND revision=?',
            ('lab', design_id, revision),
        ).fetchone()
        if (
            candidate
            and json.loads(candidate['record_json']).get('document_kind') == 'FULL_ROUTE_DRAFT'
        ):
            row = candidate
            source_scope = 'lab'
    if row is None:
        raise ValueError('FULL_ROUTE_DOCUMENT_NOT_FOUND')
    md, path = document_paths(db, row['relative_path'])
    if md.is_symlink() or path.is_symlink():
        raise ValueError('FULL_ROUTE_DOCUMENT_PATH_INVALID')
    data = json.loads(path.read_bytes())
    record = json.loads(row['record_json'])
    validate_record(record, content=md.read_bytes(), structured_data=data)
    expected = _material(
        con,
        db,
        source_scope,
        data['route'],
        data['request_id'],
        design_id,
        revision,
        data['route_result'],
    )
    if data != expected or record['document_kind'] != 'FULL_ROUTE_DRAFT':
        raise ValueError('FULL_ROUTE_DOCUMENT_BINDING_CHANGED')
    rendered, metadata = _render(data)
    if rendered != md.read_bytes() or metadata['template_sha256'] != record['template_sha256']:
        raise ValueError('FULL_ROUTE_RENDERED_CONTENT_CHANGED')
    if scope != source_scope and data['review_scope_binding'] != {
        'source_scope': 'lab',
        'review_scope': lifecycle.SCOPE,
        'origin': 'EXPLICIT_ISOLATED_LAB_GATEWAY_ONLY',
    }:
        raise PermissionError('FULL_ROUTE_REVIEW_SCOPE_MISMATCH')
    if scope == lifecycle.SCOPE and data['route'] == 'F':
        _, raw = _row(con, db, data['result_evidence_id'], source_scope)
        base = raw.get('baseline_binding')
        if base:
            current = con.execute(
                'SELECT version FROM lifecycle_current_v1 WHERE scope=?', (base['scope'],)
            ).fetchone()
            if not current or current['version'] != base['version']:
                raise ValueError('FULL_ROUTE_NO_OP_BASELINE_NO_LONGER_CURRENT')
    return {'record': record, 'data': data, 'path': str(md), 'structured_path': str(path)}


def create_route_document(db, *, scope, route, request_id, result):
    if (
        not isinstance(route, str)
        or route not in 'ABCDEFGH'
        or len(route) != 1
        or not isinstance(request_id, str)
        or not request_id
    ):
        raise ValueError('FULL_ROUTE_DOCUMENT_INPUT_INVALID')
    design_id = 'FULL-' + route + '-' + data_digest(request_id)[:24]
    created = []
    try:
        with closing(connect(db)) as con, con:
            con.execute('BEGIN IMMEDIATE')
            init_registry(con)
            old = con.execute(
                'SELECT revision,record_json FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? ORDER BY revision DESC LIMIT 1',
                (scope, design_id),
            ).fetchone()
            revision = old[0] if old else 1
            data = _material(con, db, scope, route, request_id, design_id, revision, result)
            if old and data_digest(data) == json.loads(old[1])['structured_data_sha256']:
                return verify_route_document(con, db, design_id, revision, scope)
            if old:
                revision += 1
                data['revision'] = revision
            relative = f'full_route_documents/{design_id}_r{revision:04d}.md'
            md, path = document_paths(db, relative)
            md.parent.mkdir(parents=True, exist_ok=True)
            content, meta = _render(data)
            for file, raw in ((md, content), (path, canonical_json(data).encode())):
                with file.open('xb') as stream:
                    created.append(file)
                    stream.write(raw)
            register_document(
                con,
                domain_id=scope,
                design_id=design_id,
                document_kind='FULL_ROUTE_DRAFT',
                content=content,
                structured_data=data,
                render_metadata=meta,
                relative_path=relative,
                evidence_assessment='RECORDED_ROUTE_OUTPUT_NOT_CAUSAL_OR_APPROVAL_PROOF',
            )
            return verify_route_document(con, db, design_id, revision, scope)
    except BaseException:
        for file in created:
            file.unlink(missing_ok=True)
        raise
