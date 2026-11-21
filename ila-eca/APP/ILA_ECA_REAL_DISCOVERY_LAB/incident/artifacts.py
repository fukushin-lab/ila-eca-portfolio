"""Render existing incident records; link candidates to existing change lifecycle.

The Phase1 LAB evidence namespace ('lab') and legacy lifecycle namespace are
explicitly bound only inside the existing isolated-LAB gateway. No arbitrary
domain mapping, enterprise approval, execution or automatic Baseline activation.
"""

from contextlib import closing
from hashlib import sha256
from pathlib import Path
import json
import re
import sqlite3
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, utc_now
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import (
    canonical_json,
    data_digest,
    render_template,
    register_document,
    validate_record,
    init_registry,
)
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import document_paths
from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import Investigation
from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import Principal, timestamp
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle import changes as lc

TEMPLATE = Path(__file__).resolve().parent.parent / 'templates/incident_investigation_v1.md.tpl'


def model_run_record(row, raw):
    record = {
        'evidence_id': row['evidence_id'],
        'record_sha256': data_digest(row),
        'status': raw['status'],
        'origin': raw['origin'],
        'actual_llm_calls': raw.get(
            'actual_llm_calls', raw.get('trace', {}).get('actual_llm_calls', 0)
        ),
        'model': raw.get('trace', {}).get('model'),
        'model_digest': raw.get('trace', {}).get('model_digest'),
        'elapsed_seconds': raw['elapsed_seconds'],
        'error_type': raw.get('error_type'),
        'error_code': raw.get('error_code'),
    }
    if 'metrics' in raw:
        record['metrics'] = raw['metrics']
    if 'call_count_state' in raw:
        record['call_count_state'] = raw['call_count_state']
    return record


def _baseline_binding(base, subject, version, spec):
    from ILA_ECA_REAL_DISCOVERY_LAB.design.change import resolve

    if (
        not base
        or base.get('scope') != lc.SCOPE
        or base.get('version') != version
        or base.get('spec_sha256') != data_digest(spec)
        or base.get('subject_ref') != subject
        or base.get('binding_origin') != 'EXPLICIT_LAB_CASE_INPUT_UNVERIFIED'
        or not isinstance(base.get('target_paths'), list)
        or not base['target_paths']
    ):
        raise ValueError('INCIDENT_EXPLICIT_BASELINE_SUBJECT_BINDING_REQUIRED')
    for path in base['target_paths']:
        try:
            resolve(spec, path)
        except (KeyError, IndexError, ValueError, TypeError):
            raise ValueError('INCIDENT_BASELINE_TARGET_PATH_MISSING') from None


def _material(db, case_id, head):
    engine = Investigation.readonly(db)
    case = engine.get(case_id, Principal('REPORT-READER'), head=head)
    s = case['state']
    if s['pending']:
        raise ValueError('INCIDENT_PENDING_OPERATION_CANNOT_BE_FINAL_REPORT')
    decisions = []
    actions = []
    models = []
    with closing(connect(db)) as con:
        con.row_factory = sqlite3.Row
        for did in s['decision_ids']:
            row = con.execute(
                'SELECT * FROM phase1_decision_ext_v1 WHERE decision_id=?', (did,)
            ).fetchone()
            decisions.append({'decision_id': did, 'proposal': json.loads(row['proposal_json'])})
        for aid in s['action_ids']:
            row = con.execute('SELECT * FROM phase1_action_v1 WHERE action_id=?', (aid,)).fetchone()
            actions.append(
                {
                    **dict(row),
                    'before_json': json.loads(row['before_json']),
                    'after_json': json.loads(row['after_json']),
                    'result_json': json.loads(row['result_json']),
                }
            )
        for eid in s['model_records']:
            row, raw = engine._raw(eid, Principal('REPORT-READER'))
            if row['adapter'] == 'incident_model_result_v1':
                models.append(model_run_record(row, raw))
    return {
        'schema': 'ila.eca.incident-investigation-report.v1',
        'case_id': case_id,
        'head_evidence_id': head,
        'snapshot': s,
        'facts': engine._facts(s, Principal('REPORT-READER')),
        'decisions': decisions,
        'actions': actions,
        'model_runs': models,
        'source_reference_integrity': 'VERIFIED',
        'causal_correctness': 'NOT_AUTOMATICALLY_PROVED',
        'enterprise_authority': False,
        'baseline_updated_by_report': False,
    }


def _body(data):
    def block(value):
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
        fence = '`' * max(3, max((len(x) for x in re.findall(r'`+', raw)), default=0) + 1)
        return fence + 'json\n' + raw + '\n' + fence

    s = data['snapshot']
    parts = [
        '## 症状・状態',
        s['incident']['symptom'],
        f"状態: {s['status']} / 理由: {s['reason']}",
        '実行結果・モデルの判断・実製品での妥当性は別の検証です。本文は保存済み記録から整形しています。',
        '## 対象・時刻・不足情報',
        block(s['incident']),
        '## 現在の仮説（モデルの評価）',
        block(s['hypotheses']),
        '## 撤回した仮説と理由',
        block(s['retired']),
        '## 判断ごとの根拠・次の調査・結果の解釈',
        block(data['decisions']),
        '## 元の項目パス・所属・時刻・条件・取得元付き証拠',
        block(data['facts']),
        '## 実施した読み取りと結果',
        block(data['actions']),
        '## 修復候補・既存変更との対応',
        block(
            {
                'candidates': s['repair_candidates'],
                'change_links': s['change_links'],
                'outcomes': s['repair_outcomes'],
            }
        ),
        '## モデル実行・失敗記録',
        block(data['model_runs']),
        '## 追跡情報',
        block(
            {
                'case_id': data['case_id'],
                'head_evidence_id': data['head_evidence_id'],
                'model_input_and_raw_response_evidence_ids': s['model_records'],
                'snapshot_sha256': data_digest(s),
                'source_reference_integrity': data['source_reference_integrity'],
                'causal_correctness': data['causal_correctness'],
                'enterprise_authority': False,
                'baseline_updated_by_report': False,
            }
        ),
    ]
    return '\n\n'.join(parts)


def create_report(db, case_id, principal):
    case = Investigation.readonly(db).get(case_id, principal)
    material = _material(db, case_id, case['head'])
    did = 'INCIDENT-' + data_digest(case_id)[:24]
    created = []
    try:
        with closing(connect(db)) as con, con:
            con.execute('BEGIN IMMEDIATE')
            init_registry(con)
            old = con.execute(
                'SELECT revision,relative_path,record_json FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? ORDER BY revision DESC LIMIT 1',
                ('lab', did),
            ).fetchone()
            template = TEMPLATE.read_bytes()
            renderer = sha256(__import__('inspect').getsource(_body).encode()).hexdigest()
            revision = old[0] if old else 1
            data = {
                **material,
                'design_id': did,
                'revision': revision,
                'template_sha256': sha256(template).hexdigest(),
                'renderer_sha256': renderer,
            }
            if old and data_digest(data) == json.loads(old[2])['structured_data_sha256']:
                return verify_report(con, db, did, revision)
            if old:
                revision += 1
                data['revision'] = revision
            relative = f'incident_reports/{did}_r{revision:04d}.md'
            md, path = document_paths(db, relative)
            md.parent.mkdir(parents=True, exist_ok=True)
            content, meta = render_template(
                template,
                {'case_id': case_id, 'revision': revision, 'body': _body(data)},
                template_version='incident-investigation-v1',
            )
            for file, raw in ((md, content), (path, canonical_json(data).encode())):
                with file.open('xb') as out:
                    created.append(file)
                    out.write(raw)
            record = register_document(
                con,
                domain_id='lab',
                design_id=did,
                document_kind='INCIDENT_INVESTIGATION',
                content=content,
                structured_data=data,
                render_metadata=meta,
                relative_path=relative,
                evidence_assessment='TRACEABLE_RECORD_NOT_CAUSAL_APPROVAL',
            )
            return {'record': record, 'data': data, 'path': str(md), 'structured_path': str(path)}
    except BaseException:
        for file in created:
            file.unlink(missing_ok=True)
        raise


def verify_report(con, db, design_id, revision):
    row = con.execute(
        'SELECT relative_path,record_json FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? AND revision=?',
        ('lab', design_id, revision),
    ).fetchone()
    if not row:
        raise ValueError('INCIDENT_REPORT_NOT_FOUND')
    md, path = document_paths(db, row[0])
    data = json.loads(path.read_bytes())
    record = json.loads(row[1])
    validate_record(record, content=md.read_bytes(), structured_data=data)
    material = _material(db, data['case_id'], data['head_evidence_id'])
    if (
        any(data[k] != v for k, v in material.items())
        or record['document_kind'] != 'INCIDENT_INVESTIGATION'
    ):
        raise ValueError('INCIDENT_REPORT_BINDING_CHANGED')
    return {'record': record, 'data': data, 'path': str(md), 'structured_path': str(path)}


def verify_repair_binding(con, db, binding, change):
    if lc.proposal_kind(change) != 'DOCKER_LAB':
        from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import verify_context

        verify_context(con, db, change)
        context = json.loads(change['proposal_context_json'])
        if (
            binding.get('change_id') != change['change_id']
            or binding.get('case_id') != context['case_id']
            or binding.get('candidate_decision_id') != context['candidate_decision_id']
            or binding.get('report_design_id') != context['report_design_id']
            or binding.get('report_revision') != context['report_revision']
            or binding.get('artifact_sha256') != context['artifact_sha256']
            or binding.get('intended_spec_sha256')
            != data_digest(json.loads(change['intended_spec_json']))
        ):
            raise ValueError('INCIDENT_KUBERNETES_REVIEW_BINDING_CHANGED')
        return verify_report(con, db, context['report_design_id'], context['report_revision'])
    report = verify_report(con, db, binding['report_design_id'], binding['report_revision'])
    s = report['data']['snapshot']
    base = s['incident']['baseline_ref']
    if (
        s['scope'] != 'lab'
        or change['scope'] != lc.SCOPE
        or binding['case_id'] != s['case_id']
        or report['record']['artifact_sha256'] != binding['artifact_sha256']
        or binding['change_id'] != change['change_id']
        or not base
        or base['scope'] != lc.SCOPE
        or base['version'] != change['base_version']
        or data_digest(json.loads(change['intended_spec_json'])) != binding['intended_spec_sha256']
        or binding['candidate_decision_id']
        not in {c['decision_id'] for c in s['repair_candidates']}
    ):
        raise ValueError('INCIDENT_REPAIR_BINDING_CHANGED')
    stored = con.execute(
        'SELECT spec_json FROM lifecycle_baseline_v1 WHERE scope=? AND version=?',
        (lc.SCOPE, base['version']),
    ).fetchone()
    if not stored or data_digest(json.loads(stored[0])) != base['spec_sha256']:
        raise ValueError('INCIDENT_BASELINE_BINDING_CHANGED')
    _baseline_binding(
        base, s['request']['subject_id'], change['base_version'], json.loads(stored[0])
    )
    return report


def propose_repair(engine, case_id, principal, *, change_id, intended_spec, proposal_context=None, execution_target=None):
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import SCHEMA
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.recovery import SCHEMA as SELECTOR_SCHEMA

    if isinstance(intended_spec, dict) and intended_spec.get('schema') in {SCHEMA, SELECTOR_SCHEMA}:
        return _propose_kubernetes_review(
            engine, case_id, principal, change_id, intended_spec, proposal_context, execution_target
        )
    if proposal_context is not None or execution_target is not None:
        raise ValueError('INCIDENT_UNEXPECTED_REVIEW_CONTEXT')
    case = engine.get(case_id, principal)
    s = case['state']
    existing = next((l for l in s['change_links'] if l['change_id'] == change_id), None)
    if existing:
        if existing['intended_spec_sha256'] != data_digest(intended_spec):
            raise ValueError('INCIDENT_REPAIR_CHANGED_REPLAY')
        lc.assert_change_integrity(engine.db, change_id)
        return lc.get_change(engine.db, change_id)
    if s['status'] != 'WAITING_REPAIR' or not s['repair_candidates']:
        raise ValueError('INCIDENT_REPAIR_CANDIDATE_REQUIRED')
    base = s['incident']['baseline_ref']
    current = lc.current_baseline(engine.db)
    if current['origin'] not in {
        'EXPLICIT_LAB_FIXTURE_NOT_AUTHORITY',
        'LAB_SIMULATED_ACCEPTED_NOT_ENTERPRISE_AUTHORITY',
    }:
        raise ValueError('INCIDENT_EXPLICIT_CURRENT_LAB_BASELINE_REQUIRED')
    _baseline_binding(base, s['request']['subject_id'], current['version'], current['spec'])
    report = create_report(engine.db, case_id, principal)
    candidate = s['repair_candidates'][-1]
    binding = {
        'case_id': case_id,
        'change_id': change_id,
        'candidate_decision_id': candidate['decision_id'],
        'report_design_id': report['record']['design_id'],
        'report_revision': report['record']['revision'],
        'artifact_sha256': report['record']['artifact_sha256'],
        'intended_spec_sha256': data_digest(intended_spec),
    }
    try:
        ch = lc.get_change(engine.db, change_id)
    except ValueError as exc:
        if 'Record not found' not in str(exc):
            raise
        ch = lc.propose_change(
            engine.db,
            change_id=change_id,
            requested_by=principal.ref,
            purpose=candidate['proposal']['reason'],
            intended_spec=intended_spec,
        )
    if (
        ch['intended_spec'] != intended_spec
        or ch['purpose'] != candidate['proposal']['reason']
        or ch['requested_by'] != principal.ref
    ):
        raise ValueError('INCIDENT_CHANGE_ID_CONFLICT')
    from ILA_ECA_REAL_DISCOVERY_LAB.design.change import create_template_draft

    p = candidate['proposal']
    details = {
        'incident_investigation_binding': binding,
        'impact': p['impact'],
        'verification': p['verification'],
        'rollback': p['rollback'],
        'unknowns': s['incident']['unknowns'],
        'construction': {
            'state': 'NOT_PERFORMED',
            'proposal': p['reason'],
            'target_spec_origin': 'EXPLICIT_CALLER_INPUT_NOT_INFERRED_BY_LOOP',
        },
    }
    if ch['status'] == 'DRAFT':
        create_template_draft(
            engine.db,
            change_id,
            author='MODEL_INCIDENT_CANDIDATE',
            design_origin='AI',
            details=details,
        )
    else:
        lc.assert_change_integrity(engine.db, change_id)
        with closing(connect(engine.db)) as con:
            row = con.execute(
                'SELECT structured_path FROM lifecycle_design_artifact_v2 WHERE change_id=?',
                (change_id,),
            ).fetchone()
        if (
            not row
            or json.loads((engine.db.parent / 'design_drafts_lab' / row[0]).read_bytes())['details']
            != details
        ):
            raise ValueError('INCIDENT_SUBMITTED_CHANGE_BINDING_CONFLICT')
    s['change_links'].append(binding)
    s.update(status='WAITING_REPAIR', reason='EXISTING_CHANGE_AWAITING_REVIEW')
    engine._commit(s, case['head'], 'EXISTING_CHANGE_LINKED', binding)
    return lc.get_change(engine.db, change_id)


def _propose_kubernetes_review(engine, case_id, principal, change_id, intended_spec, context, execution_target=None):
    """Submit the saved proposal to the existing queue, never to an executor."""
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import KIND
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import validate_spec
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import validate_context

    validate_spec(intended_spec)
    validate_context(context)
    case = engine.get(case_id, principal)
    s = case['state']
    if principal.scope != 'lab' or s['scope'] != 'lab' or context['case_id'] != case_id:
        raise PermissionError('INCIDENT_KUBERNETES_LAB_SCOPE_REQUIRED')
    existing = next((l for l in s['change_links'] if l['change_id'] == change_id), None)
    if existing:
        change = lc.get_change(engine.db, change_id)
        if (
            existing['intended_spec_sha256'] != data_digest(intended_spec)
            or lc.proposal_kind(change) != KIND
            or change['proposal_context'] != context
        ):
            raise ValueError('INCIDENT_REPAIR_CHANGED_REPLAY')
        lc.assert_change_integrity(engine.db, change_id)
        return change
    if s['status'] != 'WAITING_REPAIR' or not s['repair_candidates']:
        raise ValueError('INCIDENT_REPAIR_CANDIDATE_REQUIRED')
    candidate = s['repair_candidates'][-1]
    if (
        context['case_head'] != case['head']
        or context['candidate_decision_id'] != candidate['decision_id']
    ):
        raise ValueError('INCIDENT_CURRENT_KUBERNETES_CANDIDATE_REQUIRED')
    report = create_report(engine.db, case_id, principal)
    if (
        context['report_design_id'] != report['record']['design_id']
        or context['report_revision'] != report['record']['revision']
        or context['artifact_sha256'] != report['record']['artifact_sha256']
    ):
        raise ValueError('INCIDENT_KUBERNETES_REPORT_CONTEXT_CHANGED')
    change = lc.propose_review_change(
        engine.db,
        change_id=change_id,
        requested_by=principal.ref,
        purpose=candidate['proposal']['reason'],
        intended_spec=intended_spec,
        proposal_context=context,
    )
    binding = {
        'case_id': case_id,
        'change_id': change_id,
        'candidate_decision_id': candidate['decision_id'],
        'report_design_id': report['record']['design_id'],
        'report_revision': report['record']['revision'],
        'artifact_sha256': report['record']['artifact_sha256'],
        'intended_spec_sha256': data_digest(intended_spec),
    }
    p = candidate['proposal']
    assessment = next(
        d['proposal']['assessment']
        for d in report['data']['decisions']
        if d['decision_id'] == candidate['decision_id']
    )
    unknowns = list(
        dict.fromkeys(
            s['incident']['unknowns']
            + assessment['missing']
            + [
                item
                for h in assessment['hypotheses']
                if h['id'] in p['hypothesis_ids']
                for item in h['missing']
            ]
        )
    )
    details = {
        'incident_investigation_binding': binding,
        'document_reviews': [
            {'design_id': context['report_design_id'], 'revision': context['report_revision']}
        ],
        'impact': p['impact'],
        'verification': p['verification'],
        'rollback': p['rollback'],
        'unknowns': unknowns,
        'proposal_context': context,
        'construction': {
            'state': 'NOT_PERFORMED',
            'proposal': p['reason'],
            'target_spec_origin': 'EXPLICIT_CALLER_INPUT_NOT_INFERRED_BY_LOOP',
        },
        'evidence_assessment': 'OBSERVED_SNAPSHOT_NOT_EFFECTIVE_BASELINE',
    }
    if execution_target is not None:
        from ILA_ECA_REAL_DISCOVERY_LAB.incident.recovery import validate_execution_target

        validate_execution_target(execution_target, intended_spec)
        details['construction']['execution_target'] = execution_target
        details['construction']['execution_target_sha256'] = data_digest(execution_target)
    with closing(connect(engine.db)) as con:
        plans = con.execute(
            "SELECT evidence_id,payload_json FROM evidence WHERE adapter='incident_concrete_repair_plan_v1' "
            "AND json_extract(payload_json,'$.case_id')=? AND json_extract(payload_json,'$.spec_sha256')=?",
            (case_id, data_digest(intended_spec)),
        ).fetchall()
    if plans:
        if len(plans) != 1:
            raise ValueError('INCIDENT_CONCRETE_PLAN_BINDING_AMBIGUOUS')
        from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import load_evidence

        _, plan = load_evidence(engine.db, plans[0][0], 'lab')
        load_evidence(engine.db, plan['model_result_evidence_id'], 'lab')
        if plan['spec'] != intended_spec or plan['candidate_decision_id'] != candidate['decision_id']:
            raise ValueError('INCIDENT_CONCRETE_PLAN_BINDING_CHANGED')
        details['construction'].update(
            target_spec_origin='UNAPPROVED_MODEL_PLAN_DATA_NOT_APPLIED',
            concrete_plan_evidence_id=plans[0][0],
            concrete_plan_model_result_evidence_id=plan['model_result_evidence_id'],
        )
    from ILA_ECA_REAL_DISCOVERY_LAB.design.change import create_template_draft
    from ILA_ECA_REAL_DISCOVERY_LAB.design.change import prepare_details

    details = prepare_details(engine.db, change_id, details)
    if change['status'] == 'DRAFT':
        model = next(
            (
                r.get('model')
                for r in report['data']['model_runs']
                if r['evidence_id'] == candidate['model_result_evidence_id']
            ),
            None,
        )
        create_template_draft(
            engine.db,
            change_id,
            author='MODEL_INCIDENT_CANDIDATE',
            design_origin='AI',
            model_id=model,
            details=details,
        )
    else:
        lc.assert_change_integrity(engine.db, change_id)
        with closing(connect(engine.db)) as con:
            row = con.execute(
                'SELECT structured_path FROM lifecycle_design_artifact_v2 WHERE change_id=?',
                (change_id,),
            ).fetchone()
        if (
            not row
            or json.loads((engine.db.parent / 'design_drafts_lab' / row[0]).read_bytes())['details']
            != details
        ):
            raise ValueError('INCIDENT_SUBMITTED_CHANGE_BINDING_CONFLICT')
    s['change_links'].append(binding)
    s.update(status='WAITING_REPAIR', reason='EXISTING_CHANGE_AWAITING_REVIEW')
    engine._commit(s, case['head'], 'EXISTING_CHANGE_LINKED', binding)
    return lc.get_change(engine.db, change_id)


def check_repair(engine, case_id, verifier, *, change_id, operation_id):
    case = engine.get(case_id, verifier)
    s = case['state']
    ch = lc.get_change(engine.db, change_id)
    lc.assert_change_integrity(engine.db, change_id)
    if change_id not in {l['change_id'] for l in s['change_links']}:
        raise ValueError('INCIDENT_CHANGE_NOT_LINKED')
    if ch['status'] not in {'VERIFIED_LAB_ONLY', 'EFFECTIVE_LAB_ONLY'}:
        raise ValueError('EXISTING_INDEPENDENT_VERIFICATION_REQUIRED')
    if verifier.ref in {ch['implementation_actor'], ch['design_author']}:
        raise PermissionError('INDEPENDENT_SYMPTOM_VERIFIER_REQUIRED')
    op = engine.registry.get(operation_id, verifier)
    if op.kind != 'SYMPTOM_CHECK' or op.target_ref != s['request']['subject_id']:
        raise ValueError('ORIGINAL_SYMPTOM_CHECK_REQUIRED')
    inv = {
        'operation_id': operation_id,
        'query': '',
        'fact_refs': [],
        'information_needed': s['incident']['symptom'],
        'reason': 'Existing change verified; independently check the original symptom',
        'outcomes': [
            {'result': 'Present', 'interpretation': 'Continue the same case'},
            {'result': 'Absent', 'interpretation': 'LAB symptom recovery within check scope'},
        ],
        'hypothesis_ids': [],
        'basis_refs': [],
        'retry_reason': 'Post-repair independent symptom verification',
    }
    verification = json.loads(ch['verification_json'])
    eid = engine._publish(
        s['scope'],
        s['request']['subject_id'],
        'incident_existing_verification_v1',
        change_id,
        {'verification': verification},
    )
    decision = engine._decision(
        s,
        verifier,
        {
            'next_mode': 'INVESTIGATE',
            'investigation': inv,
            'missing': [],
            'assessment_origin': 'EXISTING_INDEPENDENT_VERIFICATION_NOT_LLM',
        },
        eid,
    )
    s.update(status='ACTIVE', reason='POST_REPAIR_SYMPTOM_CHECK')
    prepared = engine._commit(s, case['head'], 'SYMPTOM_CHECK_SELECTED')
    result = engine.execute_selected(
        case_id, verifier, inv, decision, expected_head=prepared['head']
    )
    s = result['state']
    if (
        s['pending']
        or not s['last_result']
        or len(s['action_ids']) <= len(case['state']['action_ids'])
    ):
        return result
    receipt = s['last_result'][-1]
    _, raw = engine._raw(receipt, verifier)
    symptom = raw.get('values', {}).get('symptom_status', 'UNOBSERVED')
    valid = (
        raw.get('acquisition_state') == 'OBSERVED'
        and raw.get('target_ref') == s['request']['subject_id']
        and timestamp(raw['source_observed_at']) >= timestamp(verification['verified_at_utc'])
        and raw.get('values', {}).get('symptom_ref') == case_id
        and raw.get('action_id') == s['action_ids'][-1]
        and lc.get_change(engine.db, change_id)['verification_json'] == ch['verification_json']
    )
    if not valid or symptom not in {'PRESENT', 'ABSENT'}:
        symptom = 'UNOBSERVED'
    s['repair_outcomes'].append(
        {
            'change_id': change_id,
            'symptom_status': symptom,
            'verifier': verifier.ref,
            'evidence_id': receipt,
            'lifecycle_verification_sha256': data_digest(verification),
            'checked_at': utc_now(),
        }
    )
    s.update(
        status=(
            'RESOLVED_LAB_ONLY'
            if symptom == 'ABSENT'
            else ('ACTIVE' if symptom == 'PRESENT' else 'HOLD')
        ),
        reason='ORIGINAL_SYMPTOM_' + symptom,
    )
    return engine._commit(s, result['head'], 'INDEPENDENT_SYMPTOM_RESULT')


def assert_symptom_resolved(db, binding, change):
    case = Investigation.readonly(db).get(binding['case_id'], Principal('ACCEPTANCE-READER'))
    s = case['state']
    matches = [o for o in s['repair_outcomes'] if o['change_id'] == change['change_id']]
    if (
        s['status'] != 'RESOLVED_LAB_ONLY'
        or not matches
        or matches[-1]['symptom_status'] != 'ABSENT'
        or matches[-1]['lifecycle_verification_sha256']
        != data_digest(json.loads(change['verification_json']))
    ):
        raise ValueError('INCIDENT_ORIGINAL_SYMPTOM_NOT_INDEPENDENTLY_RESOLVED')
