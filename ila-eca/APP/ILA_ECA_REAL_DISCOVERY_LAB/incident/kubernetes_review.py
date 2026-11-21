"""Typed Kubernetes Service-port proposals for existing review, never execution.

Observed snapshots are document inputs, not effective Baselines. No product,
approval, execution or Baseline mutation is implemented by this module.
"""

from pathlib import Path
import copy
import json
import re
import sqlite3

from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest, canonical_json
from ILA_ECA_REAL_DISCOVERY_LAB.design.change import resolve

KIND = 'KUBERNETES_REVIEW_ONLY'
SCHEMA = 'ila.eca.kubernetes-service-port-change.v1'
CONTEXT_SCHEMA = 'ila.eca.kubernetes-review-context.v1'
ORIGIN = 'OBSERVED_SNAPSHOT_NOT_EFFECTIVE_BASELINE'
_META = {'name', 'namespace', 'uid', 'generation', 'creationTimestamp'}
_SPEC = {'type', 'clusterIP', 'selector', 'ports'}
_PORT = {'name', 'protocol', 'port', 'targetPort', 'nodePort', 'appProtocol'}
_CONTEXT = {
    'schema',
    'case_id',
    'case_head',
    'candidate_decision_id',
    'report_design_id',
    'report_revision',
    'artifact_sha256',
    'observation',
    'cluster_ref',
    'source_scope',
    'basis_role',
}


def _text(value, label):
    if type(value) is not str or not value.strip() or len(value) > 300:
        raise ValueError('KUBERNETES_REVIEW_INVALID_' + label)


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _port(value):
    if type(value) is int:
        return 1 <= value <= 65535
    return (
        type(value) is str
        and 1 <= len(value) <= 15
        and re.fullmatch('[a-z0-9]+(?:-[a-z0-9]+)*', value) is not None
        and any(c.isalpha() for c in value)
    )


def _service(value, resource):
    if type(value) is not dict or set(value) != {'metadata', 'spec'}:
        raise ValueError('KUBERNETES_REVIEW_SERVICE_PROJECTION_REQUIRED')
    meta, spec = value['metadata'], value['spec']
    if (
        type(meta) is not dict
        or not {'name', 'namespace', 'uid'} <= set(meta)
        or set(meta) - _META
        or any(meta[k] != resource[k] for k in ('name', 'namespace', 'uid'))
    ):
        raise ValueError('KUBERNETES_REVIEW_RESOURCE_IDENTITY_MISMATCH')
    if 'generation' in meta and (type(meta['generation']) is not int or meta['generation'] < 0):
        raise ValueError('KUBERNETES_REVIEW_INVALID_GENERATION')
    if 'creationTimestamp' in meta:
        _text(meta['creationTimestamp'], 'CREATION_TIME')
    if type(spec) is not dict or 'ports' not in spec or set(spec) - _SPEC:
        raise ValueError('KUBERNETES_REVIEW_SPEC_PROJECTION_REQUIRED')
    if 'selector' in spec and (
        type(spec['selector']) is not dict
        or any(type(k) is not str or type(v) is not str for k, v in spec['selector'].items())
    ):
        raise ValueError('KUBERNETES_REVIEW_INVALID_SELECTOR')
    if any(type(spec[k]) is not str for k in ('type', 'clusterIP') if k in spec):
        raise ValueError('KUBERNETES_REVIEW_INVALID_SERVICE_FIELD')
    ports = spec['ports']
    if type(ports) is not list or not ports:
        raise ValueError('KUBERNETES_REVIEW_NONEMPTY_PORTS_REQUIRED')
    keys = []
    for port in ports:
        if (
            type(port) is not dict
            or not {'protocol', 'port', 'targetPort'} <= set(port)
            or set(port) - _PORT
            or type(port['port']) is not int
            or not 1 <= port['port'] <= 65535
            or type(port['protocol']) is not str
            or port['protocol'] not in {'TCP', 'UDP', 'SCTP'}
            or not _port(port['targetPort'])
        ):
            raise ValueError('KUBERNETES_REVIEW_INVALID_PORT_PROJECTION')
        if 'name' in port:
            _text(port['name'], 'PORT_NAME')
        if 'nodePort' in port and (
            type(port['nodePort']) is not int or not 1 <= port['nodePort'] <= 65535
        ):
            raise ValueError('KUBERNETES_REVIEW_INVALID_NODE_PORT')
        if 'appProtocol' in port:
            _text(port['appProtocol'], 'APP_PROTOCOL')
        keys.append((port.get('name'), port['protocol'], port['port']))
    if len(set(keys)) != len(keys):
        raise ValueError('KUBERNETES_REVIEW_DUPLICATE_PORT_IDENTITY')


def validate_spec(spec):
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.recovery import SCHEMA as SELECTOR_SCHEMA
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.recovery import validate_selector_spec

    if isinstance(spec, dict) and spec.get('schema') == SELECTOR_SCHEMA:
        return validate_selector_spec(spec)
    if (
        type(spec) is not dict
        or set(spec) != {'schema', 'scope', 'resource', 'before', 'after'}
        or spec['schema'] != SCHEMA
        or spec['scope'] != 'lab'
    ):
        raise ValueError('KUBERNETES_REVIEW_EXACT_TYPED_SPEC_REQUIRED')
    resource = spec['resource']
    if (
        type(resource) is not dict
        or set(resource) != {'apiVersion', 'kind', 'cluster_ref', 'namespace', 'name', 'uid'}
        or resource['apiVersion'] != 'v1'
        or resource['kind'] != 'Service'
    ):
        raise ValueError('KUBERNETES_REVIEW_SERVICE_RESOURCE_REQUIRED')
    for key in ('cluster_ref', 'namespace', 'name', 'uid'):
        _text(resource[key], key.upper())
    _service(spec['before'], resource)
    _service(spec['after'], resource)
    before, after = copy.deepcopy(spec['before']), copy.deepcopy(spec['after'])
    prior = [p.pop('targetPort') for p in before['spec']['ports']]
    intended = [p.pop('targetPort') for p in after['spec']['ports']]
    if canonical_json(before) != canonical_json(after) or canonical_json(prior) == canonical_json(
        intended
    ):
        raise ValueError('KUBERNETES_REVIEW_ONLY_TARGET_PORT_DIFFERENCE_ALLOWED')
    canonical_json(spec)
    return spec


def validate_context(context):
    if (
        type(context) is not dict
        or set(context) != _CONTEXT
        or context['schema'] != CONTEXT_SCHEMA
        or context['source_scope'] != 'lab'
        or context['basis_role'] != ORIGIN
        or type(context['report_revision']) is not int
        or context['report_revision'] < 1
        or not _sha(context['artifact_sha256'])
    ):
        raise ValueError('KUBERNETES_REVIEW_EXACT_CONTEXT_REQUIRED')
    for key in ('case_id', 'case_head', 'candidate_decision_id', 'report_design_id', 'cluster_ref'):
        _text(context[key], key.upper())
    observation = context['observation']
    if (
        type(observation) is not dict
        or set(observation) != {'evidence_id', 'path', 'record_sha256', 'field_sha256'}
        or not _sha(observation['record_sha256'])
        or not _sha(observation['field_sha256'])
        or type(observation['path']) is not str
        or not observation['path'].startswith('/values/fields/')
        or len(observation['path']) > 1000
    ):
        raise ValueError('KUBERNETES_REVIEW_EXACT_OBSERVATION_REFERENCE_REQUIRED')
    _text(observation['evidence_id'], 'EVIDENCE_ID')
    canonical_json(context)
    return context


def verify_context(con, db, change):
    """Verify historical report/candidate/receipt and return a virtual doc base.

    The current case head may advance after the referenced immutable report;
    neither that advancement nor the source snapshot activates any Baseline.
    """
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.artifacts import verify_report
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import Investigation
    from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import Principal

    value = dict(change)
    if (
        value.get('proposal_kind') != KIND
        or value.get('scope') != 'lab'
        or value.get('base_version') != 0
    ):
        raise ValueError('KUBERNETES_REVIEW_KIND_SCOPE_AND_UNBOUND_BASE_REQUIRED')
    spec = validate_spec(json.loads(value['intended_spec_json']))
    context = validate_context(json.loads(value['proposal_context_json']))
    if context['cluster_ref'] != spec['resource']['cluster_ref']:
        raise ValueError('KUBERNETES_REVIEW_CLUSTER_REFERENCE_CHANGED')
    report = verify_report(con, db, context['report_design_id'], context['report_revision'])
    state = report['data']['snapshot']
    record = report['record']
    candidate = next(
        (
            v
            for v in state['repair_candidates']
            if v['decision_id'] == context['candidate_decision_id']
        ),
        None,
    )
    if (
        record['domain_id'] != 'lab'
        or record['artifact_sha256'] != context['artifact_sha256']
        or report['data']['case_id'] != context['case_id']
        or report['data']['head_evidence_id'] != context['case_head']
        or state['status'] != 'WAITING_REPAIR'
        or candidate is None
        or state['scope'] != 'lab'
    ):
        raise ValueError('KUBERNETES_REVIEW_INCIDENT_REPORT_CANDIDATE_CHANGED')
    principal = Principal('KUBERNETES-CHANGE-REVIEW-READER')
    engine = Investigation.readonly(Path(db))
    current = engine.get(context['case_id'], principal)
    if candidate not in current['state']['repair_candidates']:
        raise ValueError('KUBERNETES_REVIEW_CANDIDATE_NOT_RETAINED')
    con.row_factory = sqlite3.Row
    decision = con.execute(
        'SELECT * FROM phase1_decision_ext_v1 WHERE decision_id=?',
        (context['candidate_decision_id'],),
    ).fetchone()
    if (
        decision is None
        or decision['request_id'] != context['case_id']
        or decision['subject_scope'] != 'lab'
    ):
        raise ValueError('KUBERNETES_REVIEW_DECISION_SCOPE_CHANGED')
    assessment = json.loads(decision['proposal_json']).get('assessment', {})
    if (
        assessment.get('next_mode') != 'PROPOSE_REPAIR'
        or assessment.get('repair') != candidate['proposal']
    ):
        raise ValueError('KUBERNETES_REVIEW_SAVED_CANDIDATE_CHANGED')
    observation = context['observation']
    engine.gateway.verify_evidence(observation['evidence_id'], principal=principal)
    source = con.execute(
        'SELECT * FROM evidence WHERE evidence_id=?', (observation['evidence_id'],)
    ).fetchone()
    if (
        source is None
        or source['scope'] != 'lab'
        or data_digest(dict(source)) != observation['record_sha256']
    ):
        raise ValueError('KUBERNETES_REVIEW_OBSERVATION_RECORD_CHANGED')
    payload = json.loads(source['payload_json'])
    if (
        payload.get('acquisition_state') != 'OBSERVED'
        or payload.get('basis_type') != 'OBSERVATION'
        or observation['evidence_id'] not in {f['evidence_id'] for f in report['data']['facts']}
    ):
        raise ValueError('KUBERNETES_REVIEW_SELECTED_OBSERVATION_REQUIRED')
    try:
        before = resolve(payload, observation['path'])
    except (ValueError, KeyError, IndexError, TypeError):
        raise ValueError('KUBERNETES_REVIEW_OBSERVATION_POINTER_MISSING') from None
    if data_digest(before) != observation['field_sha256'] or canonical_json(
        before
    ) != canonical_json(spec['before']):
        raise ValueError('KUBERNETES_REVIEW_BEFORE_DIFFERS_FROM_CAPTURE')
    return {
        'scope': 'lab',
        'version': 0,
        'spec': {**copy.deepcopy(spec), 'after': copy.deepcopy(spec['before'])},
        'origin': ORIGIN,
    }
