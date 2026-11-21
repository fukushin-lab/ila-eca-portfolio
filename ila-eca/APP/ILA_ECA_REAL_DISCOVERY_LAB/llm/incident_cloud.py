"""Opt-in online C reasoner; reuse the same investigation and evidence.

An operator authorization binds the complete incident manifest and explicitly
permits the selected adapters' future results to leave this LAB. It is not
inferred from read permission, a model answer, or the word 'lab'.
"""

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import copy
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect
from ILA_ECA_REAL_DISCOVERY_LAB.llm import cloud as cloud
from ILA_ECA_REAL_DISCOVERY_LAB.incident import reasoner as ir
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest

MODEL = 'gpt-6.2-astra'


@dataclass(frozen=True)
class IncidentCloudRuntime:
    authorization: dict
    transport: object
    execution_kind: str = 'LIVE'
    max_output_tokens: int | None = None


def validate_authorization(record, manifest, *, check_expiry=True):
    keys = {
        'schema',
        'scope',
        'case_id',
        'manifest_sha256',
        'approved_by',
        'expires_at',
        'classification',
        'external_send_permitted',
        'include_read_results',
    }
    if type(record) is not dict or set(record) != keys:
        raise PermissionError('INCIDENT_CLOUD_EXPORT_RECORD_REQUIRED')
    if (
        record['schema'] != 'ila.eca.incident-cloud-authorization.v1'
        or record['scope'] != 'lab'
        or manifest['request']['scope'] != 'lab'
        or record['case_id'] != manifest['request']['request_id']
        or record['manifest_sha256'] != data_digest(manifest)
        or record['external_send_permitted'] is not True
        or record['include_read_results'] is not True
        or record['classification'] not in {'SYNTHETIC_ONLINE', 'OPERATOR_CARRIED_ONLINE'}
        or type(record['approved_by']) is not str
        or not record['approved_by'].strip()
    ):
        raise PermissionError('INCIDENT_CLOUD_EXPORT_BINDING_MISMATCH')
    try:
        expiry = datetime.fromisoformat(record['expires_at'])
    except (ValueError, TypeError):
        raise PermissionError('INCIDENT_CLOUD_EXPORT_EXPIRY_INVALID') from None
    if expiry.tzinfo is None or (check_expiry and expiry <= datetime.now(timezone.utc)):
        raise PermissionError('INCIDENT_CLOUD_EXPORT_EXPIRED')


class CloudIncidentReasoner:
    origin = 'OPENAI_ASTRA_ONLINE'
    require_evaluation_slot = True
    include_all_context = True  # No 8B-specific character truncation on this path.

    def __init__(self, db, manifest, runtime):
        if type(runtime) is not IncidentCloudRuntime or not callable(runtime.transport):
            raise PermissionError('INCIDENT_CLOUD_TRUSTED_RUNTIME_REQUIRED')
        validate_authorization(runtime.authorization, manifest, check_expiry=False)
        if runtime.execution_kind not in {'LIVE', 'HISTORICAL_REPLAY', 'MOCK'}:
            raise ValueError('INCIDENT_CLOUD_EXECUTION_KIND_INVALID')
        self.db = Path(db)
        self.manifest = copy.deepcopy(manifest)
        self.runtime = runtime
        self.origin = (
            'OPENAI_ASTRA_ONLINE'
            if runtime.execution_kind == 'LIVE'
            else 'OPENAI_ASTRA_' + runtime.execution_kind
        )

    def execution_identity(self):
        return {
            'provider': 'OPENAI',
            'model': MODEL,
            'endpoint': cloud.ENDPOINT,
            'settings': cloud.generation_settings(self.runtime.max_output_tokens),
            'authorization_sha256': data_digest(self.runtime.authorization),
            'manifest_sha256': data_digest(self.manifest),
            'execution_kind': self.runtime.execution_kind,
        }

    def assess(self, context):
        result = None
        request = None
        try:
            validate_authorization(self.runtime.authorization, self.manifest)
            if context['case_id'] != self.manifest['request']['request_id']:
                raise PermissionError('INCIDENT_CLOUD_CASE_CHANGED')
            request = {
                'model': MODEL,
                'input': [
                    {'role': 'system', 'content': ir.INSTRUCTION},
                    {
                        'role': 'user',
                        'content': canonical_json(
                            {'context': context, 'output_schema': ir.generation_schema(context)}
                        ),
                    },
                ],
                **cloud.generation_settings(self.runtime.max_output_tokens),
            }
            # Bind provider deduplication to the engine's durable model attempt.
            # Viewing a saved case never creates an attempt. An explicit resume
            # after a failed call has a new token and retains the old exchange.
            # The attempt identifier is control metadata, not model input.
            attempt = None
            with closing(connect(self.db)) as con:
                exists = con.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='incident_case_head_v1'"
                ).fetchone()
                row = (
                    con.execute(
                        'SELECT e.payload_json FROM incident_case_head_v1 h JOIN evidence e ON e.evidence_id=h.head_evidence_id WHERE h.request_id=?',
                        (context['case_id'],),
                    ).fetchone()
                    if exists
                    else None
                )
                pending = cloud.parse(row[0])['state'].get('pending') if row else None
                if pending and pending['kind'] == 'MODEL':
                    attempt = pending['token']
            rid = 'C-' + data_digest([context['case_id'], context, attempt])[:48]
            record = self.runtime.authorization
            exact = {
                'schema': 'ila.eca.cloud-export-authorization.v1',
                'scope': 'lab',
                'request_id': rid,
                'endpoint': cloud.ENDPOINT,
                'model': MODEL,
                'request_sha256': data_digest(request),
                'approved_by': record['approved_by'],
                'expires_at': record['expires_at'],
                'classification': record['classification'],
                'external_send_permitted': True,
            }
            runtime = cloud.CloudRuntime(exact, self.runtime.transport, self.runtime.execution_kind)
            result = cloud.infer_cloud(
                self.db, scope='lab', route='C', request_id=rid, request=request, runtime=runtime
            )
            if result['status'] != 'GENERATED':
                raise ValueError('INCIDENT_CLOUD_GENERATION_FAILED')
            # Parse/validate original response; no field repair or causal inference here.
            value = cloud.parse(result['value'])
            ir.validate(value, context)
            return {
                'value': value,
                'trace': self._trace(request, result),
                'actual_llm_calls': result['actual_llm_calls'],
                'origin': self.origin,
            }
        except BaseException as exc:
            result = result or getattr(exc, 'route_call', None)
            exc.incident_trace = self._trace(request, result)
            if isinstance(exc, Exception):
                code = str(exc)
                exc.incident_error_code = (
                    code
                    if isinstance(exc, (ValueError, PermissionError))
                    and code.startswith(('INCIDENT_', 'READ_', 'CLOUD_'))
                    else 'INCIDENT_CLOUD_' + type(exc).__name__.upper()
                )
            raise

    def _trace(self, request, result):
        trace = {
            'model': MODEL,
            'profile': self.execution_identity(),
            'origin': self.origin,
            'actual_llm_calls': result['actual_llm_calls'] if result else 0,
            'exchange': {'request': request} if request else {},
        }
        if result:
            trace['cloud_result'] = copy.deepcopy(result)
            trace['cloud_result_evidence_id'] = result['evidence_id']
            trace['failure_stage'] = result.get('error_code')
        return trace


def runtime_from_config(path, config, *, key_provider):
    if not {'schema', 'incident_authorization_path'} <= set(config) or set(config) - {
        'schema',
        'incident_authorization_path',
        'max_output_tokens',
        'timeout_seconds',
    }:
        raise ValueError('INCIDENT_CLOUD_CONFIG_INVALID')

    def local(name):
        value = Path(config[name])
        return value if value.is_absolute() else Path(path).parent / value

    cloud.generation_settings(config.get('max_output_tokens'))
    return IncidentCloudRuntime(
        cloud.read_authorization(local('incident_authorization_path')),
        cloud.OpenAITransport(key_provider, timeout=config.get('timeout_seconds', 900)),
        'LIVE',
        config.get('max_output_tokens'),
    )
