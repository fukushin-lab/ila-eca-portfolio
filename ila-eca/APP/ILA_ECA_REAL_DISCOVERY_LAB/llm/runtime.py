"""Guarded local transport, model profile and capacity checks."""

from __future__ import annotations
from contextlib import contextmanager
import socket
import ipaddress
import json
import math

DEFAULT_RESPONSE_BYTES = 8 * 1024 * 1024

DEFAULT_READ_BYTES = 8 * 1024 * 1024


def positive_int(value, code):
    if type(value) is not int or value <= 0:
        raise ValueError(code)
    return value


def positive_seconds(value, code):
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError(code)
    return value


def context_assessment(prompt, schema, *, context_tokens, output_tokens, input_tokens=None):
    """Return token quantities, never treat byte length as a measured token count.

    Without a trusted tokenizer, UTF-8 bytes plus framing are a conservative
    token upper estimate for the byte-fallback models used here. Exceeding this
    estimate is NOT proof the real request cannot fit: token measurement is
    required. A caller may supply a trusted measured count; model output cannot.
    """
    positive_int(context_tokens, 'MODEL_CONTEXT_INVALID')
    positive_int(output_tokens, 'MODEL_OUTPUT_INVALID')
    if input_tokens is not None:
        if type(input_tokens) is not int or input_tokens < 0:
            raise ValueError('MODEL_INPUT_TOKEN_COUNT_INVALID')
        count = input_tokens
        kind = 'MEASURED_INPUT_TOKENS'
    else:
        input_bytes = len(prompt.encode('utf8')) + len(
            json.dumps(schema, ensure_ascii=False).encode('utf8')
        )
        count = input_bytes + 1024
        kind = 'CONSERVATIVE_UTF8_TOKEN_UPPER_ESTIMATE_NOT_MEASURED'
    return {
        'input_tokens_or_upper_estimate': count,
        'input_count_kind': kind,
        'output_reservation_tokens': output_tokens,
        'context_tokens': context_tokens,
        'within_budget': count + output_tokens <= context_tokens,
    }


def require_context(prompt, schema, *, context_tokens, output_tokens, input_tokens=None):
    assessment = context_assessment(
        prompt,
        schema,
        context_tokens=context_tokens,
        output_tokens=output_tokens,
        input_tokens=input_tokens,
    )
    if output_tokens > context_tokens:
        raise ValueError('INCIDENT_CONFIGURED_CONTEXT_TOO_SMALL_NO_TRUNCATION')
    if not assessment['within_budget']:
        code = (
            'INCIDENT_CONFIGURED_CONTEXT_TOO_SMALL_NO_TRUNCATION'
            if input_tokens is not None
            else 'INCIDENT_INPUT_TOKEN_MEASUREMENT_REQUIRED_NO_TRUNCATION'
        )
        raise ValueError(code)
    return assessment


def verify_installed_context(model, context_tokens):
    """Only enlarged legacy-local contexts need metadata; never download a model."""
    if context_tokens <= 32768:
        return
    from urllib import request as http

    class NoRedirect(http.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise PermissionError('LOCAL_MODEL_METADATA_REDIRECT_DENIED')

    req = http.Request(
        'http://127.0.0.1:11434/api/show',
        data=json.dumps({'model': model}).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with http.build_opener(http.ProxyHandler({}), NoRedirect()).open(req, timeout=15) as response:
        raw = response.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('LOCAL_MODEL_METADATA_OVER_LIMIT')
    info = json.loads(raw).get('model_info', {})
    limits = [
        v for k, v in info.items() if k.endswith('.context_length') and type(v) is int and v > 0
    ]
    if not limits:
        raise ValueError('LOCAL_MODEL_CONTEXT_NOT_VERIFIED')
    if context_tokens > min(limits):
        raise ValueError('LOCAL_MODEL_ADVERTISED_CONTEXT_EXCEEDED')


from urllib import request

LOCAL_ENDPOINT = 'http://127.0.0.1:11434/api/generate'

ALLOWED_MODELS = frozenset(('qwen3:4b', 'qwen3:8b'))


class LocalOllamaError(ValueError):
    """A bounded, redacted transport failure: no prompts or responses logged."""


def request_json(
    *,
    prompt: str,
    schema: dict,
    model: str = 'qwen3:4b',
    endpoint: str = LOCAL_ENDPOINT,
    timeout: int = 90,
    num_predict: int = 512,
    max_http_bytes: int = DEFAULT_RESPONSE_BYTES,
    max_final_chars: int | None = None,
    opener=None,
    num_ctx: int | None = None,
    options: dict | None = None,
) -> object:
    """Generate strict structured data using the fixed localhost Ollama API.

    The caller MUST independently validate the returned data structure and its
    authority before acting.  No fallback response or model-issued command.
    """
    if endpoint != LOCAL_ENDPOINT or model not in ALLOWED_MODELS:
        raise ValueError('ONLY_LOCAL_OLLAMA_ALLOWED')
    # Design proposals can take minutes when the local model partly uses CPU.
    # Existing callers keep their original 90/180-second limits unless explicit.
    positive_seconds(timeout, 'OLLAMA_TIMEOUT_OUT_OF_RANGE')
    if not isinstance(num_predict, int) or isinstance(num_predict, bool) or not 0 < num_predict:
        raise ValueError('OLLAMA_NUM_PREDICT_OUT_OF_RANGE')
    if (
        type(max_http_bytes) is not int
        or not 0 < max_http_bytes
        or (
            max_final_chars is not None
            and (type(max_final_chars) is not int or max_final_chars <= 0)
        )
    ):
        raise ValueError('OLLAMA_RESPONSE_LIMIT_INVALID')
    if not isinstance(prompt, str) or not prompt or not isinstance(schema, dict):
        raise ValueError('OLLAMA_PROMPT_OR_SCHEMA_INVALID')
    if num_ctx is not None and (type(num_ctx) is not int or not 1024 <= num_ctx):
        raise ValueError('OLLAMA_CONTEXT_OUT_OF_RANGE')
    if num_ctx is not None:
        require_context(prompt, schema, context_tokens=num_ctx, output_tokens=num_predict)
        verify_installed_context(model, num_ctx)
    if opener is None:
        opener = request.urlopen
    runtime_options = {'temperature': 0, 'num_predict': num_predict}
    if num_ctx is not None:
        runtime_options['num_ctx'] = num_ctx
    if options is not None:
        from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import IncidentModelProfile

        checked = IncidentModelProfile(model=model, options=options)
        if checked.options['num_predict'] != num_predict or checked.options['num_ctx'] != num_ctx:
            raise ValueError('OLLAMA_OPTIONS_CAPACITY_MISMATCH')
        runtime_options = checked.options
    payload = (
        json.dumps(
            {
                'model': model,
                'stream': False,
                'think': False,
                'format': schema,
                'prompt': prompt,
                'options': runtime_options,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(',', ':'),
        )
        + '\n'
    ).encode('utf-8')
    req = request.Request(
        endpoint, data=payload, method='POST', headers={'Content-Type': 'application/json'}
    )
    with opener(req, timeout=timeout) as response:
        data = response.read(max_http_bytes + 1)
    if len(data) > max_http_bytes:
        raise LocalOllamaError('OLLAMA_RESPONSE_OVER_LIMIT')
    try:
        envelope = json.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LocalOllamaError('OLLAMA_HTTP_BODY_INVALID_JSON') from exc
    if not isinstance(envelope, dict):
        raise LocalOllamaError('OLLAMA_HTTP_BODY_NOT_OBJECT')
    raw = envelope.get('response')
    reason = str(envelope.get('done_reason', 'unknown'))[:48]
    eval_count = envelope.get('eval_count')
    eval_count = eval_count if type(eval_count) is int else 'unknown'
    # No response body, source content, credentials or model thoughts in failures.
    meta = f'done_reason={reason};eval_count={eval_count};thinking_present={bool(envelope.get("thinking"))}'
    if not isinstance(raw, str) or not raw.strip():
        raise LocalOllamaError('OLLAMA_EMPTY_FINAL_RESPONSE: ' + meta)
    if max_final_chars is not None and len(raw) > max_final_chars:
        raise LocalOllamaError('OLLAMA_FINAL_RESPONSE_OVER_LIMIT: ' + meta)
    if envelope.get('done') is False:
        raise LocalOllamaError('OLLAMA_INCOMPLETE_GENERATION: ' + meta)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LocalOllamaError('OLLAMA_FINAL_NOT_JSON: ' + meta) from exc


from dataclasses import dataclass, field

from urllib import request as http

import copy
import re

from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest


def open_local(request, timeout):
    if request.full_url != LOCAL_ENDPOINT:
        raise PermissionError('INCIDENT_LOCAL_EXECUTION_ENVIRONMENT_REQUIRED')

    class NoRedirect(http.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise PermissionError('INCIDENT_MODEL_REDIRECT_DENIED')

    return http.build_opener(http.ProxyHandler({}), http.HTTPHandler(), NoRedirect()).open(
        request, timeout=timeout
    )


@dataclass(frozen=True)
class IncidentModelProfile:
    model: str = 'qwen3:8b'
    allowed_models: tuple = ('qwen3:4b', 'qwen3:8b')
    expected_digest: str | None = None
    endpoint: str = LOCAL_ENDPOINT
    environment: str = 'ISOLATED_LAB'
    timeout: float = 480
    max_http_bytes: int = DEFAULT_RESPONSE_BYTES
    options: dict = field(
        default_factory=lambda: {'temperature': 0, 'num_ctx': 32768, 'num_predict': 4096}
    )

    def __post_init__(self):
        if self.environment != 'ISOLATED_LAB' or self.endpoint != LOCAL_ENDPOINT:
            raise PermissionError('INCIDENT_LOCAL_EXECUTION_ENVIRONMENT_REQUIRED')
        if (
            type(self.allowed_models) not in (list, tuple)
            or not 1 <= len(self.allowed_models) <= 16
            or self.model not in self.allowed_models
            or any(
                not isinstance(m, str)
                or not re.fullmatch(r'[A-Za-z0-9_.:/-]{1,120}', m)
                or 'cloud' in m.lower()
                for m in self.allowed_models
            )
        ):
            raise PermissionError('INCIDENT_MODEL_NOT_EXPLICITLY_ALLOWED')
        if self.expected_digest is not None and not re.fullmatch(
            r'[a-f0-9]{64}', self.expected_digest
        ):
            raise ValueError('INCIDENT_MODEL_DIGEST_INVALID')
        if (
            type(self.timeout) not in (int, float)
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise ValueError('INCIDENT_MODEL_TIMEOUT_INVALID')
        if type(self.max_http_bytes) is not int or self.max_http_bytes <= 0:
            raise ValueError('INCIDENT_MODEL_RESPONSE_LIMIT_INVALID')
        rules = {
            'num_ctx': (int, 1024, float('inf')),
            'num_predict': (int, 1, float('inf')),
            'temperature': ((int, float), 0, 2),
            'seed': (int, 0, 2147483647),
            'top_k': (int, 1, float('inf')),
            'top_p': ((int, float), 0, 1),
            'repeat_penalty': ((int, float), 0, 2),
        }
        if (
            type(self.options) is not dict
            or not {'num_ctx', 'num_predict', 'temperature'} <= self.options.keys()
            or set(self.options) - rules.keys()
        ):
            raise ValueError('INCIDENT_MODEL_OPTIONS_INVALID')
        for k, v in self.options.items():
            kind, lo, hi = rules[k]
            if (
                isinstance(v, bool)
                or not isinstance(v, kind)
                or not math.isfinite(v)
                or not lo <= v <= hi
            ):
                raise ValueError('INCIDENT_MODEL_OPTIONS_INVALID')
        object.__setattr__(self, 'options', copy.deepcopy(self.options))
        object.__setattr__(self, 'allowed_models', tuple(self.allowed_models))

    def as_dict(self):
        return {
            'schema': 'ila.eca.incident-model-profile.v1',
            'model': self.model,
            'allowed_models': list(self.allowed_models),
            'expected_digest': self.expected_digest,
            'endpoint': self.endpoint,
            'environment': self.environment,
            'timeout': self.timeout,
            'max_http_bytes': self.max_http_bytes,
            'options': copy.deepcopy(self.options),
        }

    @classmethod
    def from_dict(cls, value):
        if (
            type(value) is not dict
            or value.get('schema') != 'ila.eca.incident-model-profile.v1'
            or set(value)
            != {
                'schema',
                'model',
                'allowed_models',
                'expected_digest',
                'endpoint',
                'environment',
                'timeout',
                'max_http_bytes',
                'options',
            }
        ):
            raise ValueError('INCIDENT_MODEL_PROFILE_INVALID')
        return cls(**{k: v for k, v in value.items() if k != 'schema'})


def generate(*, profile, prompt, schema, opener, text_output=False):
    # This scoped adapter permits only models explicitly selected by the trusted
    # operator profile. It does not change local_ollama.ALLOWED_MODELS or callers.
    checked = IncidentModelProfile.from_dict(profile.as_dict())
    if not isinstance(prompt, str) or not prompt:
        raise ValueError('OLLAMA_PROMPT_OR_SCHEMA_INVALID')
    require_context(
        prompt,
        schema,
        context_tokens=checked.options['num_ctx'],
        output_tokens=checked.options['num_predict'],
    )
    verify_installed_context(checked.model, checked.options['num_ctx'])
    payload = {
        'model': checked.model,
        'stream': False,
        'think': False,
        'format': schema,
        'prompt': prompt,
        'options': copy.deepcopy(checked.options),
    }
    if schema is None:
        payload.pop('format')
    req = http.Request(
        checked.endpoint,
        data=json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')
        ).encode(),
        method='POST',
        headers={'Content-Type': 'application/json'},
    )
    with opener(req, timeout=checked.timeout) as response:
        raw = response.read(checked.max_http_bytes + 1)
    if len(raw) > checked.max_http_bytes:
        raise LocalOllamaError('OLLAMA_RESPONSE_OVER_LIMIT')
    try:
        envelope = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError):
        raise LocalOllamaError('OLLAMA_HTTP_BODY_INVALID_JSON') from None
    if type(envelope) is not dict:
        raise LocalOllamaError('OLLAMA_HTTP_BODY_NOT_OBJECT')
    final = envelope.get('response')
    if not isinstance(final, str) or not final.strip():
        raise LocalOllamaError('OLLAMA_EMPTY_FINAL_RESPONSE')
    if envelope.get('done') is False:
        raise LocalOllamaError('OLLAMA_INCOMPLETE_GENERATION')
    if text_output:
        return final
    try:
        return json.loads(final)
    except ValueError:
        raise LocalOllamaError('OLLAMA_FINAL_NOT_JSON') from None


def metrics(trace, *, failure_stage=None):
    if 'cloud_result' in trace:
        result = trace['cloud_result']
        usage = result.get('usage') or {}
        return {
            'provider': 'OPENAI',
            'model': trace.get('model'),
            'profile': trace.get('profile'),
            'input_tokens': usage.get('input_tokens'),
            'output_tokens': usage.get('output_tokens'),
            'http_status': result.get('http_status'),
            'failure_stage': failure_stage,
            'raw_response_state': 'RECEIVED' if result.get('response_base64') else 'NOT_RECEIVED',
            'dispatch_state': result.get('dispatch_state'),
            'elapsed_seconds': result.get('elapsed_seconds'),
            'transport_calls': result.get('transport_calls'),
            'actual_llm_calls': result.get('actual_llm_calls'),
            'execution_kind': result.get('execution_kind'),
            'count_definition': 'CLOUD_TRANSPORT_ATTEMPTS_WITH_PROVIDER_USAGE_NOT_LOCAL_OLLAMA_METRICS',
        }
    exchange = trace.get('exchange', {})
    request = exchange.get('request', {})
    response = exchange.get('response', {})
    if not isinstance(response, dict):
        response = {}

    def count(name):
        n = response.get(name)
        return n if type(n) is int and n >= 0 else None

    return {
        'model': trace.get('model'),
        'model_digest': trace.get('model_digest'),
        'profile': trace.get('profile'),
        'profile_sha256': data_digest(trace['profile']) if trace.get('profile') else None,
        'generation_settings': request.get('options', (trace.get('profile') or {}).get('options')),
        'input_tokens': count('prompt_eval_count'),
        'output_tokens': count('eval_count'),
        'provider_total_duration_ns': count('total_duration'),
        'provider_prompt_duration_ns': count('prompt_eval_duration'),
        'provider_generation_duration_ns': count('eval_duration'),
        'completion_reason': response.get('done_reason'),
        'http_status': exchange.get('http_status'),
        'failure_stage': failure_stage,
        'raw_response_state': (
            ('RECEIVED' if exchange['response_body'].get('complete_response', True) else 'PARTIAL')
            if exchange.get('response_body')
            else 'NOT_RECEIVED'
        ),
        'count_definition': 'LOCAL_GENERATION_HTTP_REQUEST_ATTEMPTS_NOT_PROVIDER_BILLING',
    }


@contextmanager
def deny_external_egress():
    """Test-only process-level guard; permits 127.0.0.0/8 and ::1.

    Not an OS firewall, VPC isolation, or a production security boundary.
    """
    original = socket.socket.connect

    def guarded(sock, address):
        host = address[0] if isinstance(address, tuple) else ''
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
        if not local:
            raise PermissionError('CLOSED_DOMAIN_EXTERNAL_EGRESS_DENIED')
        return original(sock, address)

    socket.socket.connect = guarded
    try:
        yield
    finally:
        socket.socket.connect = original
