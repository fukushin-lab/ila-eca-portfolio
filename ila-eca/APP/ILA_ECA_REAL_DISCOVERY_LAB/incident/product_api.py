"""Explicitly opted-in GET-only, bounded AWX/K8s/GitLab/Prometheus adapters.

No discovery of targets from LLM text, no write operations, no redirects,
no raw API response persistence, no implied authentication or authority.
Default: only literal loopback. Remote HTTPS requires explicit CLI permission
and exact host allowlisting in a trusted local operator configuration.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import ipaddress
import json
import os
import re
import ssl
from urllib.parse import urlsplit
from urllib.request import (
    Request,
    build_opener,
    HTTPHandler,
    HTTPSHandler,
    HTTPRedirectHandler,
    ProxyHandler,
)


MAX_BODY = 256_000
MAX_CONFIG = 32_000
HOST_RE = re.compile(r'^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$')
TOKEN_ENVS = {
    'AWX': 'ILA_ECA_API_TOKEN_AWX',
    'GITLAB': 'ILA_ECA_API_TOKEN_GITLAB',
    'KUBERNETES': 'ILA_ECA_API_TOKEN_KUBERNETES',
    'PROMETHEUS': 'ILA_ECA_API_TOKEN_PROMETHEUS',
}
PATHS = {
    'AWX': re.compile(r'^/api/v2/jobs/[0-9]{1,14}/$'),
    'GITLAB': re.compile(r'^/api/v4/projects/[0-9]{1,14}/repository/commits/[a-fA-F0-9]{7,40}$'),
    'KUBERNETES': re.compile(r'^/api/v1/namespaces/[a-z0-9-]{1,63}/events$'),
    'PROMETHEUS': re.compile(r'^/api/v1/alerts$'),
}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PermissionError('READONLY_API_REDIRECT_DENIED')


def _duplicates_rejected(pairs):
    value = {}
    for k, v in pairs:
        if k in value:
            raise ValueError('READONLY_API_DUPLICATE_JSON_KEY')
        value[k] = v
    return value


def _host_allowed(
    url: str, product: str, allowed_hosts: list[str], remote: bool
) -> tuple[str, bool]:
    if not isinstance(url, str) or not 1 <= len(url) <= 1000 or '\\' in url:
        raise ValueError('INVALID_READONLY_API_URL')
    parsed = urlsplit(url)
    if (
        parsed.scheme not in ('http', 'https')
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise PermissionError('READONLY_API_URL_DENIED')
    host = parsed.hostname.lower()
    if '%' in host or not isinstance(allowed_hosts, list) or len(allowed_hosts) > 12:
        raise PermissionError('READONLY_API_HOST_DENIED')
    if not all(isinstance(h, str) and h == h.lower() and len(h) < 254 for h in allowed_hosts):
        raise PermissionError('READONLY_API_HOST_LIST_INVALID')
    if host not in allowed_hosts:
        raise PermissionError('READONLY_API_HOST_NOT_ALLOWED')
    if product not in PATHS or not PATHS[product].fullmatch(parsed.path):
        raise PermissionError('READONLY_API_PATH_OR_PRODUCT_DENIED')
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise PermissionError('READONLY_API_PORT_DENIED')
    try:
        addr = ipaddress.ip_address(host)
        loopback = addr.is_loopback
    except ValueError:
        loopback = False
        if not HOST_RE.fullmatch(host) or host.endswith('.local') or host.endswith('.internal'):
            raise PermissionError('READONLY_API_HOST_DENIED')
    if loopback:
        if parsed.scheme != 'http' or parsed.port is None:
            raise PermissionError('READONLY_LOOPBACK_REQUIRES_HTTP_EXPLICIT_PORT')
    else:
        if not remote or parsed.scheme != 'https' or parsed.port not in (None, 443):
            raise PermissionError('REMOTE_READONLY_NOT_EXPLICITLY_ALLOWED')
        # Remote IP literals and local domain resolution are not permitted.
        try:
            ipaddress.ip_address(host)
            raise PermissionError('REMOTE_READONLY_IP_LITERAL_DENIED')
        except ValueError:
            pass
    return host, loopback


def capture(
    url: str,
    product: str,
    *,
    allowed_hosts: list[str],
    allow_remote: bool = False,
    token: str | None = None,
    timeout: float = 4.0,
) -> dict:
    host, loopback = _host_allowed(url, product, allowed_hosts, allow_remote)
    if token is not None and (
        not isinstance(token, str) or not 1 <= len(token) <= 2048 or '\r' in token or '\n' in token
    ):
        raise PermissionError('INVALID_READONLY_API_TOKEN')
    if token and loopback:  # never send real credentials to a local test server
        raise PermissionError('READONLY_API_LOOPBACK_TOKEN_DENIED')
    if not 0.2 <= timeout <= 10:
        raise ValueError('READONLY_API_TIMEOUT_INVALID')
    headers = {'Accept': 'application/json', 'User-Agent': 'ILA-ECA-Portfolio-readonly-v19'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = Request(url, headers=headers, method='GET')
    opener = build_opener(
        ProxyHandler({}),
        HTTPHandler(),
        HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )
    try:
        with opener.open(req, timeout=timeout) as response:
            if response.status != 200:
                raise ValueError('READONLY_API_NOT_200')
            content_type = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
            if content_type not in ('application/json', 'application/vnd.api+json'):
                raise ValueError('READONLY_API_NOT_JSON')
            if (
                response.headers.get('Content-Length', '').isdigit()
                and int(response.headers['Content-Length']) > MAX_BODY
            ):
                raise ValueError('READONLY_API_BODY_TOO_LARGE')
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError('READONLY_API_BODY_TOO_LARGE')
    except PermissionError:
        raise
    except Exception as exc:
        # Never include requests, URLs, tokens, or response bodies in reports.
        if isinstance(exc, ValueError) and str(exc).startswith('READONLY_'):
            raise
        raise RuntimeError('READONLY_API_FETCH_FAILED') from None
    try:
        payload = json.loads(body.decode('utf-8'), object_pairs_hook=_duplicates_rejected)
    except (ValueError, UnicodeError):
        raise ValueError('READONLY_API_INVALID_JSON') from None
    signal, fields = normalize(product, payload)
    now = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    return {
        'product': product,
        'signal': signal,
        'fields': fields,
        'observed_at': now,
        'response_sha256': sha256(body).hexdigest(),
        'source_ref': url,
        'source_kind': 'UNVERIFIED_HTTP_GET_OBSERVATION',
        'transport': 'HTTPS_REMOTE_EXPLICIT' if not loopback else 'HTTP_LOOPBACK_MOCK',
        'read_only': True,
        'write_operations': 0,
    }


from typing import Any

PRODUCTS = {'AWX', 'GITLAB', 'KUBERNETES', 'NETWORK', 'PROMETHEUS', 'LINUX', 'VSPHERE'}


SENSITIVE = re.compile(
    r'(?i)(AKIA[0-9A-Z]{16}|-----BEGIN .*PRIVATE KEY|password|access_token|secret_key|authorization|private_key|api[_-]?key|Bearer\s+\S+)'
)


def _safe_text(value: Any, limit: int = 160) -> str:
    if not isinstance(value, (str, int, float, bool)):
        raise ValueError('NON_SCALAR_SNAPSHOT_FIELD')
    s = str(value).strip()[:limit]
    if SENSITIVE.search(s):
        raise PermissionError('SENSITIVE_SNAPSHOT_CONTENT_DENIED')
    return s


def normalize(product: str, payload: dict) -> tuple[str, dict]:
    """Extract small known API-shape fields; never persist raw/secret-bearing data."""
    if product not in PRODUCTS or not isinstance(payload, dict):
        raise ValueError('UNKNOWN_SNAPSHOT_ADAPTER')
    if product == 'AWX':
        data = {
            'job_id': _safe_text(payload.get('id', 'UNKNOWN')),
            'status': _safe_text(payload.get('status', 'unknown')),
            'elapsed': _safe_text(payload.get('elapsed', 'unknown')),
        }
        signal = f"AWX job {data['status']} id={data['job_id']}"
    elif product == 'GITLAB':
        data = {
            'commit_id': _safe_text(payload.get('id', 'UNKNOWN')),
            'title': _safe_text(payload.get('title', 'unknown')),
        }
        signal = f"GitLab commit {data['commit_id']} {data['title']}"
    elif product == 'KUBERNETES':
        items = payload.get('items', [])
        if not isinstance(items, list) or len(items) > 60:
            raise ValueError('INVALID_K8S_EVENTS')
        reasons = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError('INVALID_K8S_EVENT')
            reason = _safe_text(item.get('reason', 'UNKNOWN'), 80)
            # Event messages are untrusted; extract only bounded diagnostic tokens.
            reasons.append(reason)
        data = {'event_count': len(items), 'reasons': reasons[:12]}
        signal = 'Kubernetes event reasons: ' + ', '.join(reasons[:12])
    elif product == 'NETWORK':
        data = {
            'query': _safe_text(payload.get('query', 'unknown'), 80),
            'rcode': _safe_text(payload.get('rcode', 'unknown'), 60),
        }
        signal = f"DNS query {data['query']} response {data['rcode']}"
    elif product == 'PROMETHEUS':
        items = (
            payload.get('data', {}).get('alerts', [])
            if isinstance(payload.get('data'), dict)
            else None
        )
        if not isinstance(items, list) or len(items) > 100:
            raise ValueError('INVALID_PROMETHEUS_ALERTS')
        alerts = []
        for item in items:
            if not isinstance(item, dict):
                raise ValueError('INVALID_PROM_ALERT')
            labels = item.get('labels', {})
            if not isinstance(labels, dict):
                raise ValueError('INVALID_PROM_LABELS')
            alerts.append(
                {
                    'name': _safe_text(labels.get('alertname', 'unknown'), 80),
                    'state': _safe_text(item.get('state', 'unknown'), 30),
                }
            )
        data = {'alert_count': len(items), 'alerts': alerts[:12]}
        signal = 'Prometheus active alerts: ' + ', '.join(x['name'] for x in alerts[:12])
    elif product == 'LINUX':
        data = {
            'mount': _safe_text(payload.get('mount', 'unknown')),
            'available_bytes': _safe_text(payload.get('available_bytes', 'unknown')),
            'state': _safe_text(payload.get('state', 'unknown')),
        }
        signal = f"Linux storage {data['mount']} {data['state']}"
    else:
        data = {
            'datastore': _safe_text(payload.get('datastore', 'unknown')),
            'state': _safe_text(payload.get('state', 'unknown')),
        }
        signal = f"vSphere datastore {data['datastore']} {data['state']}"
    if SENSITIVE.search(json.dumps(data, ensure_ascii=False)):
        raise PermissionError('SENSITIVE_NORMALIZED_SNAPSHOT_DENIED')
    return signal[:500], data
