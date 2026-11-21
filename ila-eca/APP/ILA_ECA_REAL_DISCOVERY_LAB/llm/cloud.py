"""C/G Responses transport into existing evidence/document storage.

No key discovery, monetary budget policy, export authorization inference, automatic retries,
semantic approval or infrastructure writes. Host supplies trusted runtime objects.
"""

from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import parse_json

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from time import perf_counter
import base64
import copy
import json
import sqlite3
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, init_db
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest, canonical_json
from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import reserve, _save, load_evidence, metadata_ready
from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import positive_int, positive_seconds

ENDPOINT = "https://api.openai.com/v1/responses"


class CloudTransportNotDispatched(PermissionError):
    """Trusted transport failed its local preflight before any provider attempt."""


MODEL = "gpt-6.2-sol"
SETTINGS = {
    "reasoning": {"effort": "high"},
    "max_output_tokens": 16000,
    "stream": False,
    "store": False,
    "tools": [],
    "truncation": "disabled",
    "service_tier": "default",
}


def generation_settings(max_output_tokens=None):
    settings = copy.deepcopy(SETTINGS)
    if max_output_tokens is not None:
        positive_int(max_output_tokens, "CLOUD_OUTPUT_CAPACITY_INVALID")
        # Published model capacity, not a small-case application ceiling.
        if max_output_tokens > 128000:
            raise ValueError("CLOUD_MODEL_OUTPUT_CAPACITY_EXCEEDED")
        settings["max_output_tokens"] = max_output_tokens
    return settings


def parse(raw):
    return parse_json(
        raw, duplicate_error="CLOUD_DUPLICATE_JSON_KEY", nonfinite_error="CLOUD_NONFINITE_JSON"
    )


def validate_request(request, *, route="G"):
    if type(request) is not dict or set(request) != {"model", "input", *SETTINGS}:
        raise ValueError("CLOUD_EXACT_REQUEST_REQUIRED")
    expected = generation_settings(request.get("max_output_tokens"))
    if (
        route not in {"C", "G"}
        or request["model"] != ("gpt-6.2-astra" if route == "C" else MODEL)
        or any(request[k] != v for k, v in expected.items())
    ):
        raise ValueError("CLOUD_UNREVIEWED_MODEL_OR_SETTINGS")
    if type(request["input"]) is not list or not request["input"]:
        raise ValueError("CLOUD_INPUT_REQUIRED")
    for message in request["input"]:
        if (
            type(message) is not dict
            or set(message) != {"role", "content"}
            or message["role"] not in {"system", "user"}
            or type(message["content"]) is not str
        ):
            raise ValueError("CLOUD_TEXT_MESSAGES_ONLY")
    canonical_json(request)


def request_for(input_data, materials, *, max_output_tokens=None):
    from ILA_ECA_REAL_DISCOVERY_LAB.design.cloud_draft import INSTRUCTION

    return {
        "model": MODEL,
        "input": [
            {"role": "system", "content": INSTRUCTION},
            {
                "role": "user",
                "content": canonical_json(
                    {"original_input": input_data, "technical_reference_documents": materials}
                ),
            },
        ],
        **generation_settings(max_output_tokens),
    }


def authorized(record, *, scope, request_id, request):
    """Record must come from an operator-selected local approval, never the LLM.

    This is an explicit LAB/operator assertion, not enterprise identity proof.
    It does not declassify content or authorize any AWS construction/changes.
    """
    expected = {
        "schema",
        "scope",
        "request_id",
        "endpoint",
        "model",
        "request_sha256",
        "approved_by",
        "expires_at",
        "classification",
        "external_send_permitted",
    }
    if type(record) is not dict or set(record) != expected:
        raise PermissionError("CLOUD_EXPORT_RECORD_REQUIRED")
    if (
        record["schema"] != "ila.eca.cloud-export-authorization.v1"
        or record["scope"] != scope
        or record["request_id"] != request_id
        or record["endpoint"] != ENDPOINT
        or record["model"] != request["model"]
        or record["request_sha256"] != data_digest(request)
        or record["external_send_permitted"] is not True
        or record["classification"] not in {"SYNTHETIC_ONLINE", "OPERATOR_CARRIED_ONLINE"}
        or type(record["approved_by"]) is not str
        or not record["approved_by"].strip()
    ):
        raise PermissionError("CLOUD_EXPORT_BINDING_MISMATCH")
    try:
        expiry = datetime.fromisoformat(record["expires_at"])
    except (TypeError, ValueError):
        raise PermissionError("CLOUD_EXPORT_EXPIRY_INVALID") from None
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise PermissionError("CLOUD_EXPORT_EXPIRED")


def read_authorization(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise PermissionError("CLOUD_EXPORT_FILE_REQUIRED")
    return parse(path.read_bytes())


@dataclass(frozen=True)
class CloudRuntime:
    authorization: dict
    transport: object  # trusted host callback: (request bytes) -> (HTTP status, response bytes)
    execution_kind: str = "LIVE"
    max_output_tokens: int | None = None


class OpenAITransport:
    """One POST. Caller injects its existing credential provider, never JSON input."""

    def __init__(self, key_provider, timeout=900):
        if not callable(key_provider):
            raise TypeError("CLOUD_CREDENTIAL_PROVIDER_REQUIRED")
        positive_seconds(timeout, "CLOUD_TIMEOUT_INVALID")
        self.key_provider = key_provider
        self.timeout = timeout

    def __call__(self, body):
        import ssl, urllib.request, urllib.error

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        try:
            key = self.key_provider()
        except Exception as exc:
            raise CloudTransportNotDispatched("CLOUD_CREDENTIAL_PROVIDER_PREFLIGHT_FAILED") from exc
        if type(key) is not str or not key or any(c.isspace() for c in key):
            raise CloudTransportNotDispatched("CLOUD_CREDENTIAL_UNAVAILABLE")
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        request = urllib.request.Request(
            ENDPOINT,
            data=body,
            method="POST",
            headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        )
        try:
            with opener.open(request, timeout=self.timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            code = exc.code
            try:
                body = exc.read()
            finally:
                exc.close()
            # Preserve the original provider error for the existing audit path.
            # Never persist an echoed credential or include it in diagnostics.
            if key.encode("utf-8") in body:
                raise ValueError("CLOUD_HTTP_BODY_CONTAINS_CREDENTIAL_NOT_SAVED")
            return code, body


def text(envelope, *, model=MODEL):
    if (
        envelope.get("status") != "completed"
        or envelope.get("error")
        or envelope.get("incomplete_details")
    ):
        raise ValueError("CLOUD_GENERATION_NOT_COMPLETE")
    actual = envelope.get("model", "")
    if actual != model and not actual.startswith(model + "-"):
        raise ValueError("CLOUD_RESPONSE_MODEL_CHANGED")
    if envelope.get("service_tier") != "default":
        raise ValueError("CLOUD_RESPONSE_TIER_CHANGED")
    parts = []
    for item in envelope.get("output", []):
        if item.get("type") == "reasoning":
            continue
        if (
            item.get("type") != "message"
            or item.get("role") != "assistant"
            or item.get("status") != "completed"
        ):
            raise ValueError("CLOUD_UNEXPECTED_OUTPUT_ITEM")
        for content in item.get("content", []):
            if content.get("type") != "output_text" or type(content.get("text")) is not str:
                raise ValueError("CLOUD_REFUSED_OR_NON_TEXT_OUTPUT")
            parts.append(content["text"])
    value = "\n".join(parts)
    if not value.strip():
        raise ValueError("CLOUD_EMPTY_OUTPUT")
    return value


def verify_exchange(saved, input_record, input_row):
    if saved["input_record_sha256"] != data_digest(input_row):
        raise ValueError("CLOUD_INPUT_RECORD_CHANGED")
    condition = input_record["condition"]
    request = condition["request"]
    validate_request(request, route=condition["route"])
    if input_record["condition_sha256"] != data_digest(condition):
        raise ValueError("CLOUD_CONDITION_CHANGED")
    if saved.get("request_sha256") != data_digest(request):
        raise ValueError("CLOUD_REQUEST_CHANGED")
    raw = base64.b64decode(saved["response_base64"], validate=True)
    if sha256(raw).hexdigest() != saved["response_sha256"]:
        raise ValueError("CLOUD_RESPONSE_CHANGED")
    if saved["status"] == "GENERATED":
        envelope = parse(raw)
        if saved["http_status"] != 200 or saved["value"] != text(envelope, model=request["model"]):
            raise ValueError("CLOUD_OUTPUT_CHANGED")
        if saved["usage"] != envelope.get("usage"):
            raise ValueError("CLOUD_USAGE_CHANGED")
        if saved["dispatch_state"] != "RESPONSE_RECEIVED":
            raise ValueError("CLOUD_RESPONSE_STATE_CHANGED")
    return saved


def infer_cloud(db, *, scope, request_id, request, runtime, route="G"):
    if scope != "lab":
        raise PermissionError("CLOUD_ONLINE_LAB_SCOPE_ONLY")
    if type(runtime) is not CloudRuntime or not callable(runtime.transport):
        raise PermissionError("CLOUD_TRUSTED_RUNTIME_REQUIRED")
    if runtime.execution_kind not in {"LIVE", "HISTORICAL_REPLAY", "MOCK"}:
        raise ValueError("CLOUD_EXECUTION_KIND_INVALID")
    if type(request_id) is not str or not 1 <= len(request_id) <= 200:
        raise ValueError("CLOUD_REQUEST_ID_INVALID")
    validate_request(request, route=route)
    request = copy.deepcopy(request)
    # Authorization is part of immutable input, but expiry is checked only before
    # a fresh send. Reading an already saved result never sends or needs renewal.
    condition = {
        "route": route,
        "request_id": request_id,
        "request": request,
        "endpoint": ENDPOINT,
        "authorization": copy.deepcopy(runtime.authorization),
        "execution_kind": runtime.execution_kind,
        "adapter_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    source = "full-route://" + route + "/" + request_id
    record = {"condition": condition, "condition_sha256": data_digest(condition)}
    # Check authorization before recording a NEW request; exact existing records
    # can be read after expiry without reopening an authorization window.
    init_db(db)
    with closing(connect(db)) as con:
        exists = con.execute(
            "SELECT 1 FROM evidence WHERE scope=? AND source=? AND adapter=?",
            (scope, source, "cloud_route_input_v1"),
        ).fetchone()
    if not exists:
        authorized(runtime.authorization, scope=scope, request_id=request_id, request=request)
    input_id, new = reserve(db, scope, source, "cloud_route_input_v1", record)
    if not metadata_ready(db, input_id, scope):
        raise ValueError("CLOUD_INPUT_METADATA_PENDING_NO_RESEND")
    input_row, input_record = load_evidence(db, input_id, scope)
    if not new:
        with closing(connect(db)) as con:
            rows = con.execute(
                "SELECT evidence_id FROM evidence WHERE scope=? AND source=? AND adapter='cloud_route_result_v1'",
                (scope, source),
            ).fetchall()
        if len(rows) > 1:
            raise ValueError("CLOUD_RESULT_AMBIGUOUS")
        if rows:
            if not metadata_ready(db, rows[0][0], scope):
                raise ValueError("CLOUD_RESULT_METADATA_PENDING_NO_RESEND")
            _, saved = load_evidence(db, rows[0][0], scope)
            verify_exchange(saved, input_record, input_row)
            return {**saved, "evidence_id": rows[0][0], "actual_llm_calls": 0, "cache_hit": True}
        raise ValueError("CLOUD_INTERRUPTED_RESULT_UNKNOWN_NO_RESEND")
    started = perf_counter()
    body = b""
    status = None
    calls = 0
    usage = None
    dispatch = "NOT_DISPATCHED"
    value = None
    error = None
    interrupted = None
    try:
        authorized(runtime.authorization, scope=scope, request_id=request_id, request=request)
        dispatch = "DISPATCHING"
        calls = 1
        status, body = runtime.transport(canonical_json(request).encode("utf-8"))
        dispatch = "RESPONSE_RECEIVED"
        if type(status) is not int or type(body) is not bytes:
            body = b""
            raise ValueError("CLOUD_INVALID_TRANSPORT_RESULT")
        if status != 200:
            raise ValueError("CLOUD_HTTP_ERROR_" + str(status))
        envelope = parse(body)
        usage = envelope.get("usage")
        actual_model = envelope.get("model", "")
        if actual_model != request["model"] and not actual_model.startswith(request["model"] + "-"):
            raise ValueError("CLOUD_RESPONSE_MODEL_CHANGED")
        if envelope.get("service_tier") != "default":
            raise ValueError("CLOUD_RESPONSE_TIER_CHANGED")
        value = text(envelope, model=request["model"])
    except BaseException as exc:
        if isinstance(exc, CloudTransportNotDispatched):
            calls = 0
            dispatch = "NOT_DISPATCHED"
        elif calls and dispatch == "DISPATCHING":
            dispatch = "RESULT_UNKNOWN"
        error = (
            str(exc)
            if type(exc) is ValueError and str(exc).startswith("CLOUD_")
            else type(exc).__name__
        )
        # No arbitrary exception messages, URLs or credential-provider contents.
        if not isinstance(exc, Exception):
            error = "CLOUD_INTERRUPTED"
            interrupted = exc
    saved = {
        "route": route,
        "status": "GENERATED" if error is None else "HOLD",
        "value": value if error is None else None,
        "input_evidence_id": input_id,
        "input_record_sha256": data_digest(input_row),
        "request_sha256": data_digest(request),
        "response_base64": base64.b64encode(body).decode(),
        "response_sha256": sha256(body).hexdigest(),
        "http_status": status,
        "usage": usage,
        "dispatch_state": dispatch,
        "actual_llm_calls": calls if runtime.execution_kind == "LIVE" else 0,
        "transport_calls": calls,
        "execution_kind": runtime.execution_kind,
        "elapsed_seconds": round(perf_counter() - started, 3),
        "error_code": error,
        "transport_attempt_count_definition": "Actual provider attempt; typed local preflight refusal is zero",
        "external_llm_used": runtime.execution_kind == "LIVE" and calls > 0,
        "human_approved": False,
        "baseline_updated": False,
        "cloud_resources_created": False,
        "repair_or_apply_executed": False,
        "semantic_quality": "NOT_AUTOMATICALLY_EVALUATED",
    }
    eid = _save(db, scope, source, "cloud_route_result_v1", saved)
    result = {**saved, "evidence_id": eid, "cache_hit": False}
    if interrupted is not None:
        interrupted.route_call = result
        raise interrupted
    return result


def runtime_from_config(path, *, key_provider):
    """Explicit online host configuration; no default credential discovery or monetary budget dependency."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise PermissionError("CLOUD_CONFIG_FILE_REQUIRED")
    config = parse(path.read_bytes())
    if type(config) is dict and config.get("schema") == "ila.eca.incident-cloud-runtime.v1":
        from ILA_ECA_REAL_DISCOVERY_LAB.llm.incident_cloud import (
            runtime_from_config as incident_runtime,
        )

        return incident_runtime(path, config, key_provider=key_provider)
    if (
        type(config) is not dict
        or not {"schema", "authorization_path"} <= set(config)
        or set(config) - {"schema", "authorization_path", "max_output_tokens", "timeout_seconds"}
        or config["schema"] != "ila.eca.cloud-runtime.v1"
    ):
        raise ValueError("CLOUD_CONFIG_INVALID")

    def local(name):
        value = Path(config[name])
        return value if value.is_absolute() else path.parent / value

    generation_settings(config.get("max_output_tokens"))
    return CloudRuntime(
        read_authorization(local("authorization_path")),
        OpenAITransport(key_provider, timeout=config.get("timeout_seconds", 900)),
        "LIVE",
        config.get("max_output_tokens"),
    )
