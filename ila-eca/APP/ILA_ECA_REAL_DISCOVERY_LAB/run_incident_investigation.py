"""Existing Windows entry delegates here; no automatic model or product writes."""

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import copy
import json
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, utc_now
from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import (
    Investigation,
    ReadOperation,
    ReadRegistry,
)
from ILA_ECA_REAL_DISCOVERY_LAB.incident.reasoner import LocalIncidentReasoner
from ILA_ECA_REAL_DISCOVERY_LAB.incident.artifacts import create_report
from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import Request, Principal


def run_request(
    db,
    path,
    *,
    use_local_llm=False,
    model="qwen3:8b",
    profile=None,
    resume_reason=None,
    reconcile_model_reason=None,
    cloud_runtime=None,
    cancel_requested=None,
    registry=None,
):
    """Trusted operator manifest binds operations; JSON cannot supply Python/commands."""
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.readers import existing_evidence
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.readers import readonly_http

    manifest = json.loads(Path(path).read_text("utf-8-sig"))
    if (
        set(manifest) != {"schema", "request", "incident", "operations", "max_steps", "max_calls"}
        or manifest["schema"] != "ila.eca.incident-request.v1"
    ):
        raise ValueError("INCIDENT_MANIFEST_INVALID")
    request = Request(**manifest["request"])
    p = Principal(request.requester_ref)
    ops = []
    for row in manifest["operations"]:
        if row["kind"] == "AUDIT_FIELDS":
            ops.append(
                existing_evidence(
                    row["operation_id"], target_ref=row["target_ref"], selections=row["selections"]
                )
            )
        elif row["kind"] == "HTTP_GET_LOOPBACK":
            ops.append(
                readonly_http(
                    row["operation_id"],
                    target_ref=row["target_ref"],
                    url=row["url"],
                    product=row["product"],
                    allowed_hosts=row["allowed_hosts"],
                    allow_remote=False,
                )
            )
        else:
            raise PermissionError("INCIDENT_OPERATOR_ADAPTER_NOT_SUPPORTED")
    if profile is not None and not use_local_llm:
        raise ValueError("INCIDENT_PROFILE_REQUIRES_LOCAL_MODEL_OPT_IN")
    if cloud_runtime is not None:
        if use_local_llm or profile is not None:
            raise ValueError("INCIDENT_CLOUD_LOCAL_SETTINGS_CONFLICT")
        from ILA_ECA_REAL_DISCOVERY_LAB.llm.incident_cloud import CloudIncidentReasoner

        reasoner = CloudIncidentReasoner(db, manifest, cloud_runtime)
    else:
        reasoner = (
            LocalIncidentReasoner(model=model, profile=profile)
            if profile is not None
            else (LocalIncidentReasoner(model=model) if use_local_llm else None)
        )
    # Only a trusted Python caller supplies product readers; request JSON cannot.
    if registry is not None and not isinstance(registry, ReadRegistry):
        raise TypeError("TRUSTED_READ_REGISTRY_REQUIRED")
    engine = Investigation(db, registry=registry or ReadRegistry(ops), reasoner=reasoner)
    if registry is not None and reasoner is not None:
        reasoner.require_evaluation_slot = True
    case = engine.start(
        request,
        p,
        incident=manifest["incident"],
        max_steps=manifest["max_steps"],
        max_calls=manifest["max_calls"],
    )
    if (
        (use_local_llm or cloud_runtime is not None)
        and case["state"]["reason"] == "LOCAL_MODEL_NOT_ENABLED"
        and not case["state"]["pending"]
    ):
        case = engine.resume(
            request.request_id, p, reason="Explicit model opt-in after disabled intake"
        )
    if reconcile_model_reason:
        case = engine.reconcile_model(request.request_id, p, reason=reconcile_model_reason)
    if resume_reason:
        case = engine.resume(request.request_id, p, reason=resume_reason)
    case = engine.run(request.request_id, p, cancel_requested=cancel_requested)
    report = create_report(db, request.request_id, p) if not case["state"]["pending"] else None
    return {
        "case_id": request.request_id,
        "state": case["state"]["status"],
        "reason": case["state"]["reason"],
        "report": report,
        "pending": case["state"]["pending"],
        "incident_resolved": case["state"]["status"] == "RESOLVED_LAB_ONLY",
        "proposal_document_ready": case["state"]["status"] == "WAITING_REPAIR"
        and not case["state"]["pending"],
        "model_assessment_origin": reasoner.origin if reasoner is not None else "DISABLED",
        "infrastructure_writes": 0,
    }
