"""Bounded LAB repair via an existing GitLab approval and AWX job.

Investigation stays read-only. This module has no diagnostic rules, approval
writer, arbitrary command executor, automatic retry, or Baseline activation.
"""

from contextlib import closing
from datetime import datetime, timezone
import copy
import json
import re
import sqlite3

from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, utc_now
from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import Principal, timestamp
from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import reserve, _save, load_evidence, infer
from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import Investigation
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration import approval
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.store import Store
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle import changes as lifecycle

SCHEMA = "ila.eca.kubernetes-service-selector-change.v1"
PLAN_INSTRUCTION = (
    "Translate the saved incident repair proposal into one concrete, reviewable "
    "change using only the observed resource and allowed action contract. "
    "You must choose the intended values from the evidence, not from a supplied "
    "answer or an assumed default. If evidence does not justify a concrete change, "
    "choose HOLD and name the missing evidence. Never execute or approve. "
    "Keep current resource identity and unrelated fields unchanged. "
    "A proposed change is neither approval nor proof of recovery."
)


def validate_selector_spec(spec):
    """An operation allowlist, not a Service-selector diagnosis."""
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import _service

    if type(spec) is not dict or set(spec) != {"schema", "scope", "resource", "before", "after"}:
        raise ValueError("REPAIR_SPEC_FIELDS_INVALID")
    if spec["schema"] != SCHEMA or spec["scope"] != "lab":
        raise PermissionError("REPAIR_LAB_SELECTOR_CONTRACT_REQUIRED")
    resource = spec["resource"]
    if type(resource) is not dict or set(resource) != {
        "apiVersion",
        "kind",
        "cluster_ref",
        "namespace",
        "name",
        "uid",
    }:
        raise ValueError("REPAIR_RESOURCE_IDENTITY_REQUIRED")
    if resource["apiVersion"] != "v1" or resource["kind"] != "Service":
        raise PermissionError("REPAIR_OPERATION_NOT_ALLOWED")
    for key in ("cluster_ref", "namespace", "name", "uid"):
        if type(resource[key]) is not str or not resource[key] or len(resource[key]) > 253:
            raise ValueError("REPAIR_RESOURCE_IDENTITY_REQUIRED")
    for key in ("namespace", "name"):
        if not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?", resource[key]):
            raise ValueError("REPAIR_RESOURCE_NAME_INVALID")
    _service(spec["before"], resource)
    _service(spec["after"], resource)
    before, after = copy.deepcopy(spec["before"]), copy.deepcopy(spec["after"])
    prior, intended = before["spec"].pop("selector", None), after["spec"].pop("selector", None)
    if (
        before != after
        or prior == intended
        or not isinstance(prior, dict)
        or not isinstance(intended, dict)
        or not intended
    ):
        raise ValueError("REPAIR_ONLY_NONEMPTY_SELECTOR_CHANGE_ALLOWED")
    for mapping in (prior, intended):
        for key, value in mapping.items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_-]{0,252}", key) or not re.fullmatch(
                r"[A-Za-z0-9_.-]{0,63}", value
            ):
                raise ValueError("REPAIR_SELECTOR_LABEL_INVALID")
    return spec


def service_projection(resource):
    from ILA_ECA_REAL_DISCOVERY_LAB.incident.kubernetes_review import _META, _SPEC

    return {
        "metadata": {k: v for k, v in resource["metadata"].items() if k in _META},
        "spec": {k: v for k, v in resource["spec"].items() if k in _SPEC},
    }


def validate_execution_target(target, spec):
    validate_selector_spec(spec)
    if (
        type(target) is not dict
        or target.get("scope") != "lab"
        or target.get("execution_enabled") is not True
    ):
        raise PermissionError("AWX_EXECUTION_TARGET_NOT_ALLOWED")
    for key, expected in {
        "cluster_ref": spec["resource"]["cluster_ref"],
        "namespace": spec["resource"]["namespace"],
        "service": spec["resource"]["name"],
    }.items():
        if target.get(key) != expected:
            raise PermissionError("AWX_EXECUTION_TARGET_NOT_ALLOWED")
    for key in ("template_id", "inventory", "project", "execution_environment"):
        if type(target.get(key)) is not int or target[key] <= 0:
            raise PermissionError("AWX_EXECUTION_TARGET_PIN_REQUIRED")
    if (
        not re.fullmatch("[0-9a-f]{64}", target.get("playbook_sha256", ""))
        or not re.fullmatch("[0-9a-f]{40}", target.get("scm_revision", ""))
        or not re.fullmatch(r"[A-Za-z0-9_/-]+\.yml", target.get("playbook", ""))
        or ".." in target["playbook"].split("/")
    ):
        raise PermissionError("AWX_EXECUTION_TARGET_PIN_REQUIRED")
    return target


def _reviewed_target(db, change_id, target, spec):
    validate_execution_target(target, spec)
    with closing(connect(db)) as con:
        row = con.execute(
            "SELECT structured_path FROM lifecycle_design_artifact_v2 WHERE change_id=? ORDER BY revision DESC LIMIT 1",
            (change_id,),
        ).fetchone()
    if not row:
        raise PermissionError("AWX_REVIEWED_EXECUTION_TARGET_REQUIRED")
    document = json.loads(
        (__import__("pathlib").Path(db).parent / "design_drafts_lab" / row[0]).read_bytes()
    )
    construction = document["details"]["construction"]
    if construction.get("execution_target") != target or construction.get(
        "execution_target_sha256"
    ) != data_digest(target):
        raise PermissionError("AWX_REVIEWED_EXECUTION_TARGET_CHANGED")


def plan_schema():
    text = {"type": "string"}
    labels = {"type": "object", "additionalProperties": {"type": "string"}}
    properties = {
        "decision": {"type": "string", "enum": ["PROPOSE", "HOLD"]},
        "selector": labels,
        "reason": text,
        "verification": text,
        "rollback": text,
        "evidence_refs": {"type": "array", "items": text},
        "missing": {"type": "array", "items": text},
    }
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def validate_plan(value, input_data):
    if type(value) is not dict or set(value) != set(plan_schema()["properties"]):
        raise ValueError("REPAIR_PLAN_FIELDS_INVALID")
    if value["decision"] not in {"PROPOSE", "HOLD"} or type(value["selector"]) is not dict:
        raise ValueError("REPAIR_PLAN_DECISION_INVALID")
    for key in ("reason", "verification", "rollback"):
        if type(value[key]) is not str or not value[key].strip():
            raise ValueError("REPAIR_PLAN_EXPLANATION_REQUIRED")
    for key in ("evidence_refs", "missing"):
        if type(value[key]) is not list or any(type(x) is not str for x in value[key]):
            raise ValueError("REPAIR_PLAN_ARRAY_INVALID")
    available = {f["fact_ref"] for f in input_data["facts"]}
    if set(value["evidence_refs"]) - available:
        raise ValueError("REPAIR_PLAN_UNSHOWN_EVIDENCE")
    if value["decision"] == "HOLD":
        if value["selector"] or not value["missing"]:
            raise ValueError("REPAIR_HOLD_REQUIRES_MISSING_INFORMATION")
        return value
    if not value["evidence_refs"]:
        raise ValueError("REPAIR_PLAN_EVIDENCE_REQUIRED")
    spec = copy.deepcopy(input_data["operation"])
    spec["after"] = copy.deepcopy(spec["before"])
    spec["after"]["spec"]["selector"] = value["selector"]
    validate_selector_spec(spec)
    return value


def propose_concrete_plan(
    db, case_id, principal, *, before, cluster_ref, profile=None, planner=None
):
    """One saved local-model request after C proposes repair; no response editing."""
    engine = Investigation.readonly(db)
    case = engine.get(case_id, principal)
    state = case["state"]
    if state["status"] != "WAITING_REPAIR" or state["pending"] or not state["repair_candidates"]:
        raise PermissionError("SAVED_INCIDENT_REPAIR_CANDIDATE_REQUIRED")
    projection = service_projection(before)
    operation = {
        "schema": SCHEMA,
        "scope": "lab",
        "resource": {
            "apiVersion": "v1",
            "kind": "Service",
            "cluster_ref": cluster_ref,
            **{k: before["metadata"][k] for k in ("namespace", "name", "uid")},
        },
        "before": projection,
    }
    material = {
        "case_id": case_id,
        "case_head": case["head"],
        "proposal": state["repair_candidates"][-1],
        "hypotheses": state["hypotheses"],
        "facts": engine._facts(state, principal),
        "operation": operation,
        "operation_contract": "Only Service.spec.selector may change; no permission to execute",
    }
    result = (planner or infer)(
        db,
        scope="lab",
        route="C",
        request_id=case_id + "-concrete-repair",
        instruction=PLAN_INSTRUCTION,
        input_data=material,
        schema=plan_schema(),
        validator=validate_plan,
        profile=profile,
    )
    if result["status"] == "GENERATED" and result["value"]["decision"] == "PROPOSE":
        spec = {**copy.deepcopy(operation), "after": copy.deepcopy(projection)}
        spec["after"]["spec"]["selector"] = copy.deepcopy(result["value"]["selector"])
        validate_selector_spec(spec)
        _save(
            db,
            "lab",
            "incident-plan://" + case_id,
            "incident_concrete_repair_plan_v1",
            {
                "case_id": case_id,
                "case_head": case["head"],
                "candidate_decision_id": state["repair_candidates"][-1]["decision_id"],
                "spec_sha256": data_digest(spec),
                "spec": spec,
                "model_result_evidence_id": result["evidence_id"],
                "chosen_value": result["value"],
                "status": "UNAPPROVED_MODEL_PLAN",
            },
        )
        return {
            "status": "UNAPPROVED_CONCRETE_PLAN",
            "spec": spec,
            "call": result,
            "case_head": case["head"],
        }
    return {"status": "HOLD", "call": result, "case_head": case["head"]}


def _results(db, request_eid):
    with closing(connect(db)) as con:
        rows = con.execute(
            "SELECT evidence_id,payload_json FROM evidence WHERE adapter='awx_repair_result_v1' AND json_extract(payload_json,'$.request_evidence_id')=?",
            (request_eid,),
        ).fetchall()
    if len(rows) > 1:
        raise ValueError("AWX_REPAIR_RESULT_AMBIGUOUS")
    return (rows[0][0], json.loads(rows[0][1])) if rows else (None, None)


def _approval_target(db, cfg, gitlab, host, case_id, sid, spec, *, allow_account_test):
    status = approval.status(db, cfg, gitlab, host, case_id, sid)
    accepted = status.get("formal_approval_granted") is True
    test = status.get("test_approval_granted") is True
    if not accepted and not (allow_account_test is True and test):
        raise PermissionError("CURRENT_BOUND_HUMAN_APPROVAL_REQUIRED")
    target = status["target"]
    if target["case_id"] != case_id or target["submission_id"] != sid:
        raise PermissionError("REPAIR_APPROVAL_CASE_MISMATCH")
    change = lifecycle.get_change(db, target["change_id"])
    lifecycle.assert_change_integrity(db, target["change_id"])
    if change["intended_spec"] != spec:
        raise PermissionError("REPAIR_APPROVED_SPEC_CHANGED")
    return target, change, ("ACCOUNT_TEST_ONLY" if test else "FORMAL_DESIGN_APPROVAL")


def execute(
    db,
    *,
    case_id,
    submission_id,
    spec,
    cfg,
    gitlab,
    approval_host,
    awx,
    target,
    observe_service,
    executor,
    allow_account_test=False,
    reconcile=False
):
    """At most one POST per approved plan. Unknown jobs can only be reconciled."""
    from ILA_ECA_REAL_DISCOVERY_LAB.core.workflows import (
        Cursor,
        Execution,
        StateGraph,
        START,
        END,
        invoke,
    )

    flow = Execution()
    graph = StateGraph(Cursor)
    bound = change = authority = expected = request = source = eid = created = tag = None
    job_id = None
    stage = "RESERVATION"
    before = None

    def preflight():
        nonlocal bound, change, authority, expected, request, source, eid, created, tag
        principal = Principal(executor, actions=("READ", "ADVISE", "LAB_CHANGE_EXECUTE"))
        principal.check()
        validate_selector_spec(spec)
        bound, change, authority = _approval_target(
            db,
            cfg,
            gitlab,
            approval_host,
            case_id,
            submission_id,
            spec,
            allow_account_test=allow_account_test,
        )
        _reviewed_target(db, bound["change_id"], target, spec)
        expected = {
            "cluster_ref": spec["resource"]["cluster_ref"],
            "namespace": spec["resource"]["namespace"],
            "service": spec["resource"]["name"],
        }
        if (
            any(target.get(k) != v for k, v in expected.items())
            or target.get("scope") != "lab"
            or target.get("execution_enabled") is not True
        ):
            raise PermissionError("AWX_EXECUTION_TARGET_NOT_ALLOWED")
        if executor in {change["design_author"], change.get("review_actor")}:
            raise PermissionError("REPAIR_SEPARATE_EXECUTION_ACTOR_REQUIRED")
        if target.get("template_id") != awx.template_id or not target.get("playbook_sha256"):
            raise PermissionError("AWX_TEMPLATE_PIN_REQUIRED")
        request = {
            "case_id": case_id,
            "submission_id": submission_id,
            "approval_target": bound,
            "authority": authority,
            "plan": spec,
            "plan_sha256": data_digest(spec),
            "target": target,
            "executor": executor,
        }
        # One submission is one execution identity, including concurrent operators.
        # Changed executors/configuration cannot evade idempotency by changing a hash.
        source = "awx-repair://" + case_id + "/" + submission_id
        eid, created = reserve(db, "lab", source, "awx_repair_request_v1", request)
        _, done = _results(db, eid)
        if done:
            flow.output = {**done, "reused": True, "new_launches": 0}
            return
        tag = "ILA-ECA-" + eid
        if not created and not reconcile:
            flow.output = {
                "state": "RESULT_UNKNOWN",
                "request_evidence_id": eid,
                "tag": tag,
                "new_launches": 0,
                "automatic_retry": False,
            }
            return

    def reconcile_job():
        nonlocal stage, job_id
        stage = "RECONCILE_EXISTING_JOB"
        jobs = awx.find_jobs(tag)
        if len(jobs) != 1:
            flow.output = {
                "state": "RESULT_UNKNOWN",
                "request_evidence_id": eid,
                "matched_jobs": len(jobs),
                "new_launches": 0,
                "automatic_retry": False,
            }
            return
        job_id = jobs[0]["id"]

    def launch():
        nonlocal before, stage, job_id
        stage = "PREFLIGHT"
        awx.check_template(target)
        # The bound GitLab approval is rechecked after preflight and before POST.
        again, _, _ = _approval_target(
            db,
            cfg,
            gitlab,
            approval_host,
            case_id,
            submission_id,
            spec,
            allow_account_test=allow_account_test,
        )
        if again != bound:
            raise PermissionError("APPROVAL_CHANGED_DURING_EXECUTION_PREFLIGHT")
        before = observe_service()
        if service_projection(before) != spec["before"]:
            raise PermissionError("LIVE_RESOURCE_CHANGED_SINCE_REVIEW")
        stage = "LAUNCH"
        # Only data parameters for a pinned, scoped Playbook; never model code.
        job_id = awx.launch(tag, spec, before["metadata"]["resourceVersion"])
        _save(
            db,
            "lab",
            source,
            "awx_repair_job_id_v1",
            {"request_evidence_id": eid, "job_id": job_id, "tag": tag, "at": utc_now()},
        )

    def job_result():
        nonlocal stage
        stage = "JOB_RESULT"
        job = awx.job(job_id)
        if job.get("status") not in {"successful", "failed", "error", "canceled"}:
            flow.output = {
                "state": "AWX_RUNNING",
                "job_id": job_id,
                "request_evidence_id": eid,
                "new_launches": int(created),
                "automatic_retry": False,
            }
            return
        if (
            job.get("job_template") != awx.template_id
            or job.get("extra_vars", {}).get("ila_execution_id") != tag
            or job.get("extra_vars", {}).get("ila_plan_sha256") != data_digest(spec)
            or (target.get("scm_revision") and job.get("scm_revision") != target["scm_revision"])
        ):
            raise PermissionError("AWX_JOB_BINDING_CHANGED")
        result = {
            "state": "AWX_SUCCEEDED_UNVERIFIED" if job["status"] == "successful" else "AWX_FAILED",
            "request_evidence_id": eid,
            "job_id": job_id,
            "tag": tag,
            "job": job,
            "before": before,
            "plan_sha256": data_digest(spec),
            "authority": authority,
            "executor": executor,
            "recorded_at": utc_now(),
            "execution_kind": getattr(awx, "execution_kind", "MOCK"),
            "recovery_verified": False,
            "new_launches": int(created),
            "automatic_retry": False,
        }
        _save(db, "lab", source, "awx_repair_result_v1", result)
        Store(db).link(case_id, "AWX_REPAIR", eid, result)
        flow.output = result
        return

    for name, function in {
        "preflight": preflight,
        "reconcile_job": reconcile_job,
        "launch": launch,
        "job_result": job_result,
    }.items():
        flow.node(graph, name, function)
    graph.add_edge(START, "preflight")
    graph.add_conditional_edges(
        "preflight",
        lambda _: flow.choose(
            lambda: END if flow.output is not None else "launch" if created else "reconcile_job"
        ),
    )
    graph.add_conditional_edges(
        "reconcile_job", lambda _: flow.choose(END if flow.output is not None else "job_result")
    )
    graph.add_conditional_edges("launch", lambda _: flow.choose("job_result"))
    graph.add_edge("job_result", END)
    try:
        return invoke(graph, db, "awx-repair", [case_id, submission_id], flow)
    except BaseException as exc:
        if stage == "RESERVATION":
            raise
        failure = {
            "state": (
                "RESULT_UNKNOWN"
                if stage in {"LAUNCH", "JOB_RESULT", "RECONCILE_EXISTING_JOB"}
                else "BLOCKED_BEFORE_LAUNCH"
            ),
            "request_evidence_id": eid,
            "job_id": job_id,
            "stage": stage,
            "exception_type": type(exc).__name__,
            "reason": (
                str(exc) if re.fullmatch("[A-Z0-9_]+", str(exc)) else "PRODUCT_OR_TRANSPORT_FAILURE"
            ),
            "cause_type": type(exc.__cause__).__name__ if exc.__cause__ else None,
            "automatic_retry": False,
            "recorded_at": utc_now(),
        }
        _save(db, "lab", source, "awx_repair_failure_v1", failure)
        if not isinstance(exc, Exception):
            raise
        return failure


def verify_recovery(db, *, case_id, result, spec, observations, verifier):
    """Independent fresh observations, never AWX status or model prose alone."""
    if result.get("state") != "AWX_SUCCEEDED_UNVERIFIED":
        raise PermissionError("COMPLETED_AWX_JOB_REQUIRED_FOR_RECOVERY_CHECK")
    if not verifier or verifier == result["executor"]:
        raise PermissionError("SEPARATE_RECOVERY_VERIFIER_REQUIRED")
    validate_selector_spec(spec)
    if data_digest(spec) != result["plan_sha256"]:
        raise ValueError("RECOVERY_PLAN_CHANGED")
    # Bind to the saved result rather than a caller's success assertion.
    _, saved = _results(db, result["request_evidence_id"])
    if saved is None or any(
        saved.get(k) != result.get(k) for k in ("job_id", "job", "plan_sha256", "executor", "state")
    ):
        raise PermissionError("SAVED_AWX_COMPLETION_REQUIRED")
    ended = timestamp(result["job"]["finished"])
    failures = []
    required = {"http", "service", "endpoints", "monitor"}
    if set(observations) != required:
        failures.append("REQUIRED_OBSERVATION_MISSING")
    for key in required:
        item = observations.get(key, {})
        if item.get("state") != "OBSERVED":
            failures.append(key.upper() + "_NOT_OBSERVED")
            continue
        try:
            if timestamp(item["observed_at"]) <= ended:
                failures.append(key.upper() + "_NOT_FRESH_AFTER_JOB")
        except (KeyError, ValueError, TypeError):
            failures.append(key.upper() + "_TIME_UNKNOWN")
    http = observations.get("http", {}).get("values", {})
    if http.get("status") != 200 or http.get("body", {}).get("healthy") is not True:
        failures.append("ORIGINAL_HTTP_SYMPTOM_REMAINS_OR_UNKNOWN")
    try:
        if timestamp(http["body"]["at"]) <= ended:
            failures.append("DEPENDENCY_HTTP_MEASUREMENT_PREDATES_COMPLETION")
    except (KeyError, ValueError, TypeError):
        failures.append("DEPENDENCY_HTTP_MEASUREMENT_TIME_UNKNOWN")
    actual = observations.get("service", {}).get("values", {})
    try:
        if service_projection(actual) != spec["after"]:
            failures.append("ACTUAL_CONFIGURATION_DIFFERS")
    except (KeyError, TypeError):
        failures.append("ACTUAL_CONFIGURATION_UNKNOWN")
    endpoints = observations.get("endpoints", {}).get("values", {}).get("items", [])
    selected = [
        e
        for s in endpoints
        if s.get("metadata", {}).get("labels", {}).get("kubernetes.io/service-name")
        == spec["resource"]["name"]
        and any(
            owner.get("kind") == "Service" and owner.get("uid") == spec["resource"]["uid"]
            for owner in s.get("metadata", {}).get("ownerReferences", [])
        )
        for e in (s.get("endpoints") or [])
        if e.get("conditions", {}).get("ready") is True and e.get("addresses")
    ]
    if not selected:
        failures.append("NO_READY_SERVICE_ENDPOINT")
    monitor = observations.get("monitor", {}).get("values", {})
    samples = (
        monitor.get("data", {}).get("result", []) if monitor.get("status") == "success" else []
    )
    # Prometheus instant-query timestamps are evaluation times, not sample times.
    # Require a separate timestamp(metric) result from the actual scrape.
    sample_times = monitor.get("sample_times", [])
    try:
        healthy = (
            bool(samples)
            and len(sample_times) == len(samples)
            and all(len(s.get("value", [])) == 2 and s["value"][1] == "1" for s in samples)
            and all(type(t) in (int, float) and t > ended.timestamp() for t in sample_times)
        )
    except (ValueError, TypeError, KeyError):
        healthy = False
    if not healthy:
        failures.append("MONITOR_RECOVERY_NOT_FRESH_OR_NOT_HEALTHY")
    alerts = observations.get("monitor", {}).get("alerts", {})
    if alerts.get("status") != "success" or not isinstance(
        alerts.get("data", {}).get("alerts"), list
    ):
        failures.append("MONITOR_ALERT_STATE_UNKNOWN")
    elif any(alert.get("state") in {"firing", "pending"} for alert in alerts["data"]["alerts"]):
        failures.append("MONITOR_ALERT_STILL_ACTIVE")
    report = {
        "case_id": case_id,
        "job_id": result["job_id"],
        "request_evidence_id": result["request_evidence_id"],
        "state": "RECOVERED_LAB_ONLY" if not failures else "RECOVERY_UNCONFIRMED",
        "failures": failures,
        "verifier": verifier,
        "observations": observations,
        "at": utc_now(),
        "execution_kind": saved.get("execution_kind", "MOCK"),
        "formal_production_acceptance": False,
        "baseline_updated": False,
    }
    evidence = _save(db, "lab", "recovery://" + case_id, "awx_independent_recovery_v1", report)
    Store(db).link(case_id, "RECOVERY_CHECK", evidence, report)
    engine = Investigation.readonly(db)
    case = engine.get(case_id, Principal(verifier))
    if case["state"]["pending"]:
        raise PermissionError("RECOVERY_CASE_HAS_PENDING_INVESTIGATION")
    state = case["state"]
    state["repair_outcomes"].append(
        {
            "job_id": result["job_id"],
            "symptom_status": "ABSENT" if not failures else "UNOBSERVED",
            "verifier": verifier,
            "evidence_id": evidence,
            "checked_at": report["at"],
            "execution_kind": report["execution_kind"],
            "authority": saved["authority"],
        }
    )
    state.update(status="RESOLVED_LAB_ONLY" if not failures else "HOLD", reason=report["state"])
    engine._commit(state, case["head"], "AWX_INDEPENDENT_RECOVERY_RECORDED", report)
    return report
