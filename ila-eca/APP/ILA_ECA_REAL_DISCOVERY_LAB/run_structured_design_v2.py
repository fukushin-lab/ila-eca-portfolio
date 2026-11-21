"""A-H review-first LAB overlay. Reuses protected gateways and existing executors."""

from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import parse_json

from contextlib import closing
from pathlib import Path
import copy
import json
import sqlite3
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, init_db
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.core.workflows import (
    Cursor,
    Execution,
    StateGraph,
    START,
    END,
    invoke,
)
from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import IncidentModelProfile
from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import (
    _save,
    load_evidence,
    infer,
    reserve,
    metadata_ready,
)


def _request(db, spec):
    if (
        type(spec) is not dict
        or set(spec) != {"schema", "request_id", "route", "scope", "profile", "payload"}
        or spec["schema"] != "ila.eca.full-route-request.v1"
    ):
        raise ValueError("FULL_ROUTE_REQUEST_INVALID")
    if spec["route"] not in list("ABCDEFGH") or spec["scope"] not in {"lab", "ila-discovery-lab"}:
        raise PermissionError("FULL_ROUTE_SCOPE_OR_ROUTE_DENIED")
    from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import valid_document_id

    if not valid_document_id(spec["request_id"]) or type(spec["payload"]) is not dict:
        raise ValueError("FULL_ROUTE_REQUEST_INVALID")
    profile = (
        IncidentModelProfile.from_dict(spec["profile"])
        if spec["profile"]
        else IncidentModelProfile(model="qwen3:8b")
    )
    init_db(db)
    source = "full-request://" + spec["request_id"]
    eid, _ = reserve(
        db,
        spec["scope"],
        source,
        "full_route_request_v1",
        {"request": copy.deepcopy(spec), "sha256": data_digest(spec)},
    )
    return profile, eid


def attach_to_review(db, document, attachment):
    """The caller supplies an intended target; model prose never becomes one."""
    from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle import changes as lc
    from ILA_ECA_REAL_DISCOVERY_LAB.design import change as sd

    cid = attachment["change_id"]
    target = attachment["intended_spec"]
    try:
        change = lc.get_change(db, cid)
    except ValueError as exc:
        if "Record not found" not in str(exc):
            raise
        change = lc.propose_change(
            db,
            change_id=cid,
            requested_by=attachment["requested_by"],
            purpose=attachment["purpose"],
            intended_spec=target,
        )
    if (
        change["intended_spec"] != target
        or change["requested_by"] != attachment["requested_by"]
        or change["purpose"] != attachment["purpose"]
    ):
        raise ValueError("FULL_ROUTE_REVIEW_TARGET_CHANGED")
    reference = {
        "design_id": document["record"]["design_id"],
        "revision": document["record"]["revision"],
    }
    if change["status"] == "DRAFT":
        draft = sd.create_template_draft(
            db,
            cid,
            author=attachment["author"],
            design_origin="AI",
            details={
                "document_reviews": [reference],
                "unknowns": attachment.get("unknowns", []),
                "construction": {"state": "NOT_PERFORMED"},
            },
        )
        return {
            "change_id": cid,
            "status": lc.get_change(db, cid)["status"],
            "document_sha256": draft["document_sha256"],
        }
    lc.assert_change_integrity(db, cid)
    with closing(connect(db)) as con:
        row = con.execute(
            "SELECT structured_path FROM lifecycle_design_artifact_v2 WHERE change_id=? ORDER BY revision DESC LIMIT 1",
            (cid,),
        ).fetchone()
    if not row:
        raise ValueError("FULL_ROUTE_REVIEW_ARTIFACT_MISSING")
    saved = json.loads((Path(db).parent / "design_drafts_lab" / row[0]).read_bytes())
    if reference not in saved["details"].get("document_reviews", []):
        raise ValueError("FULL_ROUTE_NEW_CHANGE_REQUIRED_FOR_NEW_ANNEX")
    return {
        "change_id": cid,
        "status": change["status"],
        "document_sha256": change["design_sha256"],
    }


def dispatch(db, spec, *, allow_lab_execution=False, cloud_runtime=None, cancel_requested=None):
    db = Path(db)
    profile, request_evidence_id = _request(db, spec)
    route = spec["route"]
    scope = spec["scope"]
    request_id = spec["request_id"]
    payload = spec["payload"]
    if not metadata_ready(db, request_evidence_id, scope):
        return {
            "route": route,
            "request_id": request_id,
            "scope": scope,
            "status": "HOLD",
            "result": {"record_state": "INPUT_METADATA_PENDING"},
            "document": None,
            "request_evidence_id": request_evidence_id,
            "semantic_quality": "NOT_EVALUATED",
            "enterprise_approval": False,
            "real_product_changes": 0,
        }
    result = None
    document = None
    audio_result = None
    text = None
    flow = Execution()
    graph = StateGraph(Cursor)

    def a_structured():
        nonlocal result, document
        from ILA_ECA_REAL_DISCOVERY_LAB.design.generation import generate_source_design
        from ILA_ECA_REAL_DISCOVERY_LAB.design.generation import bind_design_to_change
        from ILA_ECA_REAL_DISCOVERY_LAB.design import non_aws as nd

        if profile.expected_digest and nd._model_digest(profile.model) != profile.expected_digest:
            raise ValueError("INCIDENT_MODEL_VERSION_CHANGED")
        result = generate_source_design(
            db,
            scope=scope,
            design_id=payload["design_id"],
            task=payload["task"],
            source_evidence_ids=payload["source_evidence_ids"],
            model=profile.model,
            generation_options={"runtime_profile": profile},
        )
        document = result["document"]
        if payload.get("bind_change"):
            result["review"] = bind_design_to_change(
                db,
                scope=scope,
                design_id=payload["design_id"],
                revision=document["record"]["revision"],
                **payload["bind_change"],
            )

    def a_freeform():
        nonlocal result, document
        from ILA_ECA_REAL_DISCOVERY_LAB.design.context_routes import _received_sources

        packet = _received_sources(db, scope, payload["source_evidence_ids"])
        result = infer(
            db,
            scope=scope,
            route="A",
            request_id=request_id,
            instruction="入力の要求と受領資料に基づき、要求された設計・構成図・IaC案・手順を日本語で作成する。既存事実・提案・未知事項・根拠を区別し、未承認のレビュー案として原文を返す。実行や承認は行わない。",
            input_data={"request": payload["task"], "received_sources": packet},
            schema=None,
            profile=profile,
        )
        result["source_bindings"] = packet["search_bindings"]
        result["output_mode"] = "FREEFORM_REVIEW_ONLY"

    def b_plan():
        nonlocal result, document
        if scope != "ila-discovery-lab":
            raise PermissionError("FULL_B_EXISTING_LIFECYCLE_SCOPE_REQUIRED")
        from ILA_ECA_REAL_DISCOVERY_LAB.design.generation import plan_approved_change

        result = plan_approved_change(
            db, payload["change_id"], request_id=request_id, profile=profile
        )

    def b_execute():
        nonlocal result, document
        if scope != "ila-discovery-lab":
            raise PermissionError("FULL_B_EXISTING_LIFECYCLE_SCOPE_REQUIRED")
        from ILA_ECA_REAL_DISCOVERY_LAB.design.generation import plan_approved_change

        if not allow_lab_execution:
            raise PermissionError("FULL_B_EXPLICIT_LAB_EXECUTION_OPT_IN_REQUIRED")
        from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle.execution import execute_approved_plan

        result = execute_approved_plan(
            db,
            payload["change_id"],
            payload["plan_result"],
            Path(payload["run_root"]),
            actor=payload["actor"],
            verifier=payload.get("verifier"),
            explicit_lab_only=True,
        )
        result["call"] = payload["plan_result"]["call"]
        result["route"] = "B"
        result["evidence_id"] = _save(
            db,
            scope,
            "full-route://B/" + request_id,
            "full_route_execution_v1",
            copy.deepcopy(result),
        )

    def c_investigate():
        nonlocal result, document
        if scope != "lab":
            raise PermissionError("FULL_C_ISOLATED_LAB_SCOPE_REQUIRED")
        from .run_incident_investigation import run_request

        provider = payload.get("provider", "LOCAL8B")
        if provider not in {"LOCAL8B", "OPENAI_ASTRA"}:
            raise ValueError("FULL_C_PROVIDER_INVALID")
        if (provider == "OPENAI_ASTRA") != (cloud_runtime is not None):
            raise PermissionError("CLOUD_EXPLICIT_PROVIDER_AND_RUNTIME_REQUIRED")
        if cloud_runtime is not None and spec["profile"]:
            raise ValueError("INCIDENT_CLOUD_LOCAL_SETTINGS_CONFLICT")
        result = run_request(
            db,
            Path(payload["incident_request"]),
            use_local_llm=cloud_runtime is None,
            profile=profile if cloud_runtime is None else None,
            cloud_runtime=cloud_runtime,
            resume_reason=payload.get("resume_reason"),
            reconcile_model_reason=payload.get("reconcile_model_reason"),
            cancel_requested=cancel_requested,
        )
        from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import Investigation
        from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import Principal

        result["incident_head_evidence_id"] = Investigation.readonly(db).get(
            result["case_id"], Principal("FULL-ROUTE-READER")
        )["head"]
        document = result.get("report")
        if document is None:
            result["route"] = "C"
            result["status"] = result["state"]
            result["evidence_id"] = _save(
                db,
                scope,
                "full-route://C/" + request_id,
                "full_route_execution_v1",
                copy.deepcopy(result),
            )

    def d_answer():
        nonlocal result, document
        from ILA_ECA_REAL_DISCOVERY_LAB.design.context_routes import question

        result = question(
            db,
            scope=scope,
            request_id=request_id,
            query=payload["question"],
            evidence_ids=payload["source_evidence_ids"],
            profile=profile,
        )

    def e_audio():
        nonlocal audio_result, text
        from ILA_ECA_REAL_DISCOVERY_LAB.meeting.review import _validate_asr
        from ILA_ECA_REAL_DISCOVERY_LAB.meeting.audio import transcript_for_eca

        _, asr = load_evidence(db, payload["asr_evidence_id"], scope)
        _validate_asr(asr)
        audio_result = asr["result"]
        text = transcript_for_eca(audio_result)["meeting_text"]

    def e_text():
        nonlocal audio_result, text
        text = payload["text"]

    def e_analyze():
        nonlocal result, document
        from ILA_ECA_REAL_DISCOVERY_LAB.design.context_routes import meeting

        result = meeting(
            db,
            scope=scope,
            request_id=request_id,
            text=text,
            change_id=payload.get("change_id"),
            profile=profile,
        )

    def e_anchor():
        nonlocal result, document
        from ILA_ECA_REAL_DISCOVERY_LAB.meeting.audio import anchor_claims_to_segments

        result["audio_evidence_id"] = payload["asr_evidence_id"]
        result["audio_sha256"] = audio_result["audio_sha256"]
        result["audio_anchors"] = anchor_claims_to_segments(
            audio_result, [{"quote": i["quote"]} for i in result.get("items", [])]
        )

    def f_record():
        nonlocal result, document
        from ILA_ECA_REAL_DISCOVERY_LAB.design.context_routes import no_action

        result = no_action(
            db,
            scope=scope,
            request_id=request_id,
            target_spec=payload.get("target_spec"),
            change_id=payload.get("change_id"),
            evidence_ids=payload.get("source_evidence_ids", ()),
        )

    def g_design():
        nonlocal result, document
        if scope != "lab":
            raise PermissionError("FULL_G_SYNTHETIC_LAB_TEST_SCOPE_REQUIRED")
        if cloud_runtime is not None:
            raise PermissionError("AWS_DESIGN_EXTERNAL_RUNTIME_DENIED")
        from ILA_ECA_REAL_DISCOVERY_LAB.design.aws import run as local_design

        result = local_design(
            db, scope=scope, request_id=request_id, payload=payload, profile=profile
        )
        document = result.get("document")

    def g_draft():
        nonlocal result, document
        if scope != "lab":
            raise PermissionError("FULL_G_SYNTHETIC_LAB_TEST_SCOPE_REQUIRED")
        from ILA_ECA_REAL_DISCOVERY_LAB.design.cloud_draft import run_cloud_draft

        if payload.get("provider", "LOCAL8B") not in {"LOCAL8B", "OPENAI_SOL"}:
            raise ValueError("FULL_G_PROVIDER_INVALID")
        if payload.get("provider") == "OPENAI_SOL" and cloud_runtime is None:
            raise PermissionError("CLOUD_TRUSTED_RUNTIME_REQUIRED")
        if cloud_runtime is not None and payload.get("provider") != "OPENAI_SOL":
            raise PermissionError("CLOUD_EXPLICIT_PROVIDER_REQUIRED")
        result = run_cloud_draft(
            db,
            cloud_runtime=cloud_runtime,
            scope=scope,
            request_id=request_id,
            input_data=payload["input"],
            materials=payload["materials"],
            profile=profile,
            upstream_binding=payload.get("upstream_binding"),
        )

    def h_security():
        nonlocal result, document
        from ILA_ECA_REAL_DISCOVERY_LAB.design.context_routes import security

        result = security(
            db,
            scope=scope,
            request_id=request_id,
            symptom=payload["symptom"],
            evidence_ids=payload["source_evidence_ids"],
            unknowns=payload.get("unknowns", ()),
            profile=profile,
        )

    def inspect_result():
        nonlocal result, document
        call = result.get("call", result)
        if call.get("record_state") == "INPUT_METADATA_PENDING":
            flow.output = {
                "route": route,
                "request_id": request_id,
                "scope": scope,
                "status": "HOLD",
                "result": result,
                "document": None,
                "request_evidence_id": request_evidence_id,
                "semantic_quality": "NOT_EVALUATED",
                "enterprise_approval": False,
                "real_product_changes": 0,
            }

    def document_result():
        nonlocal result, document
        if document is None:
            from ILA_ECA_REAL_DISCOVERY_LAB.design.route_documents import create_route_document

            result = {**result, "request_evidence_id": request_evidence_id}
            document = create_route_document(
                db, scope=scope, route=route, request_id=request_id, result=result
            )

    def attach_review():
        nonlocal result, document
        result["review"] = attach_to_review(db, document, payload["review_attachment"])

    def reply():
        nonlocal result, document
        status = result.get("status", result.get("state", "RECORDED"))
        flow.output = {
            "route": route,
            "request_id": request_id,
            "scope": scope,
            "status": status,
            "result": result,
            "document": document,
            "request_evidence_id": request_evidence_id,
            "semantic_quality": "NOT_AUTOMATICALLY_EVALUATED",
            "enterprise_approval": False,
            "real_product_changes": 0,
        }

    def guard():
        nonlocal result, document
        flow.values["selected_route"] = select_route_name()
        if cloud_runtime is not None and route not in {"C", "G"}:
            raise PermissionError("CLOUD_RUNTIME_CG_ONLY")

    def select_route_name():
        if route == "A":
            mode = payload.get("output_mode", "STRUCTURED")
            if mode not in {"STRUCTURED", "FREEFORM"}:
                raise ValueError("FULL_A_OUTPUT_MODE_INVALID")
            return "a_structured" if mode == "STRUCTURED" else "a_freeform"
        if route == "B":
            if scope != "ila-discovery-lab":
                raise PermissionError("FULL_B_EXISTING_LIFECYCLE_SCOPE_REQUIRED")
            mode = payload.get("operation", "PLAN")
            if mode not in {"PLAN", "EXECUTE_LAB"}:
                raise ValueError("FULL_B_OPERATION_INVALID")
            return "b_plan" if mode == "PLAN" else "b_execute"
        if route == "E":
            return "e_audio" if payload.get("asr_evidence_id") else "e_text"
        if route == "G":
            return "g_design" if payload.get("provider") == "LOCAL_DESIGN" else "g_draft"
        return {"C": "c_investigate", "D": "d_answer", "F": "f_record", "H": "h_security"}[route]

    def select_route(_):
        return flow.choose(lambda: flow.values["selected_route"])

    for name, function in {
        "guard": guard,
        "a_structured": a_structured,
        "a_freeform": a_freeform,
        "b_plan": b_plan,
        "b_execute": b_execute,
        "c_investigate": c_investigate,
        "d_answer": d_answer,
        "e_audio": e_audio,
        "e_text": e_text,
        "e_analyze": e_analyze,
        "e_anchor": e_anchor,
        "f_record": f_record,
        "g_design": g_design,
        "g_draft": g_draft,
        "h_security": h_security,
        "inspect_result": inspect_result,
        "document_result": document_result,
        "attach_review": attach_review,
        "reply": reply,
    }.items():
        flow.node(graph, name, function)
    graph.add_edge(START, "guard")
    graph.add_conditional_edges("guard", select_route)
    for name in (
        "a_structured",
        "a_freeform",
        "b_plan",
        "b_execute",
        "c_investigate",
        "d_answer",
        "f_record",
        "g_design",
        "g_draft",
        "h_security",
    ):
        graph.add_edge(name, "inspect_result")
    graph.add_edge("e_audio", "e_analyze")
    graph.add_edge("e_text", "e_analyze")
    graph.add_conditional_edges(
        "e_analyze", lambda _: flow.choose("e_anchor" if audio_result else "inspect_result")
    )
    graph.add_edge("e_anchor", "inspect_result")
    graph.add_conditional_edges(
        "inspect_result",
        lambda _: flow.choose(END if flow.output is not None else "document_result"),
    )
    graph.add_conditional_edges(
        "document_result",
        lambda _: flow.choose("attach_review" if payload.get("review_attachment") else "reply"),
    )
    graph.add_edge("attach_review", "reply")
    graph.add_edge("reply", END)
    try:
        return invoke(graph, db, "full-route", [scope, request_id], flow)
    except Exception as exc:
        evidence = getattr(exc, "design_evidence_id", None)
        native = getattr(exc, "design_payload", None)
        call = getattr(exc, "route_call", None)
        if call is None and isinstance(result, dict):
            candidate = result.get("call", result)
            if isinstance(candidate, dict) and candidate.get("evidence_id"):
                call = candidate
        if call is not None:
            evidence = call["evidence_id"]
        count = (
            call.get("actual_llm_calls")
            if call is not None
            else (
                0
                if getattr(exc, "design_cache_hit", False)
                else native.get("actual_llm_calls") if native else 0
            )
        )
        failure = {
            "route": route,
            "status": "HOLD",
            "request_evidence_id": request_evidence_id,
            "error_type": type(exc).__name__,
            "error_code": str(exc),
            "original_failure_evidence_id": evidence,
            "actual_llm_calls": count,
            "failure_category": "UNDETERMINED" if evidence else "CODE_OR_INPUT",
            "approval_granted": False,
        }
        failure["evidence_id"] = _save(
            db, scope, "full-request://" + request_id, "full_route_failure_v1", failure
        )
        from ILA_ECA_REAL_DISCOVERY_LAB.design.route_documents import create_route_document

        document = create_route_document(
            db, scope=scope, route=route, request_id=request_id, result=failure
        )
        return {
            "route": route,
            "request_id": request_id,
            "scope": scope,
            "status": "HOLD",
            "result": failure,
            "document": document,
            "request_evidence_id": request_evidence_id,
            "semantic_quality": "NOT_EVALUATED",
            "enterprise_approval": False,
            "real_product_changes": 0,
        }


def run(db, path, *, allow_lab_execution=False, cloud_runtime=None):
    import base64, hashlib

    raw = None
    spec = None
    stage = "REQUEST_READ"
    try:
        raw = Path(path).read_bytes()
        stage = "REQUEST_PARSE"
        spec = parse_json(
            raw.decode("utf-8-sig"),
            duplicate_error="FULL_ROUTE_INPUT_DUPLICATE_JSON_KEY",
            nonfinite_error="FULL_ROUTE_INPUT_NONFINITE_JSON_NUMBER",
        )
        stage = "REQUEST_VALIDATE"
        # Validate and reserve before dispatch so only pre-inference input errors
        # enter the zero-call audit below. The ordinary reservation is idempotent.
        _request(db, spec)
    except Exception as exc:
        requested_route = spec.get("route") if type(spec) is dict else None
        route = (
            requested_route
            if isinstance(requested_route, str) and requested_route in list("ABCDEFGH")
            else "F"
        )
        input_record = {
            "path": str(path),
            "read_state": "READ" if raw is not None else "NOT_READ",
            "byte_count": len(raw) if raw is not None else None,
            "sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
            "base64": base64.b64encode(raw).decode() if raw is not None else None,
        }
        failure = {
            "route": route,
            "status": "HOLD",
            "failure_stage": stage,
            "failure_category": "CODE_OR_INPUT",
            "error_type": type(exc).__name__,
            "error_code": str(exc),
            "raw_input": input_record,
            "actual_llm_calls": 0,
            "approval_granted": False,
            "baseline_updated": False,
        }
        rid = "FULL-INPUT-ERROR-" + data_digest(failure)[:32]
        scope = "lab"
        eid, _ = reserve(db, scope, "full-request://" + rid, "full_route_failure_v1", failure)
        result = {**failure, "evidence_id": eid}
        document = None
        if metadata_ready(db, eid, scope):
            from ILA_ECA_REAL_DISCOVERY_LAB.design.route_documents import create_route_document

            document = create_route_document(
                db, scope=scope, route=route, request_id=rid, result=result
            )
        else:
            result["record_state"] = "INPUT_METADATA_PENDING"
        result = {
            "route": route,
            "request_id": rid,
            "scope": scope,
            "status": "HOLD",
            "result": result,
            "document": document,
            "request_evidence_id": eid,
            "semantic_quality": "NOT_EVALUATED",
            "enterprise_approval": False,
            "real_product_changes": 0,
        }
    else:
        result = dispatch(
            db, spec, allow_lab_execution=allow_lab_execution, cloud_runtime=cloud_runtime
        )
    destination = Path(db).parent / (result["request_id"] + ".full.json")
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), "utf-8")
    return result


def main():
    """Existing Windows argument entry for current A-H and service adapters."""
    import argparse, os

    parser = argparse.ArgumentParser(
        description="ILA/ECA current A-H entry; no implicit approval or execution"
    )
    parser.add_argument("--db", type=Path, required=True)
    choices = parser.add_mutually_exclusive_group(required=True)
    choices.add_argument("--full-route-request", type=Path)
    choices.add_argument("--incident-request", type=Path)
    choices.add_argument("--notification-config", type=Path)
    choices.add_argument("--collaboration-request", type=Path)
    parser.add_argument("--full-cloud-config", type=Path)
    parser.add_argument("--full-allow-lab-execution", action="store_true")
    parser.add_argument("--incident-use-local-llm", action="store_true")
    parser.add_argument("--incident-model", choices=["qwen3:4b", "qwen3:8b"], default="qwen3:8b")
    parser.add_argument("--incident-profile", type=Path)
    parser.add_argument("--incident-resume-reason")
    parser.add_argument("--incident-reconcile-model-reason")
    parser.add_argument("--notification-port", type=int, default=18765)
    parser.add_argument("--collaboration-config", type=Path)
    parser.add_argument("--approval-policy", type=Path)
    parser.add_argument("--approval-account-test", type=Path)
    parser.add_argument("--gitlab-approval-listen", action="store_true")
    parser.add_argument("--gitlab-approval-port", type=int, default=18766)
    args = parser.parse_args()
    db = args.db
    if bool(args.collaboration_config) != bool(args.collaboration_request):
        raise ValueError("COLLABORATION_REQUEST_AND_CONFIG_REQUIRED")
    if args.approval_policy and not args.collaboration_request:
        raise ValueError("APPROVAL_POLICY_REQUIRES_COLLABORATION_ENTRY")
    if args.approval_account_test and not (args.approval_policy and args.collaboration_request):
        raise ValueError("ACCOUNT_TEST_REQUIRES_APPROVAL_ENTRY")
    if args.gitlab_approval_listen and not (args.collaboration_request and args.approval_policy):
        raise ValueError("GITLAB_LISTENER_REQUEST_CONFIG_POLICY_REQUIRED")
    if args.full_allow_lab_execution and not args.full_route_request:
        raise ValueError("Explicit full route request required")
    if args.full_cloud_config and not args.full_route_request:
        raise ValueError("Cloud config requires an explicit C/G route request")
    if args.incident_profile and not args.incident_request:
        raise ValueError("Incident profile requires an incident request")
    if (
        args.incident_resume_reason or args.incident_reconcile_model_reason
    ) and not args.incident_request:
        raise ValueError("Incident resume requires an incident request")
    if args.incident_use_local_llm and not args.incident_request:
        raise ValueError("Local incident model requires an explicit incident request")
    if args.full_route_request:
        runtime = None
        if args.full_cloud_config:
            from .llm.cloud import runtime_from_config

            runtime = runtime_from_config(
                args.full_cloud_config, key_provider=lambda: os.environ.get("OPENAI_API_KEY")
            )
        result = run(
            db,
            args.full_route_request,
            allow_lab_execution=args.full_allow_lab_execution,
            cloud_runtime=runtime,
        )
        print(
            json.dumps(
                {
                    "route": result["route"],
                    "request_id": result["request_id"],
                    "status": result["status"],
                    "document": result["document"]["path"] if result["document"] else None,
                    "semantic_quality": result["semantic_quality"],
                    "enterprise_approval": False,
                    "real_product_changes": result["real_product_changes"],
                },
                ensure_ascii=False,
            )
        )
        return 2 if result["status"] in {"HOLD", "ACTIVE", "CANCELED"} else 0
    if args.incident_request:
        from .run_incident_investigation import run_request

        profile = (
            IncidentModelProfile.from_dict(json.loads(args.incident_profile.read_text("utf-8-sig")))
            if args.incident_profile
            else None
        )
        result = run_request(
            db,
            args.incident_request,
            use_local_llm=args.incident_use_local_llm,
            model=args.incident_model,
            profile=profile,
            resume_reason=args.incident_resume_reason,
            reconcile_model_reason=args.incident_reconcile_model_reason,
        )
        print("INCIDENT CASE:", result["case_id"])
        print("INCIDENT STATE:", result["state"], "/", result["reason"])
        print("ASSESSMENT ORIGIN:", result["model_assessment_origin"])
        return 2 if result["state"] in {"HOLD", "CANCELED"} or result.get("pending") else 0
    from .llm.cloud import parse

    if args.notification_config:
        if args.full_cloud_config or args.incident_profile or args.full_allow_lab_execution:
            raise ValueError("NOTIFICATION_LOCAL_ONLY_SETTINGS_REQUIRED")
        from .incident.notifications import serve

        serve(
            db,
            parse(args.notification_config.read_bytes()),
            token=os.environ.get("ILA_NOTIFICATION_TOKEN"),
            port=args.notification_port,
        )
        return 0
    from .collaboration.entry import execute
    from .collaboration.approval import GitLabApprovalHost, GitLabAccountTestHost, make_server

    cfg = parse(args.collaboration_config.read_bytes())
    request = parse(args.collaboration_request.read_bytes())
    host = (
        GitLabAccountTestHost(args.approval_policy, args.approval_account_test)
        if args.approval_account_test
        else GitLabApprovalHost(args.approval_policy)
    )
    if args.gitlab_approval_listen:
        from .collaboration.mcp import gitlab_api as configured_gitlab_api

        if (
            set(request) != {"schema", "case_id", "operation", "payload"}
            or request["schema"] != "ila.eca.collaboration-request.v1"
            or request["operation"] != "formal_receive"
            or set(request["payload"]) != {"submission_id"}
        ):
            raise ValueError("GITLAB_LISTENER_REQUEST_INVALID")
        api = configured_gitlab_api(db, cfg, request["case_id"])
        server = make_server(
            db,
            cfg,
            api,
            host,
            request["case_id"],
            request["payload"]["submission_id"],
            args.gitlab_approval_port,
        )
        print(
            "GitLab signed-event adapter: http://127.0.0.1:"
            + str(server.server_port)
            + "/gitlab-approvals",
            flush=True,
        )
        try:
            server.serve_forever()
        finally:
            server.server_close()
    else:
        print(json.dumps(execute(db, cfg, request, approval_host=host), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
