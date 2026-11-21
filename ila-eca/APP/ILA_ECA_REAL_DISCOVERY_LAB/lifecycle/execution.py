"""Connect a recorded B order plan to the existing V5 isolated file executor.

No planning call, new approval, arbitrary command, product write or Baseline update.
Partial/ambiguous executions remain for reconciliation; they are never resent.
"""

from contextlib import closing
from hashlib import sha256
from pathlib import Path
import base64
import copy
import json
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle import planning as agent, changes as lifecycle
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import load_evidence


def _unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("FULL_B_RECORDED_PLAN_DUPLICATE_JSON_KEY")
        out[key] = value
    return out


def _review_binding(db, change):
    with closing(connect(db)) as con:
        rows = con.execute(
            "SELECT event_id,actor,details_json FROM lifecycle_event_v1 WHERE change_id=? AND event_type='APPROVED_LAB_ONLY'",
            (change["change_id"],),
        ).fetchall()
    if len(rows) != 1 or rows[0][1] != change["review_actor"]:
        raise ValueError("FULL_B_EXISTING_REVIEW_CHANGED")
    details = json.loads(rows[0][2])
    if (
        details.get("reviewed_digest") != change["design_sha256"]
        or details.get("authority") != "LAB_SIMULATION_NOT_FORMAL_APPROVAL"
    ):
        raise ValueError("FULL_B_EXISTING_REVIEW_CHANGED")
    return {
        "change_id": change["change_id"],
        "approved_design_sha256": change["design_sha256"],
        "base_version": change["base_version"],
        "intended_spec_sha256": data_digest(change["intended_spec"]),
        "scope": change["scope"],
        "review_actor": change["review_actor"],
        "review_event_id": rows[0][0],
    }


def _recorded_plan(db, plan_result, binding):
    if not isinstance(plan_result, dict) or plan_result.get("status") != "PLANNED_UNEXECUTED":
        raise PermissionError("FULL_B_VALIDATED_SAVED_PLAN_REQUIRED")
    if plan_result.get("binding") != binding:
        raise ValueError("FULL_B_REVIEW_OR_TARGET_BINDING_CHANGED")
    call = plan_result.get("call")
    if not isinstance(call, dict) or not call.get("evidence_id"):
        raise ValueError("FULL_B_SAVED_MODEL_EVIDENCE_REQUIRED")
    row, saved = load_evidence(db, call["evidence_id"], binding["scope"])
    if (
        row["adapter"] != "route_model_result_v1"
        or saved.get("route") != "B"
        or saved.get("status") != "GENERATED"
    ):
        raise PermissionError("FULL_B_VALIDATED_SAVED_PLAN_REQUIRED")
    # Replay counters are call-site metadata. All stored model/input fields must
    # still be identical to the result the caller is authorizing for execution.
    for key, value in saved.items():
        if key == "actual_llm_calls":
            continue
        if key not in call or data_digest(call[key]) != data_digest(value):
            raise ValueError("FULL_B_MODEL_RESULT_CHANGED")
    input_row, input_record = load_evidence(db, saved["input_evidence_id"], binding["scope"])
    if (
        input_row["adapter"] != "route_model_input_v1"
        or data_digest(input_row) != saved["input_record_sha256"]
    ):
        raise ValueError("FULL_B_MODEL_INPUT_CHANGED")
    condition = input_record["condition"]
    if condition.get("route") != "B" or condition["input"].get("approved_change_ref") != binding:
        raise ValueError("FULL_B_MODEL_INPUT_TARGET_CHANGED")
    trace = saved["trace"]
    exchange = trace["exchange"]
    body = exchange["response_body"]
    raw = base64.b64decode(body["base64"], validate=True)
    if sha256(raw).hexdigest() != body["sha256"] or body.get("complete_response") is False:
        raise ValueError("FULL_B_MODEL_ORIGINAL_RESPONSE_CHANGED")
    envelope = json.loads(raw, object_pairs_hook=_unique)
    if (
        envelope != exchange["response"]
        or envelope.get("done") is not True
        or envelope.get("done_reason") not in (None, "stop")
    ):
        raise ValueError("FULL_B_MODEL_ORIGINAL_RESPONSE_CHANGED")
    original = json.loads(envelope["response"], object_pairs_hook=_unique)
    if (
        original != saved["value"]
        or original != plan_result.get("plan")
        or original != call.get("value")
    ):
        raise ValueError("FULL_B_PLAN_CHANGED")
    request = exchange["request"]
    if (
        request["prompt"] != condition["prompt"]
        or request.get("format") != condition["schema"]
        or request["model"] != condition["profile"]["model"]
    ):
        raise ValueError("FULL_B_MODEL_REQUEST_CHANGED")
    return copy.deepcopy(original), call["evidence_id"]


def execute_approved_plan(
    db,
    change_id,
    plan_result,
    root,
    *,
    actor,
    explicit_lab_only=False,
    verifier=None,
    reuse_completed=True,
):
    """Use the original V5 executor and optional independent V5 file verification.

    Only a previously initialized V5 LAB run directory is permitted. A complete
    receipt may be reused after independent verification; partial work is not rerun.
    The existing lifecycle remains REPORTED_COMPLETE until its ordinary next steps.
    """
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
    change = binding = plan = eid = planner = receipt_path = None
    receipt = execution = verification = status = None
    reused = False

    def preflight():
        nonlocal change, binding, plan, eid, planner, receipt_path, root, reused
        if explicit_lab_only is not True:
            raise PermissionError("FULL_B_EXPLICIT_ISOLATED_LAB_REQUIRED")
        lifecycle.assert_change_integrity(db, change_id)
        change = lifecycle.get_change(db, change_id)
        if change["scope"] != lifecycle.SCOPE or not change.get("review_actor"):
            raise PermissionError("FULL_B_APPROVED_LAB_CHANGE_REQUIRED")
        if lifecycle.current_baseline(db)["version"] != change["base_version"]:
            raise ValueError("FULL_B_BASELINE_CHANGED")
        binding = _review_binding(db, change)
        plan, eid = _recorded_plan(db, plan_result, binding)
        agent.validate_plan(change["intended_spec"], plan)
        root = agent._valid_run(Path(root))
        if actor in {change["review_actor"], change["design_author"]}:
            raise PermissionError("FULL_B_SEPARATE_EXECUTOR_REQUIRED")
        if verifier is not None and (not verifier or verifier in {actor, change["design_author"]}):
            raise PermissionError("FULL_B_SEPARATE_VERIFIER_REQUIRED")
        planner = "RECORDED_B_MODEL_PLAN:" + eid
        receipt_path = root / "evidence/execution_receipt.json"
        reused = False

    def execute():
        nonlocal execution, receipt
        execution = agent.execute_agent_lab(
            db, change_id, root, actor=actor, plan=plan, planner=planner, explicit_lab_only=True
        )
        receipt = json.loads(receipt_path.read_bytes())

    def reuse():
        nonlocal execution, receipt, reused
        if verifier is None:
            raise ValueError("FULL_B_COMPLETED_RUN_REQUIRES_INDEPENDENT_VERIFICATION")
        receipt = json.loads(receipt_path.read_bytes())
        if (
            receipt.get("change_id") != change_id
            or receipt.get("actor") != actor
            or change["implementation_actor"] != actor
            or receipt.get("design_sha256") != binding["approved_design_sha256"]
            or receipt.get("base_version") != binding["base_version"]
            or receipt.get("plan") != plan
            or receipt.get("planner") != planner
        ):
            raise ValueError("FULL_B_EXISTING_EXECUTION_BINDING_CHANGED")
        execution = {
            "status": "REPORTED_COMPLETE_NOT_VERIFIED",
            "root": str(root),
            "change_id": change_id,
            "planner": planner,
            "bundle": str(root / "inbox/agent_work_evidence.zip"),
            "baseline_version": change["base_version"],
        }
        reused = True

    def reject():
        raise PermissionError("FULL_B_EXISTING_EXECUTION_RECONCILE_NO_RESEND")

    def verify():
        nonlocal verification, status
        verification = (
            agent.verify_agent_lab(db, change_id, root, verifier=verifier)
            if verifier is not None
            else None
        )
        if reused and verification["status"] != "PASS_LAB_FILE_ONLY":
            raise ValueError("FULL_B_EXISTING_EXECUTION_NOT_VERIFIED")
        status = (
            "LAB_FILE_EXECUTED_AND_CHECKED_NOT_ACCEPTED"
            if verification and verification["status"] == "PASS_LAB_FILE_ONLY"
            else "HOLD" if verification else "REPORTED_COMPLETE_NOT_VERIFIED"
        )

    def finish():
        flow.output = {
            "status": status,
            "execution": execution,
            "receipt": receipt,
            "verification": verification,
            "binding": binding,
            "plan_evidence_id": eid,
            "reused_receipt": reused,
            "actual_llm_calls": 0,
            "enterprise_writes": 0,
            "approval_granted": False,
            "baseline_updated": False,
            "accepted": False,
        }

    def choose_execution():
        if change["status"] == "APPROVED_LAB_ONLY":
            return "execute"
        if (
            reuse_completed
            and change["status"] == "REPORTED_COMPLETE"
            and receipt_path.is_file()
            and (not receipt_path.is_symlink())
        ):
            return "reuse"
        return "reject"

    for name, function in {
        "preflight": preflight,
        "execute": execute,
        "reuse": reuse,
        "reject": reject,
        "verify": verify,
        "finish": finish,
    }.items():
        flow.node(graph, name, function)
    graph.add_edge(START, "preflight")
    graph.add_conditional_edges("preflight", lambda _: flow.choose(choose_execution))
    for name in ("execute", "reuse"):
        graph.add_edge(name, "verify")
    graph.add_edge("reject", END)
    graph.add_edge("verify", "finish")
    graph.add_edge("finish", END)
    return invoke(graph, db, "approved-plan", change_id, flow)
