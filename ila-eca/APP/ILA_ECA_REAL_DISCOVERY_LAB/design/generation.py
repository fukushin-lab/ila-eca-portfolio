"""A/B adapters over existing design artifacts and reviewed LAB lifecycle.

A descriptive LLM proposal is never converted into an executable specification.
Only the caller's explicit spec may enter the existing change review. B plans
the ordering of already-approved service IDs and never executes any operation.
"""

from contextlib import closing
from pathlib import Path
import copy
import json
import sqlite3
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect
from ILA_ECA_REAL_DISCOVERY_LAB.design import non_aws as nd
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle import changes as lc
from ILA_ECA_REAL_DISCOVERY_LAB.design import change as sd
from ILA_ECA_REAL_DISCOVERY_LAB.lifecycle.planning import deterministic_order, validate_plan
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import IncidentModelProfile


def generate_source_design(
    db,
    *,
    scope,
    design_id,
    task,
    source_evidence_ids,
    model="qwen3:8b",
    generator=None,
    generation_options=None,
):
    """Reuse received-source generation and its same-data document renderer."""
    options = dict(generation_options or {})
    if set(options) - {"opener", "model_digest", "runtime_profile"}:
        raise ValueError("FULL_A_GENERATION_OPTIONS_INVALID")
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
    generated = document = None

    def generate():
        nonlocal generated
        generated = (generator or nd.generate_design)(
            db, scope=scope, task=task, evidence_ids=source_evidence_ids, model=model, **options
        )

    def render():
        nonlocal document
        try:
            document = nd.create_proposal_document(
                db,
                design_id=design_id,
                generation_evidence_id=generated["evidence_id"],
                scope=scope,
            )
        except BaseException as exc:
            # Preserve the completed/cached attempt when a later artifact step fails.
            # Current invocation count differs from the original count on a replay.
            exc.design_evidence_id = generated["evidence_id"]
            exc.design_payload = {
                **generated["payload"],
                "actual_llm_calls": generated["actual_llm_calls"],
            }
            exc.design_cache_hit = generated["cache_hit"]
            raise

    def finish():
        flow.output = {
            "status": "AWAITING_REVIEW",
            "generation": generated,
            "document": document,
            "scope": "RECEIVED_SOURCE_NON_AWS_CHANGE_OR_ADDITIONAL_BUILD_PROPOSAL",
            "execution_state": "NOT_PERFORMED",
            "approval_granted": False,
            "baseline_updated": False,
        }

    for name, function in {"generate": generate, "render": render, "finish": finish}.items():
        flow.node(graph, name, function)
    for first, second in [
        (START, "generate"),
        ("generate", "render"),
        ("render", "finish"),
        ("finish", END),
    ]:
        graph.add_edge(first, second)
    return invoke(graph, db, "source-design", [scope, design_id, task, source_evidence_ids], flow)


def bind_design_to_change(
    db,
    *,
    scope,
    design_id,
    revision,
    change_id,
    requested_by,
    intended_spec,
    author="LOCAL_LLM_DESIGN_AUTHOR",
    purpose=None,
    work_plan=None,
):
    """Attach an immutable generated proposal to an explicit existing-LAB target.

    No target is inferred from components, prose, or IaC in the model's proposal.
    The existing lifecycle validates supported targets, content and reviewer roles.
    """
    db = Path(db)
    if scope != lc.SCOPE:
        raise PermissionError("FULL_A_CHANGE_SCOPE_MISMATCH")
    if type(intended_spec) is not dict:
        raise ValueError("FULL_A_EXPLICIT_INTENDED_SPEC_REQUIRED")
    with closing(connect(db)) as con:
        document = nd.verify_proposal_from_connection(con, db, design_id, revision, scope)
    data = document["data"]
    purpose = data["request"]["goal"] if purpose is None else purpose
    details = {
        "document_reviews": [{"design_id": design_id, "revision": revision}],
        "unknowns": copy.deepcopy(data["request"]["input_unknowns"]),
        "target_spec_origin": "EXPLICIT_CALLER_INPUT_NOT_INFERRED_FROM_MODEL_PROSE",
        "construction": {"state": "NOT_PERFORMED"},
        "source_generation_evidence_id": data["generation_evidence_id"],
    }
    try:
        change = lc.get_change(db, change_id)
    except ValueError as exc:
        if "Record not found" not in str(exc):
            raise
        change = None
    if change is None:
        change = lc.propose_change(
            db,
            change_id=change_id,
            requested_by=requested_by,
            purpose=purpose,
            intended_spec=copy.deepcopy(intended_spec),
        )
    elif (
        change["intended_spec"] != intended_spec
        or change["requested_by"] != requested_by
        or change["purpose"] != purpose
    ):
        raise ValueError("FULL_A_CHANGED_CHANGE_REQUEST_REPLAY")
    lc.assert_change_integrity(db, change_id)
    if change["status"] == "DRAFT":
        if work_plan:
            lc.register_work_plan(db, change_id, work_plan)
        artifact = sd.create_template_draft(
            db,
            change_id,
            author=author,
            design_origin="AI",
            model_id=data["model"],
            details=details,
        )
    else:
        if work_plan:
            current = [
                {k: r[k] for k in ("step_id", "description")}
                for r in lc.work_progress(db, change_id)
            ]
            if current != work_plan:
                raise ValueError("FULL_A_CHANGED_WORK_PLAN_REPLAY")
        expected = sd.prepare_details(db, change_id, details)
        with closing(connect(db)) as con:
            con.row_factory = sqlite3.Row
            row = con.execute(
                "SELECT * FROM lifecycle_design_artifact_v2 WHERE change_id=? ORDER BY revision DESC LIMIT 1",
                (change_id,),
            ).fetchone()
        if not row or not sd.verify_artifact_content(db, row):
            raise ValueError("FULL_A_EXISTING_ARTIFACT_INVALID")
        saved = json.loads(
            (db.resolve().parent / "design_drafts_lab" / row["structured_path"]).read_bytes()
        )
        if (
            saved["details"] != expected
            or change["design_origin"] != "AI"
            or change["design_author"] != author
            or change["model_id"] != data["model"]
        ):
            raise ValueError("FULL_A_CHANGED_ANNEX_OR_AUTHOR_REPLAY")
        artifact = {
            "artifact_id": row["artifact_id"],
            "change_id": change_id,
            "revision": row["revision"],
            "path": str(db.resolve().parent / "design_drafts_lab" / row["relative_path"]),
            "structured_path": str(
                db.resolve().parent / "design_drafts_lab" / row["structured_path"]
            ),
            "document_sha256": row["document_sha256"],
            "document_record": json.loads(row["record_json"]),
        }
    artifact = {
        k: artifact[k]
        for k in (
            "artifact_id",
            "change_id",
            "revision",
            "path",
            "structured_path",
            "document_sha256",
            "document_record",
        )
    }
    return {
        "status": lc.get_change(db, change_id)["status"],
        "change_id": change_id,
        "artifact": artifact,
        "proposal_document": document,
        "execution_state": "NOT_PERFORMED",
        "approval_granted": False,
        "baseline_updated": False,
    }


PLAN_INSTRUCTION = """/no_think
Schedule the already-approved isolated LAB service IDs. Return only order and note.
Every declared dependency must precede its service, and each service appears exactly once.
This is ordering only. Do not add commands, paths, configuration, services or approval.
The approved change remains the source of executable operations; no execution is requested.
"""


def _review_event(db, change):
    """Reference the existing approval event; never create an approval."""
    with closing(connect(db)) as con:
        con.row_factory = sqlite3.Row
        rows = [
            dict(row)
            for row in con.execute(
                "SELECT * FROM lifecycle_event_v1 WHERE change_id=? AND event_type='APPROVED_LAB_ONLY'",
                (change["change_id"],),
            ).fetchall()
        ]
    matching = [
        row
        for row in rows
        if row["actor"] == change["review_actor"]
        and json.loads(row["details_json"]).get("reviewed_digest") == change["design_sha256"]
    ]
    if len(matching) != 1:
        raise ValueError("FULL_B_CURRENT_REVIEW_EVENT_REQUIRED")
    return matching[0]


def plan_approved_change(db, change_id, *, request_id=None, profile=None, invoke=None):
    """Plan approved IDs; original V5/V6/V9 execution gates remain authoritative."""
    change = lc.get_change(db, change_id)
    lc.assert_change_integrity(db, change_id)
    base = lc.current_baseline(db)
    if change["status"] != "APPROVED_LAB_ONLY" or not change["review_actor"]:
        raise PermissionError("FULL_B_APPROVED_LAB_CHANGE_REQUIRED")
    if change["scope"] != lc.SCOPE or change["base_version"] != base["version"]:
        raise ValueError("FULL_B_BASELINE_OR_SCOPE_CHANGED")
    review = _review_event(db, change)
    spec = change["intended_spec"]
    deterministic_order(spec)
    services = [{"id": s["id"], "depends_on": sorted(s["depends_on"])} for s in spec["services"]]
    ids = [s["id"] for s in services]
    schema = {
        "type": "object",
        "properties": {
            "order": {
                "type": "array",
                "items": {"type": "string", "enum": ids},
                "minItems": len(ids),
                "maxItems": len(ids),
                "uniqueItems": True,
            },
            "note": {"type": "string"},
        },
        "required": ["order", "note"],
        "additionalProperties": False,
    }
    binding = {
        "change_id": change_id,
        "approved_design_sha256": change["design_sha256"],
        "base_version": change["base_version"],
        "intended_spec_sha256": data_digest(spec),
        "scope": change["scope"],
        "review_actor": change["review_actor"],
        "review_event_id": review["event_id"],
    }

    def validator(value):
        validate_plan(spec, value)
        return value

    input_data = {
        "planner_scope": "ORDER_OF_ALREADY_APPROVED_SERVICE_IDS_ONLY",
        "approved_change_ref": binding,
        "services": services,
    }
    if invoke is None:
        from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import infer

        result = infer(
            db,
            scope=lc.SCOPE,
            route="B",
            request_id=request_id or change_id + "-PLAN",
            instruction=PLAN_INSTRUCTION,
            input_data=input_data,
            schema=schema,
            validator=validator,
            profile=profile or IncidentModelProfile(model="qwen3:8b", allowed_models=("qwen3:8b",)),
        )
    else:
        result = invoke(
            instruction=PLAN_INSTRUCTION, input_data=input_data, schema=schema, validator=validator
        )
    try:
        lc.assert_change_integrity(db, change_id)
        fresh = lc.get_change(db, change_id)
        if (
            fresh["status"] != "APPROVED_LAB_ONLY"
            or fresh["design_sha256"] != binding["approved_design_sha256"]
            or fresh["review_actor"] != binding["review_actor"]
            or _review_event(db, fresh) != review
            or lc.current_baseline(db)["version"] != binding["base_version"]
        ):
            raise ValueError("FULL_B_REVIEW_CHANGED_DURING_PLANNING")
        if result["status"] != "GENERATED":
            return {
                "status": "HOLD",
                "plan": None,
                "binding": binding,
                "call": result,
                "execution_state": "NOT_PERFORMED",
                "approval_granted": False,
            }
        plan = validator(result["value"])
    except BaseException as exc:
        # The caller records a later validation failure with the already-saved
        # original model attempt, rather than reporting zero calls or resending.
        exc.route_call = result
        raise
    return {
        "status": "PLANNED_UNEXECUTED",
        "plan": copy.deepcopy(plan),
        "binding": binding,
        "call": result,
        "execution_state": "NOT_PERFORMED",
        "approval_granted": False,
        "baseline_updated": False,
    }
