"""One case, one next read, re-evaluation. Existing audit DB remains canonical.

phase1_request/decision_log/phase1_action/evidence are reused; one head index
extends an existing request. Events and model exchanges are immutable Evidence.
This adapter uses the existing Phase1 isolated-LAB principal, not enterprise IAM.
"""

from contextlib import closing
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
import copy
import json
import sqlite3
import uuid

from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect, save_evidence, utc_now
from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import (
    UnifiedPhase1,
    Request,
    Principal,
    _DIGEST,
    timestamp,
)
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest
from ILA_ECA_REAL_DISCOVERY_LAB.core.evidence import collect_evidence
from ILA_ECA_REAL_DISCOVERY_LAB.incident import reasoner as ir
from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import DEFAULT_READ_BYTES, positive_int
from ILA_ECA_REAL_DISCOVERY_LAB.core.workflows import (
    Cursor,
    Execution,
    StateGraph,
    START,
    END,
    invoke,
    wait_for_request,
)


@dataclass
class ReadOperation:
    operation_id: str
    target_ref: str
    source_ref: str
    description: str
    handler: object
    paths: list = field(default_factory=lambda: ["/values"])
    conditions: dict = field(default_factory=dict)
    window: dict = field(default_factory=dict)
    basis_type: str = "OBSERVATION"
    origin: str = "SYNTHETIC_LAB"
    effect: str = "READ"
    kind: str = "ADAPTER"

    def catalog(self):
        return {
            f.name: copy.deepcopy(getattr(self, f.name))
            for f in fields(self)
            if f.name != "handler"
        }


class ReadRegistry:
    def __init__(self, operations=()):
        self.operations = {o.operation_id: o for o in operations}
        if len(self.operations) != len(operations):
            raise ValueError("DUPLICATE_READ_OPERATION")
        for o in operations:
            if o.effect != "READ" or not callable(o.handler):
                raise PermissionError("INVESTIGATION_READ_ONLY")
            if not o.operation_id or not o.target_ref or not o.source_ref:
                raise ValueError("READ_OPERATION_IDENTITY_MISSING")

    def catalog(self):
        return [o.catalog() for o in self.operations.values()]

    def get(self, key, principal):
        principal.check()
        if "READ" not in principal.actions:
            raise PermissionError("READ_PERMISSION_REQUIRED")
        if key not in self.operations:
            raise PermissionError("READ_ADAPTER_UNAVAILABLE")
        op = self.operations[key]
        if op.effect != "READ":
            raise PermissionError("INVESTIGATION_READ_ONLY")
        return op


class Investigation:
    def __init__(
        self, db, *, registry=None, reasoner=None, read_result_max_bytes=DEFAULT_READ_BYTES
    ):
        self.db = Path(db)
        self.gateway = UnifiedPhase1(self.db)
        self.registry = registry or ReadRegistry()
        self.reasoner = reasoner
        self.read_result_max_bytes = positive_int(
            read_result_max_bytes, "READ_RESULT_CAPACITY_INVALID"
        )
        lookup = ReadOperation(
            "audit.lookup",
            "CURRENT-CASE",
            "audit://current-case",
            "Return exact original fields for selected directory fact_refs; no new observation",
            self._lookup,
            kind="AUDIT_LOOKUP",
        )
        if (
            "audit.lookup" in self.registry.operations
            and self.registry.operations["audit.lookup"].catalog() != lookup.catalog()
        ):
            raise ValueError("AUDIT_LOOKUP_ID_RESERVED")
        self.registry.operations["audit.lookup"] = lookup
        with closing(connect(self.db)) as con, con:
            con.execute("""CREATE TABLE IF NOT EXISTS incident_case_head_v1 (
                request_id TEXT PRIMARY KEY REFERENCES phase1_request_v1(request_id),
                scope TEXT NOT NULL,head_evidence_id TEXT,revision INTEGER NOT NULL)""")

    @classmethod
    def readonly(cls, db):
        obj = cls.__new__(cls)
        obj.db = Path(db)
        obj.gateway = UnifiedPhase1.__new__(UnifiedPhase1)
        obj.gateway.db = obj.db
        obj.registry = ReadRegistry()
        obj.reasoner = None
        return obj

    def _publish(self, scope, subject, adapter, source, payload, origin="INCIDENT_LAB_EXTENSION"):
        item = save_evidence(
            adapter=adapter, source=source, scope=scope, payload=payload, db_path=self.db
        )
        self.gateway._metadata(
            item["evidence_id"], subject, origin=origin, trust="UNVERIFIED_UNTIL_REVIEW"
        )
        return item["evidence_id"]

    def _lookup(self, context):
        case = self.get(context["case_id"], context["principal"])
        facts = self._facts(case["state"], context["principal"])
        requested = context["investigation"]["fact_refs"]
        if not requested or set(requested) - {f["fact_ref"] for f in facts}:
            raise ValueError("READ_AUDIT_FACT_UNKNOWN")
        return {
            "selections": [
                {"evidence_id": f["evidence_id"], "paths": [f.get("receipt_pointer", f["path"])]}
                for f in facts
                if f["fact_ref"] in requested
            ]
        }

    def _commit(self, state, head, kind, detail=None, *, action_update=None):
        state = copy.deepcopy(state)
        state["revision"] += 1
        eid = self._publish(
            state["scope"],
            state["request"]["subject_id"],
            "incident_event_v1",
            state["case_id"],
            {
                "case_id": state["case_id"],
                "previous": head,
                "state": state,
                "event": kind,
                "detail": detail or {},
                "state_sha256": data_digest(state),
            },
        )
        with closing(connect(self.db)) as con, con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT head_evidence_id,revision FROM incident_case_head_v1 WHERE request_id=?",
                (state["case_id"],),
            ).fetchone()
            if row is None or row[0] != head or row[1] != state["revision"] - 1:
                raise RuntimeError("INCIDENT_CONCURRENT_UPDATE_RELOAD")
            if action_update:
                aid, expected_sha, record = action_update
                con.row_factory = sqlite3.Row
                previous = con.execute(
                    "SELECT * FROM phase1_action_v1 WHERE action_id=?", (aid,)
                ).fetchone()
                if previous is None or data_digest(dict(previous)) != expected_sha:
                    raise ValueError("INCIDENT_PENDING_ACTION_CHANGED")
                con.execute(
                    "UPDATE phase1_action_v1 SET ended_at=?,result_status=?,after_json=?,result_json=? WHERE action_id=?",
                    (
                        record["ended_at"],
                        record["result_status"],
                        record["after_json"],
                        record["result_json"],
                        aid,
                    ),
                )
            con.execute(
                "UPDATE incident_case_head_v1 SET head_evidence_id=?,revision=? WHERE request_id=?",
                (eid, state["revision"], state["case_id"]),
            )
        return self.get(state["case_id"], Principal(state["request"]["requester_ref"]))

    def _raw(self, eid, principal):
        self.gateway.verify_evidence(eid, principal=principal)
        with closing(connect(self.db)) as con:
            con.row_factory = sqlite3.Row
            row = con.execute("SELECT * FROM evidence WHERE evidence_id=?", (eid,)).fetchone()
        if row["adapter"] == "received_document_search_v1":
            from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.intake import verify_search_evidence

            with closing(connect(self.db)) as con:
                verify_search_evidence(con, eid, principal.scope)
        return dict(row), json.loads(row["payload_json"])

    def get(self, case_id, principal, *, head=None):
        principal.check()
        if "READ" not in principal.actions:
            raise PermissionError("READ_PERMISSION_REQUIRED")
        with closing(connect(self.db)) as con:
            row = con.execute(
                "SELECT scope,head_evidence_id,revision FROM incident_case_head_v1 WHERE request_id=?",
                (case_id,),
            ).fetchone()
        if row is None or row[0] != principal.scope:
            raise PermissionError("INCIDENT_CASE_ACCESS_DENIED")
        selected = head or row[1]
        cursor = row[1]
        seen = set()
        chosen = None
        expected = row[2]
        while cursor:
            if cursor in seen or len(seen) > 512:
                raise ValueError("INCIDENT_EVENT_CHAIN_INVALID")
            seen.add(cursor)
            _, event = self._raw(cursor, principal)
            s = event["state"]
            if (
                event["case_id"] != case_id
                or s["case_id"] != case_id
                or s["scope"] != principal.scope
                or s["revision"] != expected
                or data_digest(s) != event["state_sha256"]
            ):
                raise ValueError("INCIDENT_EVENT_BINDING_CHANGED")
            if cursor == selected:
                chosen = copy.deepcopy(s)
            expected -= 1
            cursor = event["previous"]
        if expected != 0 or chosen is None:
            raise ValueError("INCIDENT_EVENT_HISTORY_MISSING")
        with closing(connect(self.db)) as con:
            original = con.execute(
                "SELECT payload_sha256 FROM phase1_request_v1 WHERE request_id=?", (case_id,)
            ).fetchone()
            if not original or original[0] != _DIGEST(chosen["request"]):
                raise ValueError("INCIDENT_REQUEST_CHANGED")
            for binding in chosen["bindings"]:
                table, key = binding["table"], binding["key"]
                if table not in {"decision_log", "phase1_action_v1", "phase1_decision_ext_v1"}:
                    raise ValueError("INCIDENT_BINDING_TABLE_INVALID")
                column = "action_id" if table == "phase1_action_v1" else "decision_id"
                con.row_factory = sqlite3.Row
                record = con.execute(f"SELECT * FROM {table} WHERE {column}=?", (key,)).fetchone()
                if record is None or data_digest(dict(record)) != binding["sha256"]:
                    raise ValueError("INCIDENT_AUDIT_BINDING_CHANGED")
                if table == "decision_log":
                    for eid in json.loads(record["evidence_ids_json"]):
                        self._raw(eid, principal)
            pending = chosen["pending"]
            if pending and pending["kind"] == "ACTION":
                con.row_factory = sqlite3.Row
                record = con.execute(
                    "SELECT * FROM phase1_action_v1 WHERE action_id=?", (pending["action_id"],)
                ).fetchone()
                if record is None or data_digest(dict(record)) != pending["reserved_sha256"]:
                    raise ValueError("INCIDENT_PENDING_ACTION_CHANGED")
        # Validate original source rows even for historical report/repair snapshots.
        self._facts(chosen, principal)
        for eid in chosen["model_records"]:
            self._raw(eid, principal)
        return {"state": chosen, "head": selected}

    def start(self, req, principal, *, incident, max_steps=8, max_calls=12):
        req.check()
        principal.check()
        if (
            req.request_type != "INCIDENT"
            or req.scope != principal.scope
            or req.requester_ref != principal.ref
            or req.requested_effect not in {"READ", "ADVISE"}
            or not {"READ", "ADVISE"} <= set(principal.actions)
        ):
            raise PermissionError("INCIDENT_EXISTING_PRINCIPAL_DENIED")
        if (
            type(max_steps) is not int
            or max_steps < 1
            or type(max_calls) is not int
            or max_calls < 1
        ):
            raise ValueError("INCIDENT_BUDGET_INVALID")
        if set(incident) != {
            "symptom",
            "occurred_at",
            "window",
            "targets",
            "unknowns",
            "baseline_ref",
            "evidence_selections",
        }:
            raise ValueError("INCIDENT_INPUT_INVALID")
        if not incident["symptom"].strip() or req.subject_id not in incident["targets"]:
            raise ValueError("INCIDENT_TARGET_OR_SYMPTOM_MISSING")
        timestamp(incident["occurred_at"])
        timestamp(incident["window"]["start"])
        timestamp(incident["window"]["end"])
        if timestamp(incident["window"]["start"]) > timestamp(incident["window"]["end"]):
            raise ValueError("INCIDENT_WINDOW_INVALID")
        # Incorporate original incident content in the existing request's replay hash.
        req = Request(
            **{
                **asdict(req),
                "details": {
                    **req.details,
                    "incident": incident,
                    "max_steps": max_steps,
                    "max_calls": max_calls,
                },
            }
        )
        req.check()
        with closing(connect(self.db)) as con:
            existing = con.execute(
                "SELECT payload_sha256 FROM phase1_request_v1 WHERE request_id=?", (req.request_id,)
            ).fetchone()
            case = con.execute(
                "SELECT head_evidence_id FROM incident_case_head_v1 WHERE request_id=?",
                (req.request_id,),
            ).fetchone()
        if existing and existing[0] != _DIGEST(asdict(req)):
            raise ValueError("INCIDENT_CHANGED_REQUEST_REPLAY")
        if case and case[0]:
            return self.get(req.request_id, principal)
        if not existing:
            self.gateway._audit(req)
        with closing(connect(self.db)) as con, con:
            con.execute(
                "INSERT OR IGNORE INTO incident_case_head_v1 VALUES(?,?,NULL,0)",
                (req.request_id, req.scope),
            )
        state = {
            "schema": "ila.eca.incident-investigation.v1",
            "case_id": req.request_id,
            "scope": req.scope,
            "request": asdict(req),
            "incident": copy.deepcopy(incident),
            "revision": 0,
            "status": "ACTIVE",
            "reason": "INITIAL_INTAKE_NOT_CAUSE_CONFIRMATION",
            "hypotheses": [],
            "retired": [],
            "selections": [],
            "bindings": [],
            "model_records": [],
            "decision_ids": [],
            "action_ids": [],
            "last_result": [],
            "pending": None,
            "steps_used": 0,
            "calls_used": 0,
            "max_steps": max_steps,
            "max_calls": max_calls,
            "repair_candidates": [],
            "change_links": [],
            "repair_outcomes": [],
            "shown_fact_refs": [],
            "requested_fact_refs": [],
        }
        for selection in incident["evidence_selections"]:
            self._add_selection(state, selection, principal)
        report = self._publish(
            req.scope,
            req.subject_id,
            "incident_reported_symptom_v1",
            req.request_id,
            {
                "target_ref": req.subject_id,
                "source_observed_at": incident["occurred_at"],
                "basis_type": "UNVERIFIED_REPORT",
                "acquisition_state": "OBSERVED",
                "coverage": "User-reported symptom, not a measured diagnosis",
                "conditions": {},
                "values": {"symptom": incident["symptom"]},
            },
        )
        self._add_selection(
            state,
            {"evidence_id": report, "paths": ["/values"], "subject_ref": req.subject_id},
            principal,
        )
        return self._commit(state, None, "CASE_STARTED")

    def _add_selection(self, state, selection, principal):
        eid = selection["evidence_id"]
        try:
            self.gateway.verify_evidence(eid, principal=principal)
        except PermissionError:
            # This only pins an existing same-domain receipt, never upgrades trust.
            self.gateway._metadata(
                eid,
                selection.get("subject_ref", state["request"]["subject_id"]),
                origin="EXISTING_AUDIT_RECEIPT",
                trust="UNVERIFIED_IMPORTED",
            )
            self.gateway.verify_evidence(eid, principal=principal)
        collected = collect_evidence(self.db, scope=state["scope"], selections=[selection])[
            "evidence"
        ][0]
        if collected["state"] != "COLLECTED_AT_RECORDED_TIME":
            raise ValueError("INCIDENT_SOURCE_NOT_COLLECTED")
        item = {"selection": copy.deepcopy(selection), "record_sha256": collected["record_sha256"]}
        if item not in state["selections"]:
            state["selections"].append(item)

    def _facts(self, state, principal):
        facts = {}
        for item in state["selections"]:
            selection = item["selection"]
            row, raw = self._raw(selection["evidence_id"], principal)
            collected = collect_evidence(self.db, scope=state["scope"], selections=[selection])[
                "evidence"
            ][0]
            if collected.get("record_sha256") != item["record_sha256"]:
                raise ValueError("INCIDENT_SOURCE_RECEIPT_CHANGED")
            meta = self.gateway.verify_evidence(selection["evidence_id"], principal=principal)
            if row["adapter"] == "received_document_search_v1":
                # A new search receipt is not new technical evidence. Keep each
                # exact paragraph under its document/version, never a live host.
                for hit_index, hit in enumerate(raw["hits"]):
                    for part_index, part in enumerate(hit["supporting_parts"]):
                        meaning = {
                            "scope": state["scope"],
                            "subject_ref": "document:" + hit["source_id"],
                            "source": hit["source_ref"],
                            "version": hit["version"],
                            "product": hit["product"],
                            "document_state": hit["document_state"],
                            "source_sha256": hit["source_sha256"],
                            "section_id": hit["section_id"],
                            "path": f"/source_text/{part['start']}:{part['end']}",
                            "basis_type": "REFERENCE",
                            "field": {
                                "state": "OBSERVED",
                                "path": f"/source_text/{part['start']}:{part['end']}",
                                "value": part["text"],
                            },
                        }
                        fid = "F" + data_digest(meaning)[:24]
                        facts.setdefault(
                            fid,
                            {
                                "fact_ref": fid,
                                **meaning,
                                "field_state": "OBSERVED",
                                "evidence_id": row["evidence_id"],
                                "receipt_pointer": f"/hits/{hit_index}/supporting_parts/{part_index}/text",
                                "record_sha256": item["record_sha256"],
                                "source_capture_at": row["observed_at"],
                                "observed_at": row["observed_at"],
                                "conditions": raw["filters"],
                                "coverage": "Retrieved source paragraphs only",
                                "observation_time_basis": "REFERENCE_RECEIPT_NOT_RUNTIME_OBSERVATION",
                                "acquisition_state": "OBSERVED",
                                "within_incident_window": False,
                                "receipt_trust": meta["trust_status"],
                            },
                        )
                if not raw["hits"]:
                    fid = (
                        "F"
                        + data_digest(
                            {
                                "scope": state["scope"],
                                "query": raw["query"],
                                "source_ids": raw["source_ids"],
                                "filters": raw["filters"],
                            }
                        )[:24]
                    )
                    facts.setdefault(
                        fid,
                        {
                            "fact_ref": fid,
                            "subject_ref": meta["subject_id"],
                            "source": row["source"],
                            "path": "/hits",
                            "field": {"path": "/hits", "state": "UNOBSERVED", "value": []},
                            "field_state": "UNOBSERVED",
                            "basis_type": "REFERENCE",
                            "acquisition_state": "NOT_OBSERVED",
                            "coverage": "No compatible received source; not a normality check",
                            "evidence_id": row["evidence_id"],
                            "record_sha256": item["record_sha256"],
                            "observed_at": row["observed_at"],
                            "conditions": raw["filters"],
                            "within_incident_window": False,
                            "receipt_trust": meta["trust_status"],
                        },
                    )
                continue
            for f in collected["fields"]:
                source_time = raw.get("source_observed_at")
                observed = source_time or row["observed_at"]
                when = timestamp(observed)
                window = state["incident"]["window"]
                meaning = {
                    "scope": state["scope"],
                    "subject_ref": meta["subject_id"],
                    "source": row["source"],
                    "path": f["path"],
                    "observed_at": observed,
                    "conditions": raw.get("conditions", {}),
                    "field": f,
                    "observation_time_basis": (
                        "SOURCE_REPORTED" if source_time else "RECEIPT_TIME_ONLY"
                    ),
                    "basis_type": raw.get("basis_type", "UNVERIFIED_RECEIPT"),
                    "coverage": raw.get("coverage", "NOT_SPECIFIED"),
                    "acquisition_state": raw.get("acquisition_state", "NOT_ASSESSED"),
                }
                fid = "F" + data_digest(meaning)[:24]
                facts.setdefault(
                    fid,
                    {
                        "fact_ref": fid,
                        **meaning,
                        "field_state": f["state"],
                        "evidence_id": row["evidence_id"],
                        "record_sha256": item["record_sha256"],
                        "source_capture_at": row["observed_at"],
                        "within_incident_window": (
                            timestamp(window["start"]) <= when <= timestamp(window["end"])
                            if source_time
                            else None
                        ),
                        "receipt_trust": meta["trust_status"],
                    },
                )
        return list(facts.values())

    def context(self, case, principal):
        state = case["state"]
        facts = self._facts(state, principal)
        refs = {r for h in state["hypotheses"] for r in h["support_refs"] + h["counter_refs"]}
        refs.update(state["requested_fact_refs"])
        essential = [f for f in facts if f["fact_ref"] in refs]
        latest = [
            f for f in facts if f["evidence_id"] in state["last_result"] and f not in essential
        ]
        other = latest + [f for f in reversed(facts) if f not in essential and f not in latest]
        context = {
            "case_id": state["case_id"],
            "incident": {k: v for k, v in state["incident"].items() if k != "evidence_selections"},
            "hypotheses": state["hypotheses"],
            "retired": state["retired"],
            "last_repair_outcomes": state["repair_outcomes"][-2:],
            "last_result_evidence_ids": state["last_result"],
            "operations": self.registry.catalog(),
            "loaded_facts": [],
            "directory": [{k: v for k, v in f.items() if k not in {"field"}} for f in facts],
            "omitted_fact_refs": [],
            "prior_model_assessment_is_causal_proof": False,
        }
        context["loaded_facts"] = essential + other
        return context

    def _bind(self, state, table, key, column):
        with closing(connect(self.db)) as con:
            con.row_factory = sqlite3.Row
            row = con.execute(f"SELECT * FROM {table} WHERE {column}=?", (key,)).fetchone()
        state["bindings"].append({"table": table, "key": key, "sha256": data_digest(dict(row))})

    def _decision(self, state, principal, value, model_eid):
        did = str(uuid.uuid4())
        now = utc_now()
        refs = [x["selection"]["evidence_id"] for x in state["selections"]] + [model_eid]
        with closing(connect(self.db)) as con, con:
            con.execute(
                "INSERT INTO decision_log VALUES(?,?,?,?,?,?)",
                (
                    did,
                    now,
                    "INCIDENT " + state["case_id"],
                    "INFORMATIONAL_ONLY",
                    canonical_json(list(dict.fromkeys(refs))),
                    "MODEL_PROPOSAL_NOT_CAUSAL_PROOF",
                ),
            )
            con.execute(
                "INSERT INTO phase1_decision_ext_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    did,
                    state["case_id"],
                    value["next_mode"],
                    "[]",
                    "incident-loop-v1",
                    "UNASSESSED",
                    canonical_json(value["missing"]),
                    "NOT_AN_APPROVAL",
                    state["scope"],
                    "[]",
                    "incident_read_registry",
                    canonical_json(
                        {
                            "assessment": value,
                            "catalog_sha256": data_digest(self.registry.catalog()),
                        }
                    ),
                ),
            )
        self._bind(state, "decision_log", did, "decision_id")
        self._bind(state, "phase1_decision_ext_v1", did, "decision_id")
        state["decision_ids"].append(did)
        return did

    def advance(self, case_id, principal, *, execute_investigation=True):
        """One model assessment and its selected read, routed by LangGraph."""
        flow = Execution()
        graph = StateGraph(Cursor)

        def prepare():
            value = self._reserve_model(case_id, principal)
            if "state" in value:
                flow.output = value
            else:
                flow.values["prepared"] = value

        def evaluate():
            flow.values["response"] = self._evaluate_model(
                case_id, principal, flow.values["prepared"]
            )

        def adopt():
            value = self._adopt_model(
                case_id, principal, flow.values["prepared"], flow.values["response"]
            )
            if "head" in value:
                flow.output = value
            else:
                flow.values["decision"] = value

        def finish(handler):
            flow.output = handler(case_id, principal, flow.values["decision"])

        flow.node(graph, "reserve_model", prepare)
        flow.node(graph, "evaluate_model", evaluate)
        flow.node(graph, "adopt_model", adopt)
        flow.node(graph, "information_required", lambda: finish(self._hold_assessment))
        flow.node(graph, "repair_candidate", lambda: finish(self._repair_assessment))
        flow.node(
            graph,
            "selected_read",
            lambda: finish(
                lambda cid, actor, decision: self._read_assessment(
                    cid, actor, decision, execute_investigation=execute_investigation
                )
            ),
        )
        graph.add_edge(START, "reserve_model")
        graph.add_conditional_edges(
            "reserve_model",
            lambda _: flow.choose(END if flow.output is not None else "evaluate_model"),
        )
        graph.add_edge("evaluate_model", "adopt_model")
        graph.add_conditional_edges(
            "adopt_model",
            lambda _: flow.choose(
                lambda: (
                    END
                    if flow.output is not None
                    else {
                        "HOLD": "information_required",
                        "PROPOSE_REPAIR": "repair_candidate",
                        "INVESTIGATE": "selected_read",
                    }[flow.values["decision"]["value"]["next_mode"]]
                )
            ),
        )
        for end in ("information_required", "repair_candidate", "selected_read"):
            graph.add_edge(end, END)
        head = self.get(case_id, principal)["head"]
        return invoke(graph, self.db, "incident-assessment", [principal.scope, case_id, head], flow)

    def run(self, case_id, principal, *, cancel_requested=None):
        """Continue only ACTIVE business state; explicit native resume stays mandatory."""
        flow = Execution()
        graph = StateGraph(Cursor)

        def inspect():
            flow.output = self.get(case_id, principal)

        def choose(_):
            if flow.error is not None:
                return END
            state = flow.output["state"]
            if state["status"] != "ACTIVE" or state["pending"]:
                return flow.choose(
                    "wait" if state["status"] in {"ACTIVE", "HOLD", "WAITING_REPAIR"} else END
                )
            return flow.choose(
                "cancel" if cancel_requested and cancel_requested() else "assessment"
            )

        def advance():
            flow.output = self.advance(case_id, principal)

        def cancel():
            flow.output = self.cancel(
                case_id, principal, "USER_REQUESTED_STOP_BETWEEN_INVESTIGATION_STEPS"
            )

        flow.node(graph, "inspect", inspect)
        flow.node(graph, "assessment", advance)
        flow.node(graph, "cancel", cancel)
        flow.node(graph, "wait", wait_for_request)
        graph.add_edge(START, "inspect")
        graph.add_conditional_edges("inspect", choose)
        graph.add_edge("assessment", "inspect")
        graph.add_edge("cancel", END)
        graph.add_edge("wait", "inspect")
        maximum = self.get(case_id, principal)["state"]["max_calls"]
        return invoke(
            graph,
            self.db,
            "incident-loop",
            [principal.scope, case_id],
            flow,
            limit=4 * maximum + 32,
            resume_wait=True,
        )

    def _reserve_model(self, case_id, principal):
        if "ADVISE" not in principal.actions:
            raise PermissionError("ADVISE_PERMISSION_REQUIRED")
        case = self.get(case_id, principal)
        state = case["state"]
        if state["pending"] or state["status"] != "ACTIVE":
            return case
        final_read_evaluation = (
            self.reasoner is not None
            and getattr(self.reasoner, "require_evaluation_slot", False)
            and bool(state["last_result"])
        )
        if (state["steps_used"] >= state["max_steps"] and not final_read_evaluation) or state[
            "calls_used"
        ] >= state["max_calls"]:
            state.update(status="HOLD", reason="EXECUTION_BUDGET_REACHED_NOT_RESOLVED")
            return self._commit(state, case["head"], "BUDGET_REACHED")
        if self.reasoner is None:
            state.update(status="HOLD", reason="LOCAL_MODEL_NOT_ENABLED")
            return self._commit(state, case["head"], "MODEL_UNAVAILABLE")
        if hasattr(self.reasoner, "execution_identity"):
            identity = self.reasoner.execution_identity()
            if state.get("execution_identity") not in (None, identity):
                state.update(
                    status="HOLD", reason="INCIDENT_EXECUTION_PROFILE_CHANGED_NEW_TRIAL_REQUIRED"
                )
                return self._commit(state, case["head"], "EXECUTION_PROFILE_CHANGED")
            state["execution_identity"] = identity
        try:
            context = self.context(case, principal)
        except ValueError as exc:
            state.update(status="HOLD", reason=str(exc))
            return self._commit(state, case["head"], "CONTEXT_LIMIT")
        token = str(uuid.uuid4())
        state["calls_used"] += 1
        state["pending"] = {"kind": "MODEL", "token": token}
        attempt = self._publish(
            state["scope"],
            state["request"]["subject_id"],
            "incident_model_input_v1",
            case_id,
            {
                "token": token,
                "context": context,
                "prompt": ir.prompt(context),
                "schema": ir.generation_schema(context),
                "origin": self.reasoner.origin,
                "execution_identity": (
                    self.reasoner.execution_identity()
                    if hasattr(self.reasoner, "execution_identity")
                    else None
                ),
            },
        )
        state["model_records"].append(attempt)
        reserved = self._commit(state, case["head"], "MODEL_RESERVED")
        return {"case": reserved, "context": context, "token": token, "attempt": attempt}

    def _evaluate_model(self, case_id, principal, prepared):
        reserved = prepared["case"]
        state = reserved["state"]
        context = prepared["context"]
        token = prepared["token"]
        attempt = prepared["attempt"]
        started = perf_counter()
        generated = None
        try:
            generated = self.reasoner.assess(context)
            value = ir.validate(generated["value"], context)
            if self.context(reserved, principal) != context:
                raise ValueError("INCIDENT_MODEL_INPUT_CHANGED")
            result = {
                "status": "GENERATED",
                "token": token,
                "input_evidence_id": attempt,
                **generated,
                "elapsed_seconds": round(perf_counter() - started, 3),
            }
        except BaseException as exc:
            trace = getattr(exc, "incident_trace", generated.get("trace", {}) if generated else {})
            interrupted = not isinstance(exc, Exception)
            result = {
                "status": "INTERRUPTED" if interrupted else "FAILED",
                "token": token,
                "input_evidence_id": attempt,
                "error_type": type(exc).__name__,
                "error_code": getattr(
                    exc,
                    "incident_error_code",
                    (
                        str(exc)
                        if str(exc).startswith(("INCIDENT_", "READ_", "OLLAMA_", "LOCAL_"))
                        else type(exc).__name__
                    ),
                ),
                "trace": trace,
                "actual_llm_calls": (
                    generated.get("actual_llm_calls", 0)
                    if generated
                    else trace.get("actual_llm_calls", None if interrupted else 0)
                ),
                "origin": self.reasoner.origin,
                "elapsed_seconds": round(perf_counter() - started, 3),
            }
            from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import metrics

            result["metrics"] = metrics(
                trace,
                failure_stage=(
                    "INTERRUPTED"
                    if interrupted
                    else (
                        "REFERENCE_VALIDATION"
                        if generated
                        else trace.get("failure_stage", "MODEL_CALL")
                    )
                ),
            )
            if generated is not None:
                result["rejected_value"] = generated.get("value")
            if interrupted:
                self._publish(
                    state["scope"],
                    state["request"]["subject_id"],
                    "incident_model_result_v1",
                    case_id,
                    result,
                )
                raise
        eid = self._publish(
            state["scope"],
            state["request"]["subject_id"],
            "incident_model_result_v1",
            case_id,
            result,
        )
        return {
            "result": result,
            "eid": eid,
            "value": value if result["status"] == "GENERATED" else None,
        }

    def _adopt_model(self, case_id, principal, prepared, response):
        context = prepared["context"]
        token = prepared["token"]
        result = response["result"]
        eid = response["eid"]
        value = response["value"]
        current = self.get(case_id, principal)
        state = current["state"]
        if not state["pending"] or state["pending"]["token"] != token:
            raise RuntimeError("INCIDENT_MODEL_CLAIM_CHANGED")
        state["model_records"].append(eid)
        state["pending"] = None
        if result["status"] == "FAILED":
            if state["status"] == "CANCELED":
                return self._commit(state, current["head"], "MODEL_FAILURE_AFTER_CANCEL")
            state.update(status="HOLD", reason="MODEL_FAILURE_REVIEW_REQUIRED")
            return self._commit(state, current["head"], "MODEL_FAILED")
        did = self._decision(state, principal, value, eid)
        state["hypotheses"] = value["hypotheses"]
        state["retired"] += value["retired"]
        state["shown_fact_refs"] = [f["fact_ref"] for f in context["loaded_facts"]]
        if state["status"] == "CANCELED":
            return self._commit(state, current["head"], "MODEL_RESULT_AFTER_CANCEL")
        return {"state": state, "current": current, "value": value, "did": did, "eid": eid}

    def _hold_assessment(self, case_id, principal, decision):
        state = decision["state"]
        current = decision["current"]
        value = decision["value"]
        did = decision["did"]
        eid = decision["eid"]
        state.update(status="HOLD", reason="MODEL_REQUESTED_INFORMATION")
        return self._commit(
            state, current["head"], "INFORMATION_REQUIRED", {"missing": value["missing"]}
        )

    def _repair_assessment(self, case_id, principal, decision):
        state = decision["state"]
        current = decision["current"]
        value = decision["value"]
        did = decision["did"]
        eid = decision["eid"]
        state["repair_candidates"].append(
            {"decision_id": did, "proposal": value["repair"], "model_result_evidence_id": eid}
        )
        state.update(status="WAITING_REPAIR", reason="UNAPPROVED_MODEL_REPAIR_CANDIDATE")
        return self._commit(state, current["head"], "REPAIR_PROPOSED")

    def _read_assessment(self, case_id, principal, decision, *, execute_investigation):
        state = decision["state"]
        current = decision["current"]
        value = decision["value"]
        did = decision["did"]
        eid = decision["eid"]
        if (
            self.reasoner is not None
            and getattr(self.reasoner, "require_evaluation_slot", False)
            and state["calls_used"] >= state["max_calls"]
        ):
            state.update(status="HOLD", reason="EVALUATION_SLOT_REQUIRED_BEFORE_NEW_READ")
            return self._commit(state, current["head"], "NO_UNEVALUATED_READ")
        if not execute_investigation:
            state.update(status="HOLD", reason="COMPARISON_ASSESSMENT_ONLY_NO_READ")
            return self._commit(state, current["head"], "ASSESSMENT_ONLY_RECORDED")
        if state["steps_used"] >= state["max_steps"]:
            state.update(status="HOLD", reason="READ_BUDGET_REACHED_LAST_RESULT_EVALUATED")
            return self._commit(state, current["head"], "NO_UNEVALUATED_READ")
        decided = self._commit(state, current["head"], "NEXT_INVESTIGATION_SELECTED")
        return self.execute_selected(
            case_id, principal, value["investigation"], did, expected_head=decided["head"]
        )

    def execute_selected(
        self, case_id, principal, investigation, decision_id, *, expected_head=None
    ):
        case = self.get(case_id, principal)
        s = case["state"]
        if s["pending"] or s["status"] != "ACTIVE":
            return case
        if expected_head and expected_head != case["head"]:
            raise RuntimeError("INCIDENT_SELECTED_DECISION_STALE")
        if decision_id != s["decision_ids"][-1]:
            raise ValueError("INCIDENT_SELECTED_DECISION_MISMATCH")
        with closing(connect(self.db)) as con:
            proposed = json.loads(
                con.execute(
                    "SELECT proposal_json FROM phase1_decision_ext_v1 WHERE decision_id=?",
                    (decision_id,),
                ).fetchone()[0]
            )
        if (
            proposed["assessment"]["next_mode"] != "INVESTIGATE"
            or proposed["assessment"]["investigation"] != investigation
            or proposed["catalog_sha256"] != data_digest(self.registry.catalog())
        ):
            raise ValueError("INCIDENT_SELECTED_OPERATION_CHANGED")
        try:
            op = self.registry.get(investigation["operation_id"], principal)
        except PermissionError:
            s.update(status="HOLD", reason="READ_ADAPTER_UNAVAILABLE")
            return self._commit(s, case["head"], "ADAPTER_UNAVAILABLE")
        ir.validate_operation_arguments(investigation, op.catalog())
        key = data_digest(
            {
                "operation": op.catalog(),
                "query": investigation.get("query", ""),
                "fact_refs": investigation.get("fact_refs", []),
            }
        )
        with closing(connect(self.db)) as con:
            previous = [
                json.loads(r[0])
                for r in con.execute(
                    "SELECT before_json FROM phase1_action_v1 WHERE action_id IN (%s)"
                    % (",".join("?" for _ in s["action_ids"]) or "''"),
                    s["action_ids"],
                )
            ]
        if (
            any(p.get("operation_key") == key for p in previous)
            and not investigation["retry_reason"].strip()
        ):
            s.update(status="HOLD", reason="DUPLICATE_INVESTIGATION_REQUIRES_REASON")
            return self._commit(s, case["head"], "DUPLICATE_BLOCKED")
        if s["steps_used"] >= s["max_steps"]:
            s.update(status="HOLD", reason="EXECUTION_BUDGET_REACHED_NOT_RESOLVED")
            return self._commit(s, case["head"], "BUDGET_REACHED")
        action_id = str(uuid.uuid4())
        before = {"operation_key": key, "operation": op.catalog(), "investigation": investigation}
        with closing(connect(self.db)) as con, con:
            con.execute(
                "INSERT INTO phase1_action_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    action_id,
                    decision_id,
                    "READ_ONLY",
                    principal.ref,
                    op.operation_id,
                    None,
                    utc_now(),
                    "",
                    "RESERVED",
                    canonical_json(before),
                    "[]",
                    "[]",
                    None,
                    "{}",
                ),
            )
            con.row_factory = sqlite3.Row
            record = con.execute(
                "SELECT * FROM phase1_action_v1 WHERE action_id=?", (action_id,)
            ).fetchone()
        s["action_ids"].append(action_id)
        s["steps_used"] += 1
        s["pending"] = {
            "kind": "ACTION",
            "action_id": action_id,
            "operation_key": key,
            "reserved_sha256": data_digest(dict(record)),
        }
        reserved = self._commit(s, case["head"], "READ_RESERVED", {"action_id": action_id})
        # An interrupted RESERVED action is never automatically resent.
        started = perf_counter()
        result = None
        handler_returned = False
        try:
            fresh = self.get(case_id, principal)
            if fresh["state"]["status"] == "CANCELED":
                return fresh
            result = op.handler(
                {
                    "action_id": action_id,
                    "case_id": case_id,
                    "operation": op.catalog(),
                    "investigation": investigation,
                    "principal": principal,
                }
            )
            handler_returned = True
            eids = self._receive_result(s, op, result, principal, action_id)
            outcome = {
                "state": result.get("state", "COLLECTED"),
                "evidence_ids": eids,
                "elapsed_seconds": round(perf_counter() - started, 3),
            }
        except Exception as exc:
            failure = self._publish(
                s["scope"],
                op.target_ref,
                "incident_read_failure_v1",
                op.source_ref,
                {
                    "target_ref": op.target_ref,
                    "acquisition_state": (
                        "ACCESS_DENIED" if isinstance(exc, PermissionError) else "FAILED"
                    ),
                    "source_observed_at": utc_now(),
                    "coverage": "No normality established",
                    "basis_type": op.basis_type,
                    "values": {
                        "error_type": type(exc).__name__,
                        "error_code": (
                            str(exc)
                            if str(exc).startswith(("READ_", "INCIDENT_"))
                            else type(exc).__name__
                        ),
                    },
                    "rejected_result": self._rejected_read_result(result),
                    "rejected_adapter_result": handler_returned,
                    "conditions": op.conditions,
                    "action_id": action_id,
                },
            )
            eids = [failure]
            outcome = {
                "state": "ACCESS_DENIED" if isinstance(exc, PermissionError) else "FAILED",
                "evidence_ids": eids,
                "elapsed_seconds": round(perf_counter() - started, 3),
                "error_type": type(exc).__name__,
                "rejected_adapter_result": handler_returned,
            }
        return self._finish_read(
            case_id,
            principal,
            action_id,
            eids,
            outcome,
            selections=[
                i["selection"] for i in s["selections"] if i["selection"]["evidence_id"] in eids
            ],
        )

    @staticmethod
    def _rejected_read_result(result):
        if result is None:
            return None
        import base64, hashlib

        try:
            raw = canonical_json(result).encode("utf-8")
        except (ValueError, TypeError):
            return {"serialization": "UNSUPPORTED_RETURN_TYPE", "type": type(result).__name__}
        return {
            "serialization": "CANONICAL_JSON_UTF8",
            "base64": base64.b64encode(raw).decode("ascii"),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "original_bytes": len(raw),
            "complete_within_limit": True,
            "accepted_as_observation": False,
        }

    def _receive_result(self, state, op, result, principal, action_id):
        if type(result) is not dict:
            raise ValueError("READ_RESULT_INVALID")
        if "selections" in result:
            eids = []
            for selection in result["selections"]:
                self._add_selection(state, selection, principal)
                eids.append(selection["evidence_id"])
            if not eids:
                raise ValueError("READ_NO_EVIDENCE_COLLECTED")
            return list(dict.fromkeys(eids))
        if (
            result.get("state") not in {"OBSERVED", "NOT_OBSERVED", "FAILED", "ACCESS_DENIED"}
            or result.get("target_ref") != op.target_ref
            or type(result.get("values")) is not dict
            or not result.get("coverage")
        ):
            raise ValueError("READ_RESULT_BINDING_INVALID")
        if timestamp(result["observed_at"]) > datetime.now(timezone.utc):
            raise ValueError("READ_FUTURE_OBSERVATION")
        payload = {
            "target_ref": op.target_ref,
            "source_observed_at": result["observed_at"],
            "acquisition_state": result["state"],
            "coverage": result["coverage"],
            "conditions": op.conditions,
            "requested_window": op.window,
            "basis_type": op.basis_type,
            "values": result["values"],
            "action_id": action_id,
            "operation": op.catalog(),
            "source_origin": op.origin,
        }
        if len(canonical_json(payload).encode()) > self.read_result_max_bytes:
            raise ValueError("READ_RESULT_OVER_LIMIT")
        eid = self._publish(
            state["scope"],
            op.target_ref,
            "incident_read_observation_v1",
            op.source_ref,
            payload,
            origin=op.origin,
        )
        self._add_selection(
            state,
            {
                "evidence_id": eid,
                "paths": op.paths,
                "subject_ref": op.target_ref,
                "conditions": op.conditions,
            },
            principal,
        )
        return [eid]

    def _finish_read(
        self, case_id, principal, action_id, eids, outcome, *, selections=(), contention_attempt=0
    ):
        case = self.get(case_id, principal)
        s = case["state"]
        if not s["pending"] or s["pending"].get("action_id") != action_id:
            raise ValueError("READ_CLAIM_NOT_PENDING")
        for selection in selections:
            self._add_selection(s, selection, principal)
        for eid in eids:
            if not any(i["selection"]["evidence_id"] == eid for i in s["selections"]):
                # Selections published before interruption can also be reconciled.
                _, raw = self._raw(eid, principal)
                paths = raw.get("operation", {}).get("paths", ["/values"])
                self._add_selection(s, {"evidence_id": eid, "paths": paths}, principal)
        with closing(connect(self.db)) as con:
            con.row_factory = sqlite3.Row
            record = dict(
                con.execute(
                    "SELECT * FROM phase1_action_v1 WHERE action_id=?", (action_id,)
                ).fetchone()
            )
        expected_sha = s["pending"]["reserved_sha256"]
        before = json.loads(record["before_json"])
        record.update(
            ended_at=utc_now(),
            result_status=outcome["state"],
            after_json=canonical_json(eids),
            result_json=canonical_json(outcome),
        )
        s["bindings"].append(
            {"table": "phase1_action_v1", "key": action_id, "sha256": data_digest(record)}
        )
        s["last_result"] = eids
        s["pending"] = None
        if outcome.get("rejected_adapter_result") and s["status"] != "CANCELED":
            s.update(status="HOLD", reason="READ_RESULT_REJECTED_REVIEW_REQUIRED")
        s["requested_fact_refs"] = before["investigation"].get("fact_refs", [])
        try:
            return self._commit(
                s,
                case["head"],
                "READ_RESULT_RECORDED",
                outcome,
                action_update=(action_id, expected_sha, record),
            )
        except RuntimeError as exc:
            if str(exc) != "INCIDENT_CONCURRENT_UPDATE_RELOAD" or contention_attempt >= 2:
                raise
            # Only reconcile the already collected receipt. Never call the reader again.
            return self._finish_read(
                case_id,
                principal,
                action_id,
                eids,
                outcome,
                selections=selections,
                contention_attempt=contention_attempt + 1,
            )

    def reconcile_capacity_rejection(self, case_id, principal, *, evidence_id, reason):
        """Accept complete saved bytes after an explicit capacity fix, without GET.

        Only the prior capacity rejection is eligible. The normal parser, subject,
        time, permissions and new capacity checks still apply. Old failure/action
        records stay immutable and visible; no JSON repair is performed.
        """
        import base64, hashlib

        case = self.get(case_id, principal)
        state = case["state"]
        if (
            state["pending"]
            or state["status"] != "HOLD"
            or evidence_id not in state["last_result"]
            or not reason.strip()
        ):
            raise PermissionError("EXPLICIT_CURRENT_CAPACITY_RECONCILIATION_REQUIRED")
        row, failure = self._raw(evidence_id, principal)
        saved = failure.get("rejected_result") or {}
        if (
            row["adapter"] != "incident_read_failure_v1"
            or failure.get("values", {}).get("error_code") != "READ_RESULT_OVER_LIMIT"
            or failure.get("rejected_adapter_result") is not True
            or saved.get("serialization") != "CANONICAL_JSON_UTF8"
            or saved.get("complete_within_limit") is not True
        ):
            raise PermissionError("ONLY_COMPLETE_CAPACITY_REJECTION_CAN_BE_RECONCILED")
        raw = base64.b64decode(saved["base64"], validate=True)
        if (
            len(raw) != saved["original_bytes"]
            or hashlib.sha256(raw).hexdigest() != saved["sha256"]
        ):
            raise ValueError("SAVED_REJECTED_READ_BYTES_CHANGED")
        action_id = failure["action_id"]
        if action_id not in state["action_ids"]:
            raise PermissionError("REJECTED_READ_NOT_IN_CURRENT_CASE")
        with closing(connect(self.db)) as con:
            before = json.loads(
                con.execute(
                    "SELECT before_json FROM phase1_action_v1 WHERE action_id=?", (action_id,)
                ).fetchone()[0]
            )
        op = self.registry.get(before["investigation"]["operation_id"], principal)
        if op.conditions != failure["conditions"] or op.target_ref != failure["target_ref"]:
            raise PermissionError("REJECTED_READ_OPERATION_BINDING_CHANGED")
        restored = json.loads(raw)
        eids = self._receive_result(state, op, restored, principal, action_id)
        state["last_result"] = eids
        state.update(
            status="ACTIVE", reason="SAVED_READ_ACCEPTED_AFTER_CAPACITY_FIX_NEEDS_MODEL_EVALUATION"
        )
        return self._commit(
            state,
            case["head"],
            "SAVED_READ_CAPACITY_RECONCILED",
            {
                "reason": reason,
                "original_rejection": evidence_id,
                "accepted_evidence_ids": eids,
                "new_product_reads": 0,
                "capacity_bytes": self.read_result_max_bytes,
            },
        )

    def reconcile_read(self, case_id, principal, *, action_id, evidence_ids):
        case = self.get(case_id, principal)
        s = case["state"]
        if (
            not evidence_ids
            or not s["pending"]
            or s["pending"].get("kind") != "ACTION"
            or s["pending"].get("action_id") != action_id
        ):
            raise ValueError("READ_RECONCILIATION_INVALID")
        failures = []
        for eid in evidence_ids:
            row, raw = self._raw(eid, principal)
            with closing(connect(self.db)) as con:
                before = json.loads(
                    con.execute(
                        "SELECT before_json FROM phase1_action_v1 WHERE action_id=?", (action_id,)
                    ).fetchone()[0]
                )
            if (
                raw.get("action_id") != action_id
                or raw.get("target_ref") != before["operation"]["target_ref"]
                or row["source"] != before["operation"]["source_ref"]
                or (raw.get("operation") is not None and raw["operation"] != before["operation"])
            ):
                raise ValueError("READ_RECONCILIATION_RECEIPT_MISMATCH")
            if row["adapter"] == "incident_read_failure_v1":
                failures.append(raw)
        outcome = {
            "state": failures[-1]["acquisition_state"] if failures else "RECONCILED",
            "evidence_ids": evidence_ids,
            "rejected_adapter_result": any(
                f.get(
                    "rejected_adapter_result",
                    f.get("rejected_result") is not None
                    or f.get("values", {}).get("error_code") == "READ_RESULT_INVALID",
                )
                for f in failures
            ),
            "elapsed_seconds": None,
        }
        return self._finish_read(case_id, principal, action_id, evidence_ids, outcome)

    def reconcile_saved_read(self, case_id, principal):
        case = self.get(case_id, principal)
        pending = case["state"]["pending"]
        if not pending or pending["kind"] != "ACTION":
            raise ValueError("READ_RECONCILIATION_INVALID")
        with closing(connect(self.db)) as con:
            rows = con.execute(
                "SELECT evidence_id FROM evidence WHERE scope=? AND adapter IN ('incident_read_observation_v1','incident_read_failure_v1') AND json_extract(payload_json,'$.action_id')=?",
                (principal.scope, pending["action_id"]),
            ).fetchall()
        if not rows:
            return case  # Result unknown: retain reservation, never resend.
        return self.reconcile_read(
            case_id, principal, action_id=pending["action_id"], evidence_ids=[r[0] for r in rows]
        )

    def cancel(self, case_id, principal, reason):
        case = self.get(case_id, principal)
        s = case["state"]
        if not reason.strip():
            raise ValueError("CANCEL_REASON_REQUIRED")
        s.update(status="CANCELED", reason=reason)
        return self._commit(s, case["head"], "CANCELED")

    def reconcile_model(self, case_id, principal, *, reason):
        case = self.get(case_id, principal)
        s = case["state"]
        if not reason.strip() or not s["pending"] or s["pending"]["kind"] != "MODEL":
            raise ValueError("MODEL_RECONCILIATION_INVALID")
        token = s["pending"]["token"]
        input_id = s["model_records"][-1]
        with closing(connect(self.db)) as con:
            found = con.execute(
                "SELECT evidence_id FROM evidence WHERE adapter='incident_model_result_v1' AND scope=? AND source=? AND json_extract(payload_json,'$.token')=? AND json_extract(payload_json,'$.input_evidence_id')=?",
                (s["scope"], case_id, token, input_id),
            ).fetchall()
        if len(found) > 1:
            raise ValueError("INCIDENT_MODEL_RECONCILIATION_AMBIGUOUS")
        if found:
            eid = found[0][0]
            _, raw = self._raw(eid, principal)
        else:
            _, input_record = self._raw(input_id, principal)
            profile = input_record.get("execution_identity")
            trace = {
                "profile": profile,
                "model": profile.get("model") if profile else None,
                "exchange": {},
            }
            from ILA_ECA_REAL_DISCOVERY_LAB.llm.runtime import metrics

            raw = {
                "status": "INTERRUPTED",
                "token": token,
                "input_evidence_id": input_id,
                "origin": input_record["origin"],
                "actual_llm_calls": None,
                "call_count_state": "UNKNOWN_AFTER_PROCESS_INTERRUPTION",
                "elapsed_seconds": None,
                "error_type": "InterruptedProcess",
                "error_code": "INCIDENT_MODEL_RESULT_NOT_RECEIVED",
                "trace": trace,
                "metrics": metrics(trace, failure_stage="INTERRUPTED_RESULT_UNKNOWN"),
            }
            eid = self._publish(
                s["scope"], s["request"]["subject_id"], "incident_model_result_v1", case_id, raw
            )
        if eid not in s["model_records"]:
            s["model_records"].append(eid)
        s["pending"] = None
        if s["status"] != "CANCELED":
            s.update(
                status="HOLD",
                reason=(
                    "MODEL_INTERRUPTED_RESULT_UNKNOWN"
                    if raw["status"] == "INTERRUPTED"
                    else "MODEL_RESULT_RECONCILED_REVIEW_REQUIRED"
                ),
            )
        return self._commit(s, case["head"], "MODEL_INTERRUPTION_RECONCILED", {"reason": reason})

    def resume(
        self,
        case_id,
        principal,
        *,
        reason,
        new_selections=(),
        max_steps=None,
        max_calls=None,
        allow_reasoner_change=False,
    ):
        case = self.get(case_id, principal)
        s = case["state"]
        if s["pending"]:
            raise RuntimeError("INCIDENT_PENDING_OPERATION_RECONCILE_NO_RESEND")
        if not reason.strip():
            raise ValueError("INCIDENT_RESUME_REASON_REQUIRED")
        identity_change = None
        if type(allow_reasoner_change) is not bool:
            raise ValueError("INCIDENT_EXPLICIT_MODEL_SWITCH_FLAG_REQUIRED")
        if allow_reasoner_change:
            if self.reasoner is None or not hasattr(self.reasoner, "execution_identity"):
                raise ValueError("INCIDENT_CONFIGURED_REASONER_IDENTITY_REQUIRED")
            next_identity = self.reasoner.execution_identity()
            identity_change = {
                "previous": copy.deepcopy(s.get("execution_identity")),
                "next": copy.deepcopy(next_identity),
                "operator": principal.ref,
                "reason": reason,
            }
            s["execution_identity"] = copy.deepcopy(next_identity)
        for selection in new_selections:
            self._add_selection(s, selection, principal)
        if max_steps is not None:
            if type(max_steps) is not int or not s["max_steps"] <= max_steps:
                raise ValueError("INCIDENT_BUDGET_INVALID")
            s["max_steps"] = max_steps
        if max_calls is not None:
            if type(max_calls) is not int or not s["max_calls"] <= max_calls:
                raise ValueError("INCIDENT_BUDGET_INVALID")
            s["max_calls"] = max_calls
        s.update(status="ACTIVE", reason=reason)
        return self._commit(s, case["head"], "RESUMED", {"reasoner_change": identity_change})
