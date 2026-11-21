"""Form-to-existing-entry bridge. Evidence is the durable command journal.

Single trusted local operator, no independent case/approval database or model policy.
"""

from pathlib import Path
from contextlib import closing, nullcontext
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from dataclasses import asdict
from hashlib import sha256
import base64
import copy
import json
import re
import sqlite3
import threading
import uuid
from ILA_ECA_REAL_DISCOVERY_LAB.core.storage import connect
from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import UnifiedPhase1, Request, Principal, utc, _SENSITIVE
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.store import Store, safe
from ILA_ECA_REAL_DISCOVERY_LAB.llm.generation import reserve, _save, load_evidence
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest, canonical_json

ROUTES = {
    "A": "設計・追加構築の設計",
    "B": "承認済み変更の作業計画",
    "C": "障害調査",
    "D": "資料への質問",
    "E": "会議の解析",
    "F": "変更要否・状態確認",
    "G": "AWS移行設計",
    "H": "セキュリティ調査",
}
TYPES = dict(
    zip(
        "ABCDEFGH",
        [
            "DESIGN",
            "CHANGE",
            "INCIDENT",
            "QUESTION",
            "MEETING_ASSERTION",
            "NO_ACTION",
            "CLOUD_LIFT",
            "SECURITY_EVENT",
        ],
    )
)
FORM = {
    "title",
    "route",
    "text",
    "environment",
    "constraints",
    "unknowns",
    "parameters",
    "stage",
    "material_keys",
    "expected_revision",
    "change_key",
    "resume_reason",
    "task_kind",
    "meeting_text",
    "meeting_receipt_key",
}
OPS = {
    "save_request",
    "run",
    "resume",
    "reconcile",
    "google_sync",
    "google_collect",
    "drive_import",
    "meeting_analyze",
    "gitlab_prepare",
    "gitlab_submit",
    "gitlab_refresh",
    "gitlab_reconcile",
    "formal_status",
    "formal_prepare",
}


def checked(value):
    safe(value)  # The complete value is serialized/scanned once.

    def check_fields(value):
        if isinstance(value, dict):
            for k, v in value.items():
                if (
                    re.fullmatch(
                        r"(?i)(password|passwd|api[_-]?key|client_secret|access_token|refresh_token|authorization)",
                        k,
                    )
                    and isinstance(v, str)
                    and v
                    and not v.startswith("${")
                ):
                    raise PermissionError("SECRET_VALUE_NOT_ALLOWED")
                check_fields(v)
        elif isinstance(value, list):
            for v in value:
                check_fields(v)
        elif isinstance(value, str) and re.search(r"https?://[^/\s]+@", value):
            raise PermissionError("URL_CREDENTIAL_NOT_ALLOWED")

    check_fields(value)
    return value


def reason(exc):
    text = getattr(exc, "code", None) or str(exc)
    return text if re.fullmatch("[A-Z][A-Z0-9_]*", text) else type(exc).__name__


def summary(result):
    """A projection, not a changed model response. Raw artifacts stay in registry."""
    if not isinstance(result, dict):
        return {}
    keys = {
        "status",
        "state",
        "reason",
        "error_code",
        "error_type",
        "actual_llm_calls",
        "completion",
        "missing",
        "missing_prerequisites",
        "approval_granted",
        "formal_approval_granted",
        "test_approval_granted",
        "gitlab_approval_verified",
        "fresh_remote_verification_required_before_use",
        "execution_allowed",
        "baseline_updated",
        "automatic_retry",
        "automatic_join",
        "automatic_recording",
        "unavailable",
        "receipts",
        "service_execution_kind",
    }
    out = {k: v for k, v in result.items() if k in keys and k != "receipts"}
    for k in ("result", "call", "validation_failure"):
        if isinstance(result.get(k), dict):
            out[k] = summary(result[k])
    return out


def has_failure(value):
    return isinstance(value, dict) and (
        bool(value.get("error_code") or value.get("error_type"))
        or any(has_failure(v) for v in value.values() if isinstance(v, dict))
    )


def job_result_category(record):
    result = record.get("result_summary", {})
    if has_failure(result):
        return "FAILED"
    outcome = record.get("outcome") or result.get("status")
    return "WAITING_INFORMATION" if outcome == "HOLD" else record["state"]


class Portal:
    def __init__(
        self,
        config,
        *,
        google_api=None,
        gitlab_api=None,
        approval_host=None,
        execution_context_factory=None,
    ):
        if config.get("demo") and execution_context_factory is None:
            raise ValueError("TEST_TRANSPORT_REQUIRED")
        if execution_context_factory is not None and not config.get("demo"):
            raise PermissionError("TEST_CONTEXT_REQUIRES_EXPLICIT_DEMO")
        self.execution_context_factory = execution_context_factory
        self.config = copy.deepcopy(config)
        self.db = Path(config["db"]).resolve(strict=True)
        if not self.db.is_file():
            raise ValueError("EXISTING_DATABASE_REQUIRED")
        self.actor = Principal(config.get("actor", "WEB-LOCAL-OPERATOR"))
        self.actor.check()
        self.gateway = UnifiedPhase1(self.db)
        self.store = Store(self.db)
        self.google_api = google_api
        self.gitlab_api = gitlab_api
        self.approval_host = approval_host
        if self.approval_host is None and config.get("approval_policy_path"):
            from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.approval import GitLabApprovalHost

            self.approval_host = GitLabApprovalHost(config["approval_policy_path"])
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ila-web")
        self.lock = threading.RLock()
        self.running = set()
        self.owned = set()
        self.closed = False
        self.upload_root = (self.db.parent / "web_uploads").resolve()
        self.mode = (
            "MOCK"
            if config.get("demo")
            else "LOCAL_MODEL" if config.get("generation_enabled") else "NOT_CONFIGURED"
        )

    def rows(self, table, sql="", args=()):
        with closing(connect(self.db)) as c:
            c.row_factory = sqlite3.Row
            if not c.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone():
                return []
            return [dict(r) for r in c.execute("SELECT * FROM " + table + " " + sql, args)]

    def events(self, cid, adapter):
        return [
            {**r, "payload": load_evidence(self.db, r["evidence_id"], "lab")[1]}
            for r in self.rows(
                "evidence",
                "WHERE adapter=? AND source=? ORDER BY observed_at,evidence_id",
                (adapter, "web-case://" + cid),
            )
        ]

    def authorize(self, cid):
        if not isinstance(cid, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,100}", cid):
            raise PermissionError("CASE_NOT_AUTHORIZED")
        own = next(iter(self.events(cid, "web_case_registration_v1")), None)
        note = self.notification(cid)
        allowed = (
            cid in self.config.get("existing_case_ids", [])
            or own
            and own["payload"]["operator"] == self.actor.ref
            or note
            and note["config_sha"] in self.config.get("allowed_notification_config_sha256", [])
        )
        if not allowed:
            raise PermissionError("CASE_NOT_AUTHORIZED")
        cases = self.rows("phase1_request_v1", "WHERE request_id=?", (cid,)) + self.rows(
            "lifecycle_change_v1", "WHERE change_id=?", (cid,)
        )
        notify = self.notification(cid)
        if not cases and not notify:
            raise ValueError("EXISTING_CASE_REQUIRED")
        if cases and cases[0]["scope"] not in {"lab", "ila-discovery-lab"}:
            raise PermissionError("CASE_SCOPE_DENIED")
        return cid

    def notification(self, cid):
        for row in self.rows("notification_case_v1"):
            m = json.loads(row["manifest"])
            if m["request"]["request_id"] == cid:
                return {**row, "manifest": m}
        return None

    def registration(self, cid):
        self.authorize(cid)
        rows = self.events(cid, "web_case_registration_v1")
        if rows:
            return rows[0]["payload"]["form"]
        note = self.notification(cid)
        if note:
            return {
                "title": "監視通知からの障害案件",
                "route": "C",
                "text": note["manifest"]["incident"]["symptom"],
                "environment": "",
                "constraints": "",
                "unknowns": "",
                "parameters": [],
            }
        rows = self.rows("lifecycle_change_v1", "WHERE change_id=?", (cid,))
        if rows:
            return {
                "title": rows[0]["purpose"],
                "route": "B",
                "text": rows[0]["purpose"],
                "environment": "",
                "constraints": "",
                "unknowns": "",
                "parameters": [],
            }
        rows = self.rows("phase1_request_v1", "WHERE request_id=?", (cid,))
        r = rows[0]
        return {
            "title": r["subject_id"],
            "route": next((k for k, v in TYPES.items() if v == r["request_type"]), "F"),
            "text": "",
            "environment": "",
            "constraints": "",
            "unknowns": "",
            "parameters": [],
        }

    def create_case(self, form, key):
        form = self.validate_form(form)
        cid = "WEBCASE-" + data_digest([self.actor.ref, key])[:24]
        body = {"operator": self.actor.ref, "form": form}
        with self.lock:
            eid, new = reserve(
                self.db, "lab", "web-case://" + cid, "web_case_registration_v1", body
            )
            if form["route"] == "C":
                manifest = self.incident_manifest(cid, form)
                from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import Investigation

                Investigation(self.db).start(
                    Request(**manifest["request"]),
                    self.actor,
                    incident=manifest["incident"],
                    max_steps=manifest["max_steps"],
                    max_calls=manifest["max_calls"],
                )
            else:
                old = self.rows("phase1_request_v1", "WHERE request_id=?", (cid,))
                if not old:
                    req = Request(
                        cid,
                        TYPES[form["route"]],
                        "TARGET-" + data_digest(form["environment"])[:16],
                        "lab",
                        utc(),
                        self.actor.ref,
                        form["title"],
                        "ADVISE",
                        cid,
                        {"web_registration_evidence_id": eid},
                    )
                    self.gateway.register_only(req, self.actor)
            return {"case_id": cid, "created": new}

    def validate_form(self, form):
        if type(form) is not dict or set(form) - FORM:
            raise ValueError("FORM_FIELDS_INVALID")
        form = copy.deepcopy(form)
        for k in (
            "title",
            "route",
            "text",
            "environment",
            "constraints",
            "unknowns",
            "stage",
            "resume_reason",
            "meeting_text",
            "meeting_receipt_key",
        ):
            if k in form and type(form[k]) is not str:
                raise ValueError("FORM_TEXT_INVALID")
        if form.get("route") not in ROUTES or not form.get("title", "").strip():
            raise ValueError("CASE_TITLE_AND_FUNCTION_REQUIRED")
        form.setdefault("parameters", [])
        if type(form["parameters"]) is not list:
            raise ValueError("ENVIRONMENT_FIELDS_INVALID")
        names = set()
        for p in form["parameters"]:
            if (
                type(p) is not dict
                or set(p) != {"name", "value", "type", "unit"}
                or not p["name"]
                or p["name"] in names
            ):
                raise ValueError("ENVIRONMENT_FIELDS_INVALID")
            names.add(p["name"])
            if p["type"] == "number":
                if type(p["value"]) not in (int, float):
                    raise ValueError("ENVIRONMENT_NUMBER_REQUIRED")
            elif p["type"] == "boolean":
                if type(p["value"]) is not bool:
                    raise ValueError("ENVIRONMENT_BOOLEAN_REQUIRED")
            elif p["type"] == "text":
                if type(p["value"]) is not str:
                    raise ValueError("ENVIRONMENT_TEXT_REQUIRED")
            else:
                raise ValueError("ENVIRONMENT_TYPE_INVALID")
        checked(form)
        return form

    def _case_receipt(self, case_id, receipt_id):
        receipt = self.store.receipt(receipt_id)
        if receipt["case_id"] != case_id:
            raise PermissionError("MEETING_RECEIPT_CASE_MISMATCH")
        return receipt

    def validate_case_form(self, case_id, input_data):
        """Shared policy, rechecked at both acceptance and actual execution."""
        form = self.validate_form(input_data)
        if form["route"] != self.registration(case_id)["route"]:
            raise PermissionError("CASE_ROUTE_CHANGED")
        if form.get("meeting_receipt_key"):
            self._case_receipt(case_id, form["meeting_receipt_key"])
        return form

    def generation_available(self):
        return bool(self.config.get("generation_enabled") or self.config.get("demo"))

    def request_form(self, cid):
        """Keep the user's request separate from an old E execution transcript.

        Presentation of old receipts only: never rewrite original inputs, model
        exchanges, document hashes, or the saved registration.
        """
        registered = self.registration(cid)
        latest = self.events(cid, "web_form_snapshot_v1")
        form = copy.deepcopy(latest[-1]["payload"]["form"] if latest else registered)
        note = None
        if (
            latest
            and form["route"] == "E"
            and "meeting_text" not in form
            and "meeting_receipt_key" not in form
            and latest[-1]["payload"].get("entry_kind") != "USER_REQUEST_ONLY"
        ):
            # The pre-separation E execution contract passed form.text as the
            # meeting body. Determine its role from that saved contract, never
            # from VTT markers, words in the transcript, or a particular case.
            text = form.get("text", "")
            form["meeting_text"] = text
            form["text"] = registered.get("text", "") if registered.get("text", "") != text else ""
            note = "過去の実行では依頼欄に会議本文が保存されていたため、原依頼と会議本文を分けて表示しています。保存済みの原入力は変更していません。"
        return form, note

    def links(self, cid, kind):
        return [
            json.loads(r["payload_json"])
            for r in self.rows("collaboration_link_v1", "WHERE case_id=? AND kind=?", (cid, kind))
        ]

    def material(self, cid, key):
        self.authorize(cid)
        return self.store.get_link(cid, "WEB_UPLOAD", key)

    def save_upload(self, cid, name, raw, kind, meeting_key=None):
        self.authorize(cid)
        self.ensure_notification_request(cid)
        if meeting_key:
            self.store.get_link(cid, "GOOGLE_MEETING", meeting_key)
        if (
            type(name) is not str
            or Path(name).name != name
            or any(x in name for x in ("/", "\\", ":", "\0"))
        ):
            raise ValueError("UPLOAD_FILENAME_INVALID")
        suffix = Path(name).suffix.lower()
        if suffix not in {
            ".txt",
            ".md",
            ".html",
            ".json",
            ".vtt",
            ".wav",
            ".mp3",
            ".mp4",
            ".m4a",
            ".ogg",
            ".flac",
        }:
            raise ValueError("UPLOAD_FORMAT_UNSUPPORTED")
        if not raw or len(raw) > self.config.get("max_upload_bytes", 64 * 1024 * 1024):
            raise ValueError("UPLOAD_SIZE_INVALID")
        if kind not in {"ENVIRONMENT", "REQUIREMENT", "POLICY", "TECHNICAL_REFERENCE", "MEETING"}:
            raise ValueError("UPLOAD_SOURCE_KIND_INVALID")
        if kind == "MEETING" and suffix in {".md", ".html", ".json"}:
            raise ValueError("MEETING_TEXT_REQUIRES_TXT_OR_VTT")
        if suffix in {".txt", ".md", ".html", ".json", ".vtt"}:
            text = raw.decode("utf-8-sig")
            checked(json.loads(text) if suffix == ".json" else text)
        digest = sha256(raw).hexdigest()
        try:
            old = self.material(cid, digest)
            if old["kind"] != kind or old.get("meeting_key") != meeting_key:
                raise PermissionError("EXISTING_MATERIAL_SOURCE_ROLE_OR_MEETING_DIFFERS")
            return old
        except ValueError:
            pass
        folder = self.upload_root / cid
        folder.mkdir(parents=True, exist_ok=True)
        if (
            self.upload_root.is_symlink()
            or folder.is_symlink()
            or folder.resolve().parent != self.upload_root
        ):
            raise PermissionError("UPLOAD_PATH_DENIED")
        path = folder / (digest + suffix)
        if path.is_symlink():
            raise PermissionError("UPLOAD_PATH_DENIED")
        if path.exists() and path.read_bytes() != raw:
            raise ValueError("UPLOAD_ORIGINAL_CHANGED")
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(raw)
        value = {
            "key": digest,
            "name": name,
            "sha256": digest,
            "bytes": len(raw),
            "kind": kind,
            "suffix": suffix,
            "relative_path": str(path.relative_to(self.db.parent)),
            "intake_state": "SAVED_NOT_PROCESSED",
            "meeting_key": meeting_key,
        }
        self.store.link(cid, "WEB_UPLOAD", digest, value)
        self.enqueue(cid, "ingest", {"material_key": digest}, key=digest)
        return value

    def upload_path(self, value):
        p = (self.db.parent / value["relative_path"]).resolve(strict=True)
        if (
            not p.is_relative_to(self.upload_root)
            or p.is_symlink()
            or sha256(p.read_bytes()).hexdigest() != value["sha256"]
        ):
            raise PermissionError("UPLOAD_BINDING_CHANGED")
        return p

    def ingest(self, cid, key):
        value = self.material(cid, key)
        path = self.upload_path(value)
        if value["suffix"] in {".txt", ".md", ".html", ".json"}:
            from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.intake import ingest_file
            from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.index import OfflineHashEmbedding

            result = ingest_file(
                self.db,
                path,
                scope="lab",
                source_ref="web-received://" + cid + "/" + key,
                title=value["name"],
                format={".md": "markdown", ".html": "html"}.get(value["suffix"], "text"),
                source_kind=value["kind"],
                version=value["sha256"],
                document_state="RECEIVED_UNVERIFIED",
                embeddings=OfflineHashEmbedding(),
                embedding_model="local-hash-256",
                model_fingerprint="local-hash-256-v1",
                max_source_bytes=self.config.get("max_upload_bytes", 64 * 1024 * 1024),
            )
            value.update(source_id=result["source_id"], evidence_id=result["evidence_id"])
        if value["kind"] == "MEETING" or value["suffix"] in {
            ".vtt",
            ".wav",
            ".mp3",
            ".mp4",
            ".m4a",
            ".ogg",
            ".flac",
        }:
            from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.entry import execute

            cfg = self.local_connection(cid)
            result = execute(
                self.db,
                cfg,
                {
                    "schema": "ila.eca.collaboration-request.v1",
                    "case_id": cid,
                    "operation": "file_import",
                    "payload": {
                        "path": str(path),
                        **(
                            {"meeting_key": value["meeting_key"]}
                            if value.get("meeting_key")
                            else {}
                        ),
                    },
                },
            )
            value["receipt_id"] = result["receipt_id"]
        value["intake_state"] = "READY"
        self.store.link(cid, "WEB_UPLOAD", key, value)
        return {"status": "IMPORTED", "material_key": key}

    def local_connection(self, cid):
        return {
            "schema": "ila.eca.collaboration-connection.v1",
            "actor": self.actor.ref,
            "scope": "lab",
            "approved_by": self.config.get("local_intake_authorized_by", self.actor.ref),
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "allowed_case_ids": [cid],
            "allowed_operations": ["status", "meeting_import", "meeting_analyze"],
            "classification": "SYNTHETIC_ONLINE" if self.config.get("demo") else "LOCAL_ONLY",
            "external_send_permitted": False,
            "allowed_export_sha256": [],
        }

    def enqueue(self, cid, op, payload, *, key=None):
        self.authorize(cid)
        if op not in OPS | {"ingest"} or type(payload) is not dict:
            raise ValueError("OPERATION_NOT_AVAILABLE")
        checked(payload)
        if op in {"save_request", "run", "resume"}:
            payload = self.validate_case_form(cid, payload)
        elif payload.get("meeting_receipt_key"):
            self._case_receipt(cid, payload["meeting_receipt_key"])
        material_binding = [
            (v["key"], v.get("source_id"), v.get("receipt_id"), v["intake_state"])
            for v in self.links(cid, "WEB_UPLOAD")
            if v.get("origin") != "FORM_INPUT"
        ]
        command = {
            "case_id": cid,
            "operation": op,
            "payload": payload,
            "material_binding": sorted(material_binding),
            "mode": self.mode,
        }
        if op not in {"save_request", "run", "resume", "reconcile", "ingest"} and self.config.get(
            "collaboration_config"
        ):
            # A host-approved permission/configuration change is a new preflight.
            # Existing provider receipts still prevent duplicate writes after it.
            command["connection_binding"] = data_digest(
                json.loads(Path(self.config["collaboration_config"]).read_bytes())
            )
        intent = copy.deepcopy(command)
        # A reload with the same business input reopens the saved execution. A newer
        # server-selected parent must not turn a double click into another model call.
        intent["payload"].pop("expected_revision", None)
        jid = data_digest([intent, key or "EXACT_INPUT"])
        with self.lock:
            old = self.rows(
                "evidence",
                "WHERE source=? AND adapter=?",
                ("web-command://" + jid, "web_ui_command_v1"),
            )
            if old:
                return {"job_id": jid, "duplicate": True}
            eid, new = reserve(self.db, "lab", "web-command://" + jid, "web_ui_command_v1", command)
            if new:
                self.owned.add(jid)
                self.event(jid, cid, "QUEUED", request_evidence_id=eid)
                self.pool.submit(self.worker, jid, command)
        return {"job_id": jid, "duplicate": not new}

    def event(self, jid, cid, state, **more):
        return _save(
            self.db,
            "lab",
            "web-job://" + jid,
            "web_ui_job_event_v1",
            {"job_id": jid, "case_id": cid, "state": state, **more},
        )

    def job(self, jid):
        rows = self.rows(
            "evidence",
            "WHERE source=? AND adapter=? ORDER BY observed_at,evidence_id",
            ("web-job://" + jid, "web_ui_job_event_v1"),
        )
        if not rows:
            command = self.rows(
                "evidence",
                "WHERE source=? AND adapter=?",
                ("web-command://" + jid, "web_ui_command_v1"),
            )
            if len(command) != 1:
                raise ValueError("JOB_NOT_FOUND")
            _, bound = load_evidence(self.db, command[0]["evidence_id"], "lab")
            self.authorize(bound["case_id"])
            return {
                "job_id": jid,
                "case_id": bound["case_id"],
                "state": "RESULT_UNKNOWN",
                "result_category": "RESULT_UNKNOWN",
                "reason": "ACCEPTED_COMMAND_HAS_NO_EXECUTION_EVENT_NO_RESEND",
                "events": [],
                "display_mode": self.mode,
            }
        events = [load_evidence(self.db, r["evidence_id"], "lab")[1] for r in rows]
        result = events[-1]
        self.authorize(result["case_id"])
        if result["state"] in {"QUEUED", "RUNNING", "STOP_REQUESTED"} and jid not in self.owned:
            # A pending job in a new server process is never automatically requeued.
            result = {
                **result,
                "state": "RESULT_UNKNOWN",
                "reason": "PROCESS_INTERRUPTED_EXPLICIT_RECONCILIATION_REQUIRED",
            }
        command = self.rows(
            "evidence",
            "WHERE source=? AND adapter=?",
            ("web-command://" + jid, "web_ui_command_v1"),
        )
        op = json.loads(command[0]["payload_json"])["operation"] if command else "unknown"
        return {
            **result,
            "result_category": job_result_category(result),
            "operation_label": {
                "run": "業務処理",
                "resume": "保存状態からの再開",
                "ingest": "資料の取込み",
                "reconcile": "結果の照合",
                "gitlab_submit": "GitLab提出",
                "gitlab_prepare": "送信対象の準備",
                "gitlab_refresh": "レビュー状態の取得",
                "formal_status": "正式承認の照合",
            }.get(op, op),
            "events": [{"state": e["state"], "reason": e.get("reason")} for e in events],
            "display_mode": self.mode,
        }

    def stop(self, cid, jid):
        self.authorize(cid)
        job = self.job(jid)
        if job["case_id"] != cid:
            raise PermissionError("JOB_CASE_MISMATCH")
        if job["state"] in {"QUEUED", "RUNNING", "RESULT_UNKNOWN"}:
            self.event(jid, cid, "STOP_REQUESTED", reason="USER_REQUESTED_STOP")
        return self.job(jid)

    def stop_requested(self, jid):
        rows = self.rows(
            "evidence",
            "WHERE source=? AND adapter=? ORDER BY observed_at DESC,evidence_id DESC LIMIT 1",
            ("web-job://" + jid, "web_ui_job_event_v1"),
        )
        return bool(rows and json.loads(rows[0]["payload_json"])["state"] == "STOP_REQUESTED")

    def worker(self, jid, command):
        cid = command["case_id"]
        with self.lock:
            self.running.add(jid)
        try:
            from ..core.workflows import Cursor, Execution, StateGraph, START, END, invoke

            flow = Execution()
            graph = StateGraph(Cursor)
            result = eid = None

            def run():
                nonlocal result
                context = (
                    self.execution_context_factory(command)
                    if self.execution_context_factory
                    else nullcontext()
                )
                with context:
                    result = self.perform(cid, command["operation"], command["payload"], jid)

            def retain_result():
                nonlocal eid
                checked(summary(result))
                eid = _save(
                    self.db,
                    "lab",
                    "web-result://" + jid,
                    "web_ui_result_v1",
                    {"case_id": cid, "mode": self.mode, "result": result},
                )

            def attach():
                self.attach_documents(cid, result)

            def finish():
                self.event(
                    jid,
                    cid,
                    "CANCELED" if self.stop_requested(jid) else "FINISHED",
                    result_evidence_id=eid,
                    outcome=(
                        "STOPPED_AFTER_CURRENT_CALL_RESULT_RETAINED"
                        if self.stop_requested(jid)
                        else (
                            result.get("status", result.get("state", "RECORDED"))
                            if isinstance(result, dict)
                            else "RECORDED"
                        )
                    ),
                    result_summary=summary(result),
                    mode=self.mode,
                )

            def begin():
                if self.stop_requested(jid):
                    self.event(jid, cid, "CANCELED", reason="USER_STOP_BEFORE_EXECUTION")
                    flow.values["canceled"] = True
                else:
                    self.event(jid, cid, "RUNNING")

            for name, function in {
                "begin": begin,
                "run": run,
                "retain_result": retain_result,
                "attach": attach,
                "finish": finish,
            }.items():
                flow.node(graph, name, function)
            graph.add_edge(START, "begin")
            graph.add_conditional_edges(
                "begin", lambda _: flow.choose(END if flow.values.get("canceled") else "run")
            )
            for first, second in [
                ("run", "retain_result"),
                ("retain_result", "attach"),
                ("attach", "finish"),
                ("finish", END),
            ]:
                graph.add_edge(first, second)
            invoke(graph, self.db, "portal-job", [cid, jid], flow)
        except Exception as exc:
            self.event(jid, cid, "FAILED", reason=reason(exc), automatic_retry=False)
        finally:
            with self.lock:
                self.running.discard(jid)

    def attach_documents(self, cid, result):
        if not isinstance(result, dict):
            return
        record = result.get("record")
        if (
            isinstance(record, dict)
            and {"design_id", "revision", "domain_id", "artifact_sha256"} <= record.keys()
        ):
            self.store.link(
                cid,
                "WEB_DOCUMENT",
                record["design_id"] + ":" + str(record["revision"]),
                {
                    **{
                        k: record[k]
                        for k in (
                            "design_id",
                            "revision",
                            "domain_id",
                            "artifact_sha256",
                            "document_kind",
                        )
                    },
                    "creation_setting": self.mode,
                },
            )
        for k in ("document", "report", "result"):
            if isinstance(result.get(k), dict):
                self.attach_documents(cid, result[k])

    def documents(self, cid):
        docs = self.links(cid, "WEB_DOCUMENT")
        for row in self.rows("lifecycle_design_artifact_v2", "WHERE change_id=?", (cid,)):
            if not row.get("record_json"):
                continue
            r = json.loads(row["record_json"])
            docs.append(
                {
                    **{
                        k: r[k]
                        for k in (
                            "design_id",
                            "revision",
                            "domain_id",
                            "artifact_sha256",
                            "document_kind",
                        )
                    },
                    "native_lifecycle": True,
                }
            )

        def saved_document(value):
            if not isinstance(value, dict):
                return
            r = value.get("record")
            if (
                isinstance(r, dict)
                and {"design_id", "revision", "domain_id", "artifact_sha256", "document_kind"}
                <= r.keys()
            ):
                docs.append(
                    {
                        k: r[k]
                        for k in (
                            "design_id",
                            "revision",
                            "domain_id",
                            "artifact_sha256",
                            "document_kind",
                        )
                    }
                )
            for k in ("document", "report", "result"):
                if isinstance(value.get(k), dict):
                    saved_document(value[k])

        for row in self.rows("collaboration_material_v1", "WHERE case_id=?", (cid,)):
            saved_document(self.store.receipt(row["receipt_id"]).get("result"))
        # Existing collaboration submissions bind documents to the existing case.
        for row in self.rows("collaboration_submission_v1", "WHERE case_id=?", (cid,)):
            m = json.loads(row["payload_json"])["prepared"]["envelope"]["manifest"]
            docs.append(
                {
                    "design_id": m["design_id"],
                    "revision": m["revision"],
                    "domain_id": m["scope"],
                    "artifact_sha256": m["artifact_sha256"],
                    "document_kind": "SAVED_REVIEW_SUBMISSION",
                }
            )
        unique = {}
        for d in docs:
            unique.setdefault(data_digest([d["domain_id"], d["design_id"], d["revision"]]), d)
        output = []
        for key, d in unique.items():
            with closing(connect(self.db)) as con:
                row = con.execute(
                    "SELECT rowid,relative_path,record_json FROM design_document_artifact_v1 WHERE domain_id=? AND design_id=? AND revision=?",
                    (d["domain_id"], d["design_id"], d["revision"]),
                ).fetchone()
            item = {"key": key, **d, "registered_sequence": row[0] if row else 0}
            if (
                row
                and not d.get("native_lifecycle")
                and json.loads(row[2])["document_kind"] == "FULL_ROUTE_DRAFT"
            ):
                from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import document_paths
                from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import validate_record

                md, structured = document_paths(self.db, row[1])
                data = json.loads(structured.read_bytes())
                validate_record(json.loads(row[2]), content=md.read_bytes(), structured_data=data)
                item["result_status"] = data.get("route_result", {}).get("status")
            output.append(item)
        return sorted(output, key=lambda d: (d["registered_sequence"], d["revision"], d["key"]))

    def document(self, cid, key):
        self.authorize(cid)
        d = next((d for d in self.documents(cid) if d["key"] == key), None)
        if not d:
            raise PermissionError("DOCUMENT_NOT_IN_CASE")
        if d.get("native_lifecycle"):
            from ILA_ECA_REAL_DISCOVERY_LAB.design.change import verify_artifact_content

            rows = self.rows(
                "lifecycle_design_artifact_v2",
                "WHERE change_id=? AND revision=?",
                (cid, d["revision"]),
            )
            if len(rows) != 1 or not verify_artifact_content(self.db, rows[0]):
                raise ValueError("EXISTING_NATIVE_DOCUMENT_HASH_OR_PATH_CHANGED")
            row = rows[0]
            r = json.loads(row["record_json"])
            registered = self.rows(
                "design_document_artifact_v1",
                "WHERE domain_id=? AND design_id=? AND revision=?",
                (d["domain_id"], d["design_id"], d["revision"]),
            )
            if (
                len(registered) != 1
                or registered[0]["record_json"] != row["record_json"]
                or r["artifact_sha256"] != d["artifact_sha256"]
            ):
                raise ValueError("EXISTING_NATIVE_DOCUMENT_REGISTRY_CHANGED")
            folder = self.db.parent / "design_drafts_lab"
            structured = folder / row["structured_path"]
            return {
                "record": r,
                "data": json.loads(structured.read_bytes()),
                "path": str(folder / row["relative_path"]),
                "structured_path": str(structured),
                "native_lifecycle": True,
            }
        from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import (
            verify_attached_document_from_connection,
        )

        with closing(connect(self.db)) as c:
            c.row_factory = sqlite3.Row
            v = verify_attached_document_from_connection(
                c, self.db, d["design_id"], d["revision"], d["domain_id"]
            )
        if v["record"]["artifact_sha256"] != d["artifact_sha256"]:
            raise ValueError("DOCUMENT_VERSION_OR_HASH_CHANGED")
        return v

    def download(self, cid, kind, key, format):
        self.authorize(cid)
        if kind == "material":
            m = self.material(cid, key)
            return self.upload_path(m).read_bytes(), m["name"]
        if kind == "meeting":
            r = self.store.receipt(key)
            if r["case_id"] != cid:
                raise PermissionError("MEETING_RECEIPT_CASE_MISMATCH")
            p = Path(r["path"])
            raw = p.read_bytes()
            if p.is_symlink() or sha256(raw).hexdigest() != r["sha256"]:
                raise ValueError("MEETING_MATERIAL_CHANGED")
            return raw, "meeting-" + r["sha256"][:12] + p.suffix
        if kind != "document" or format not in {"md", "json", "iac"}:
            raise ValueError("DOWNLOAD_TYPE_INVALID")
        d = self.document(cid, key)
        if format == "md":
            p = Path(d["path"])
        elif format == "json":
            p = Path(d.get("structured_path") or Path(d["path"]).parent / "design.json")
        else:
            p = Path(d["path"]).parent / "main.tf.json"
            if not p.is_file() or json.loads(p.read_bytes()) != d["data"].get("proposal", {}).get(
                "terraform"
            ):
                raise ValueError("REGISTERED_IAC_NOT_AVAILABLE")
        raw = p.read_bytes()
        checked(raw.decode("utf-8-sig"))
        return raw, p.name

    def detail(self, cid):
        self.authorize(cid)
        form, request_note = self.request_form(cid)
        jobs = []
        for row in self.rows(
            "evidence", "WHERE adapter=? ORDER BY observed_at", ("web_ui_command_v1",)
        ):
            c = json.loads(row["payload_json"])
            if c["case_id"] == cid:
                jobs.append(self.job(row["source"].removeprefix("web-command://")))
        info = {
            "case_id": cid,
            "form": form,
            "materials": [
                {k: v for k, v in m.items() if k != "relative_path"}
                for m in self.links(cid, "WEB_UPLOAD")
            ],
            "jobs": jobs,
            "documents": self.documents(cid),
            "mode": self.mode,
            "execution_allowed": False,
            "formal_approval_granted": False,
            "request_display_note": request_note,
            "links": [],
            "meetings": [
                {**m, "meeting_key": data_digest([m["calendar_id"], m["meeting_id"]])}
                for m in self.links(cid, "GOOGLE_MEETING")
            ],
            "meeting_materials": [],
            "notifications": bool(self.notification(cid)),
        }
        if self.rows("incident_case_head_v1", "WHERE request_id=?", (cid,)):
            from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import Investigation

            c = Investigation.readonly(self.db).get(cid, self.actor)
            info["incident"] = {
                k: c["state"].get(k)
                for k in (
                    "status",
                    "reason",
                    "hypotheses",
                    "repair_candidates",
                    "steps_used",
                    "calls_used",
                    "max_steps",
                    "max_calls",
                    "pending",
                )
            }
            if info["incident"]["pending"]:
                info["incident"]["pending"] = {"kind": info["incident"]["pending"]["kind"]}
        for row in self.rows("collaboration_submission_v1", "WHERE case_id=?", (cid,)):
            s = json.loads(row["payload_json"])
            m = s["prepared"]["envelope"]["manifest"]
            info["links"].append(
                {
                    "submission_key": row["submission_id"],
                    "state": row["state"],
                    "mr_url": s.get("web_url"),
                    "revision": m["revision"],
                    "design_id": m["design_id"],
                    "artifact_sha256": m["artifact_sha256"],
                    "commit_sha": s.get("commit_sha"),
                    "review": summary(s.get("review") or {}),
                    "formal_approval": "FRESH_VERIFICATION_REQUIRED",
                }
            )
        for row in self.rows("collaboration_material_v1", "WHERE case_id=?", (cid,)):
            r = self.store.receipt(row["receipt_id"])
            item = {
                k: r.get(k)
                for k in (
                    "receipt_id",
                    "kind",
                    "source",
                    "version",
                    "sha256",
                    "intake_origin",
                    "service_execution_kind",
                    "state",
                    "meeting",
                    "segments",
                )
            }
            item["analysis_status"] = (r.get("result") or {}).get("status")
            if r["state"] == "DONE" and item["analysis_status"] not in {
                "GENERATED",
                "COMPLETED",
                "SUCCESS",
            }:
                item["display_state"] = "ANALYSIS_FAILED"
            else:
                item["display_state"] = r["state"]
            if r["kind"] == "TEXT":
                raw = Path(r["path"]).read_bytes()
                if sha256(raw).hexdigest() != r["sha256"]:
                    raise ValueError("MEETING_ORIGINAL_MATERIAL_CHANGED")
                item["text"] = Path(r["path"]).read_text("utf-8-sig")
            info["meeting_materials"].append(item)
        for link in info["links"]:
            matching = [d for d in info["documents"] if d["design_id"] == link["design_id"]]
            link["formal_approval"] = (
                "INVALIDATED_NEWER_REVISION"
                if matching and max(d["revision"] for d in matching) != link["revision"]
                else "FRESH_VERIFICATION_REQUIRED"
            )
            for row in reversed(
                self.rows(
                    "evidence", "WHERE adapter=? ORDER BY observed_at", ("web_ui_command_v1",)
                )
            ):
                command = json.loads(row["payload_json"])
                if (
                    command["case_id"] == cid
                    and command["operation"] == "formal_status"
                    and command["payload"].get("submission_id") == link["submission_key"]
                ):
                    j = self.job(row["source"].removeprefix("web-command://"))
                    link["last_formal_check"] = {
                        "state": j["state"],
                        "result": j.get("result_summary"),
                        "reason": j.get("reason"),
                        "recorded_at": row["observed_at"],
                        "current_use_requires_fresh_check": True,
                    }
                    break
        return info

    def list_cases(self, query=""):
        ids = set(self.config.get("existing_case_ids", []))
        for row in self.rows("notification_case_v1"):
            if row["config_sha"] in self.config.get("allowed_notification_config_sha256", []):
                ids.add(json.loads(row["manifest"])["request"]["request_id"])
        for row in self.rows("evidence", "WHERE adapter=?", ("web_case_registration_v1",)):
            if json.loads(row["payload_json"])["operator"] == self.actor.ref:
                ids.add(row["source"].removeprefix("web-case://"))
        result = []
        for cid in sorted(ids):
            try:
                d = self.detail(cid)
            except (PermissionError, ValueError):
                continue
            if (
                query
                and query.casefold()
                not in (d["form"]["title"] + " " + d["form"].get("text", "")).casefold()
            ):
                continue
            incident = d.get("incident", {})
            state = (
                incident.get("status")
                if incident.get("calls_used") or incident.get("steps_used")
                else None
            ) or (d["jobs"][-1]["state"] if d["jobs"] else "RECEIVED")
            if state == "FINISHED":
                state = d["jobs"][-1]["result_category"]
                if state == "FINISHED" and d["documents"]:
                    state = "AWAITING_REVIEW"
            result.append(
                {
                    "case_id": cid,
                    "title": d["form"]["title"],
                    "route": d["form"]["route"],
                    "status": state,
                    "mode": d["mode"],
                    "documents": len(d["documents"]),
                    "notification": d["notifications"],
                }
            )
        return result

    def ensure_notification_request(self, cid):
        if self.rows("phase1_request_v1", "WHERE request_id=?", (cid,)) or self.rows(
            "lifecycle_change_v1", "WHERE change_id=?", (cid,)
        ):
            return
        note = self.notification(cid)
        if not note:
            raise ValueError("EXISTING_CASE_REQUIRED")
        from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import Investigation

        m = note["manifest"]
        request = Request(**m["request"])
        Investigation(self.db).start(
            request,
            Principal(request.requester_ref),
            incident=m["incident"],
            max_steps=m["max_steps"],
            max_calls=m["max_calls"],
        )

    def incident_manifest(self, cid, form):
        old = self.rows("incident_case_head_v1", "WHERE request_id=?", (cid,))
        if old:
            from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import Investigation

            s = Investigation.readonly(self.db).get(cid, self.actor)["state"]
            req = copy.deepcopy(s["request"])
            incident = copy.deepcopy(s["incident"])
            return {
                "schema": "ila.eca.incident-request.v1",
                "request": req,
                "incident": incident,
                "operations": copy.deepcopy(self.config.get("incident_operations", [])),
                "max_steps": s["max_steps"],
                "max_calls": s["max_calls"],
            }
        now = datetime.now(timezone.utc)
        target = "TARGET-" + data_digest(form.get("environment", ""))[:16]
        return {
            "schema": "ila.eca.incident-request.v1",
            "request": asdict(
                Request(
                    cid,
                    "INCIDENT",
                    target,
                    "lab",
                    now.isoformat(),
                    self.actor.ref,
                    form["title"],
                    "READ",
                    cid,
                )
            ),
            "incident": {
                "symptom": form.get("text") or form["title"],
                "occurred_at": now.isoformat(),
                "window": {
                    "start": (now - timedelta(minutes=10)).isoformat(),
                    "end": now.isoformat(),
                },
                "targets": [target],
                "unknowns": form.get("unknowns", "").splitlines(),
                "baseline_ref": None,
                "evidence_selections": [],
            },
            "operations": copy.deepcopy(self.config.get("incident_operations", [])),
            "max_steps": self.config.get("incident_max_steps", 8),
            "max_calls": self.config.get("incident_max_calls", 12),
        }

    def search(self, cid, query, materials):
        from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.intake import search_received
        from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.index import OfflineHashEmbedding

        ids = [m["source_id"] for m in materials if m.get("source_id")]
        if not ids:
            raise ValueError("RECEIVED_DOCUMENT_REQUIRED")
        chunks = sum(
            len(json.loads(r["chunks_json"]))
            for r in self.rows("received_section_v1")
            if r["source_id"] in ids
        )
        return search_received(
            self.db,
            query,
            scope="lab",
            embeddings=OfflineHashEmbedding(),
            embedding_model="local-hash-256",
            model_fingerprint="local-hash-256-v1",
            source_ids=ids,
            top_k=max(1, chunks),
        )["evidence_id"]

    def perform(self, case_id, operation, input_data, job_id):
        """Translate the form once; LangGraph connects the existing operators."""
        from ..core.workflows import Cursor, Execution, StateGraph, START, END, invoke

        flow = Execution()
        graph = StateGraph(Cursor)
        form = route = materials = latest_design = source_evidence_id = None
        request_spec = route_payload = None

        def authorize():
            self.authorize(case_id)

        def ingest():
            flow.output = self.ingest(case_id, input_data["material_key"])

        def collaborate():
            flow.output = self.collaborate(case_id, operation, input_data, job_id)

        def reconcile():
            flow.output = self.reconcile(case_id, input_data)

        def retain_request():
            nonlocal form, route
            form = self.validate_case_form(case_id, input_data)
            route = form["route"]
            if route == "C" and operation != "save_request":
                self.ensure_notification_request(case_id)
            snapshot = {"form": form, "job_id": job_id}
            if operation == "save_request":
                snapshot["entry_kind"] = "USER_REQUEST_ONLY"
            _save(self.db, "lab", "web-case://" + case_id, "web_form_snapshot_v1", snapshot)
            if operation == "save_request":
                flow.output = {
                    "status": "INPUT_SAVED",
                    "actual_llm_calls": 0,
                    "approval_granted": False,
                }

        def materials_and_revision():
            nonlocal materials, latest_design
            materials = self._ready_materials(case_id, form)
            latest_design = self._check_design_revision(case_id, form, route)

        def model_gate():
            if route not in {"C", "F"} and not self.generation_available():
                flow.output = {
                    "status": "HOLD",
                    "reason": "MODEL_CONNECTION_NOT_CONFIGURED_NO_CALL_SENT",
                    "actual_llm_calls": 0,
                }

        def retain_environment_and_search():
            nonlocal source_evidence_id
            self._retain_form_environment(case_id, form, route, materials)
            source_evidence_id = None
            if route in {"A", "D", "H"}:
                source_evidence_id = self.search(
                    case_id, form.get("text") or form["title"], materials
                )

        def meeting_analysis():
            if form.get("meeting_text", "").strip():
                raise ValueError("SELECT_ONE_MEETING_INPUT")
            flow.output = self.collaborate(
                case_id, "meeting_analyze", {"receipt_id": form["meeting_receipt_key"]}, job_id
            )

        def bind_request():
            nonlocal request_spec, route_payload
            request_spec = self._build_route_request(
                case_id, operation, form, job_id, materials, latest_design, source_evidence_id
            )
            route_payload = request_spec["payload"]
            _save(
                self.db,
                "lab",
                "web-case://" + case_id,
                "web_existing_request_binding_v1",
                {"job_id": job_id, "request": request_spec},
            )

        def offline_incident():
            from ..run_incident_investigation import run_request

            flow.output = run_request(
                self.db,
                Path(route_payload["incident_request"]),
                resume_reason=route_payload.get("resume_reason"),
                cancel_requested=lambda: self.stop_requested(job_id),
            )

        def dispatch():
            from ILA_ECA_REAL_DISCOVERY_LAB.run_structured_design_v2 import dispatch

            flow.output = dispatch(
                self.db, request_spec, cancel_requested=lambda: self.stop_requested(job_id)
            )

        nodes = {
            "authorize": authorize,
            "ingest": ingest,
            "collaborate": collaborate,
            "reconcile": reconcile,
            "retain_request": retain_request,
            "materials_and_revision": materials_and_revision,
            "model_gate": model_gate,
            "retain_environment_and_search": retain_environment_and_search,
            "meeting_analysis": meeting_analysis,
            "bind_request": bind_request,
            "offline_incident": offline_incident,
            "dispatch": dispatch,
        }
        for name, function in nodes.items():
            flow.node(graph, name, function)
        graph.add_edge(START, "authorize")
        graph.add_conditional_edges(
            "authorize",
            lambda _: flow.choose(
                operation
                if operation in {"ingest", "reconcile"}
                else (
                    "retain_request"
                    if operation in {"save_request", "run", "resume"}
                    else "collaborate"
                )
            ),
        )
        graph.add_conditional_edges(
            "retain_request",
            lambda _: flow.choose(END if flow.output is not None else "materials_and_revision"),
        )
        graph.add_edge("materials_and_revision", "model_gate")
        graph.add_conditional_edges(
            "model_gate",
            lambda _: flow.choose(
                END if flow.output is not None else "retain_environment_and_search"
            ),
        )
        graph.add_conditional_edges(
            "retain_environment_and_search",
            lambda _: flow.choose(
                lambda: (
                    "meeting_analysis"
                    if route == "E" and form.get("meeting_receipt_key")
                    else "bind_request"
                )
            ),
        )
        graph.add_conditional_edges(
            "bind_request",
            lambda _: flow.choose(
                lambda: (
                    "offline_incident"
                    if route == "C" and not self.generation_available()
                    else "dispatch"
                )
            ),
        )
        for name in (
            "ingest",
            "reconcile",
            "collaborate",
            "meeting_analysis",
            "offline_incident",
            "dispatch",
        ):
            graph.add_edge(name, END)
        return invoke(graph, self.db, "portal-operation", [case_id, job_id], flow)

    def _ready_materials(self, case_id, form):
        """Use only case-owned material after all pending intakes have finished."""
        materials = self.links(case_id, "WEB_UPLOAD")
        if any((material["intake_state"] != "READY" for material in materials)):
            raise ValueError("MATERIAL_INTAKE_NOT_FINISHED")
        if "material_keys" in form:
            materials = [self.material(case_id, k) for k in form["material_keys"]]
        return materials

    def _check_design_revision(self, case_id, form, route):
        """Reject stale design submissions before model dispatch."""
        matching_designs = [
            document
            for document in self.documents(case_id)
            if document["design_id"] == "DESIGN-" + data_digest(case_id)[:24]
        ]
        latest_design = (
            max(matching_designs, key=lambda document: document["revision"])
            if matching_designs
            else None
        )
        expected_revision = form.get("expected_revision", 0)
        if route in {"A", "G"} and expected_revision != (
            latest_design["revision"] if latest_design else 0
        ):
            raise ValueError("STALE_DOCUMENT_VERSION_RELOAD_REQUIRED")
        return latest_design

    def _retain_form_environment(self, case_id, form, route, materials):
        """Register user values as received evidence, never as implicit settings."""
        if route in {"A", "C", "D", "H"} and (
            form.get("environment")
            or form["parameters"]
            or (
                route in {"C", "D", "H"}
                and (
                    form.get("constraints")
                    or form.get("unknowns")
                    or (route == "C" and form.get("text"))
                )
            )
        ):
            inputs = {"environment": form.get("environment", ""), "parameters": form["parameters"]}
            if route in {"C", "D", "H"}:
                inputs.update(
                    constraints=form.get("constraints", ""), unknowns=form.get("unknowns", "")
                )
            if route == "C":
                inputs["reported_input"] = form.get("text", "")
            source_bytes = canonical_json(inputs).encode()
            content_hash = sha256(source_bytes).hexdigest()
            upload_directory = self.upload_root / case_id
            upload_directory.mkdir(parents=True, exist_ok=True)
            source_path = upload_directory / (content_hash + ".json")
            if upload_directory.is_symlink() or source_path.is_symlink():
                raise PermissionError("UPLOAD_PATH_DENIED")
            if not source_path.exists():
                source_path.write_bytes(source_bytes)
            value = {
                "key": content_hash,
                "name": "入力した対象環境.json",
                "sha256": content_hash,
                "bytes": len(source_bytes),
                "kind": "ENVIRONMENT",
                "suffix": ".json",
                "relative_path": str(source_path.relative_to(self.db.parent)),
                "intake_state": "SAVED_NOT_PROCESSED",
                "origin": "FORM_INPUT",
            }
            self.store.link(case_id, "WEB_UPLOAD", content_hash, value)
            self.ingest(case_id, content_hash)
            materials.append(self.material(case_id, content_hash))

    def _build_route_request(
        self, case_id, operation, form, job_id, materials, latest_design, source_evidence_id
    ):
        """Map form fields to the existing A-H request contract; no business decision."""
        route = form["route"]
        payload = {}
        scope = "lab"
        request_id = "WEB-" + job_id[:40]
        design_id = "DESIGN-" + data_digest(case_id)[:24]
        if route == "A":
            payload = self._design_payload(form, request_id, design_id, source_evidence_id)
        elif route == "B":
            payload = self._plan_payload(case_id, form)
            scope = "ila-discovery-lab"
        elif route == "C":
            payload = self._incident_payload(case_id, operation, form, job_id, materials)
        elif route == "D":
            payload = {
                "question": form.get("text") or form["title"],
                "source_evidence_ids": [source_evidence_id],
            }
        elif route == "E":
            payload = self._meeting_payload(form)
        elif route == "F":
            payload = {}
        elif route == "G":
            payload = self._aws_design_payload(
                case_id, form, job_id, materials, design_id, latest_design
            )
        elif route == "H":
            payload = {
                "symptom": form.get("text") or form["title"],
                "source_evidence_ids": [source_evidence_id],
                "unknowns": form.get("unknowns", "").splitlines(),
            }
        request_spec = {
            "schema": "ila.eca.full-route-request.v1",
            "request_id": request_id,
            "route": route,
            "scope": scope,
            "profile": self.config.get("model_profile"),
            "payload": payload,
        }
        return request_spec

    def _design_payload(self, form, request_id, design_id, source_evidence_id):
        """Keep user unknowns and received-source references in the A request."""
        payload = {
            "design_id": design_id,
            "task": {
                "id": request_id,
                "kind": form.get("task_kind", "CHANGE"),
                "goal": form.get("text") or form["title"],
                "constraints": form.get("constraints", "").splitlines(),
                "input_unknowns": [
                    {"id": "I" + str(i + 1), "description": x}
                    for i, x in enumerate(form.get("unknowns", "").splitlines())
                ],
            },
            "source_evidence_ids": [source_evidence_id],
        }
        return payload

    def _plan_payload(self, case_id, form):
        """Select an existing authorized change; the existing planner checks approval."""
        changes = self.rows(
            "lifecycle_change_v1", "WHERE change_id=?", (form.get("change_key", case_id),)
        )
        if not changes:
            raise ValueError("EXISTING_APPROVED_CHANGE_REQUIRED")
        if changes[0]["change_id"] != case_id and changes[0]["change_id"] not in self.config.get(
            "allowed_change_ids", []
        ):
            raise PermissionError("CHANGE_TARGET_NOT_AUTHORIZED")
        payload = {"operation": "PLAN", "change_id": changes[0]["change_id"]}
        return payload

    def _incident_payload(self, case_id, operation, form, job_id, materials):
        """Attach evidence and explicitly resume the saved investigation without resetting it."""
        note = self.notification(case_id)
        manifest = note["manifest"] if note else self.incident_manifest(case_id, form)
        self.ensure_notification_request(case_id)
        if operation == "run" and any((material.get("source_id") for material in materials)):
            from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import Investigation

            engine = Investigation(self.db)
            state = engine.get(case_id, self.actor)["state"]
            if state["calls_used"] == 0 and state["steps_used"] == 0 and (not state["pending"]):
                search_evidence_id = self.search(
                    case_id, form.get("text") or form["title"], materials
                )
                engine.resume(
                    case_id,
                    self.actor,
                    reason="利用者が初回調査に入力資料を添付",
                    new_selections=[
                        {
                            "evidence_id": search_evidence_id,
                            "subject_ref": manifest["request"]["subject_id"],
                            "paths": ["/hits"],
                        }
                    ],
                )
        request_directory = self.db.parent / "web_requests"
        request_directory.mkdir(exist_ok=True)
        request_path = request_directory / (job_id + ".incident.json")
        request_path.write_text(canonical_json(manifest), encoding="utf8")
        payload = {"incident_request": str(request_path)}
        if operation == "resume":
            if not form.get("resume_reason", "").strip():
                raise ValueError("EXPLICIT_RESUME_REASON_REQUIRED")
            from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import Investigation

            selections = []
            if any((material.get("source_id") for material in materials)):
                search_evidence_id = self.search(
                    case_id, form.get("text") or form["title"], materials
                )
                selections = [
                    {
                        "evidence_id": search_evidence_id,
                        "subject_ref": manifest["request"]["subject_id"],
                        "paths": ["/hits"],
                    }
                ]
            Investigation(self.db).resume(
                case_id, self.actor, reason=form["resume_reason"], new_selections=selections
            )
        return payload

    def _meeting_payload(self, form):
        """Keep meeting source text separate from the user request; retain old-client behavior."""
        body = form.get("meeting_text") if "meeting_text" in form else form.get("text", "")
        if not body or not body.strip():
            raise ValueError("MEETING_TEXT_OR_FILE_REQUIRED")
        payload = {"text": body}
        return payload

    def _aws_design_payload(self, case_id, form, job_id, materials, design_id, latest_design):
        """Retain source roles and bind a revision to the same design and parent hash."""
        sources = []
        if form.get("environment") or form["parameters"]:
            sources.append(
                {
                    "id": "ENV-" + job_id[:12],
                    "kind": "ENVIRONMENT",
                    "content": {
                        "description": form.get("environment", ""),
                        "parameters": form["parameters"],
                    },
                }
            )
        sources.append(
            {
                "id": "REQ-" + job_id[:12],
                "kind": "REQUIREMENT",
                "content": {
                    "request": form.get("text") or form["title"],
                    "constraints": form.get("constraints", "").splitlines(),
                    "unknowns": form.get("unknowns", "").splitlines(),
                },
            }
        )
        previous_sources = (
            self.document(case_id, latest_design["key"])["data"]["sources"] if latest_design else []
        )
        existing_source_ids = {s["id"] for s in previous_sources}
        for material in materials:
            source_id = "MAT-" + material["key"][:24]
            if source_id in existing_source_ids:
                continue
            source_path = self.upload_path(material)
            if material["suffix"] not in {".txt", ".md", ".html", ".json"}:
                continue
            content = (
                json.loads(source_path.read_bytes())
                if material["suffix"] == ".json"
                else source_path.read_text("utf-8-sig")
            )
            sources.append(
                {
                    "id": source_id,
                    "kind": material["kind"] if material["kind"] != "MEETING" else "REQUIREMENT",
                    "content": content,
                }
            )
        payload = {
            "provider": "LOCAL_DESIGN",
            "design_id": design_id,
            "stage": form.get("stage", "DRAFT"),
            "task": form.get("text") or form["title"],
            "sources": sources,
        }
        if latest_design:
            payload["parent"] = {
                "revision": latest_design["revision"],
                "artifact_sha256": latest_design["artifact_sha256"],
            }
        return payload

    def reconcile(self, cid, p):
        if not p.get("reason", "").strip():
            raise ValueError("EXPLICIT_RECONCILIATION_REASON_REQUIRED")
        if p.get("job_id"):
            jid = p["job_id"]
            old = self.job(jid)
            if old["case_id"] != cid:
                raise PermissionError("JOB_CASE_MISMATCH")
            if old["state"] != "RESULT_UNKNOWN":
                return {
                    "status": "HOLD",
                    "reason": "ONLY_INTERRUPTED_JOB_RECONCILIATION_ALLOWED",
                    "new_model_calls": 0,
                }
            results = self.rows(
                "evidence",
                "WHERE source=? AND adapter=?",
                ("web-result://" + jid, "web_ui_result_v1"),
            )
            if len(results) == 1:
                _, saved = load_evidence(self.db, results[0]["evidence_id"], "lab")
                if saved["case_id"] != cid:
                    raise PermissionError("JOB_CASE_MISMATCH")
                self.attach_documents(cid, saved["result"])
                self.event(
                    jid,
                    cid,
                    "FINISHED",
                    outcome="SAVED_RESULT_RECONCILED_NO_RESEND",
                    result_evidence_id=results[0]["evidence_id"],
                    result_summary=summary(saved["result"]),
                )
                return {
                    "status": "RECONCILED_SAVED_RESULT",
                    "new_model_calls": 0,
                    "automatic_retry": False,
                }
            if results:
                raise ValueError("RESULT_RECONCILIATION_AMBIGUOUS")
        if self.rows("incident_case_head_v1", "WHERE request_id=?", (cid,)):
            from ILA_ECA_REAL_DISCOVERY_LAB.incident.investigation import Investigation

            engine = Investigation(self.db)
            s = engine.get(cid, self.actor)["state"]
            if s["pending"]:
                c = (
                    engine.reconcile_model(cid, self.actor, reason=p["reason"])
                    if s["pending"]["kind"] == "MODEL"
                    else engine.reconcile_saved_read(cid, self.actor)
                )
                return {
                    "status": c["state"]["status"],
                    "reason": c["state"]["reason"],
                    "new_model_calls": 0,
                }
        return {
            "status": "HOLD",
            "reason": "SAVED_RESULT_ONLY_NO_AUTOMATIC_RESEND",
            "new_model_calls": 0,
        }

    def collaborate(self, cid, op, p, jid):
        from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.entry import execute

        if op == "meeting_analyze":
            r = self._case_receipt(cid, p["receipt_id"])
            if not self.generation_available():
                return {
                    "status": "HOLD",
                    "reason": "MODEL_CONNECTION_NOT_CONFIGURED_NO_CALL_SENT",
                    "actual_llm_calls": 0,
                }
            return execute(
                self.db,
                self.local_connection(cid),
                {
                    "schema": "ila.eca.collaboration-request.v1",
                    "case_id": cid,
                    "operation": "meeting_analyze",
                    "payload": {
                        "receipt_id": r["receipt_id"],
                        "resume": bool(p.get("resume")),
                        "profile": self.config.get("model_profile"),
                        "model_path": self.config.get("asr_model_path"),
                    },
                },
            )
        if not self.config.get("collaboration_config"):
            raise ValueError("COLLABORATION_CONNECTION_NOT_CONFIGURED")
        cfg = json.loads(Path(self.config["collaboration_config"]).read_bytes())
        allowed = {
            "google_sync": {"calendar_id", "start", "end"},
            "google_collect": {"meeting_key", "conference_record"},
            "drive_import": {"drive_key", "meeting_key"},
            "gitlab_prepare": {"document_key"},
            "gitlab_submit": {"document_key"},
            "gitlab_refresh": {"submission_id"},
            "gitlab_reconcile": {"submission_id"},
            "formal_status": {"submission_id"},
            "formal_prepare": {"submission_id", "reviewer_key"},
        }
        if op not in allowed or set(p) - allowed[op]:
            raise ValueError("COLLABORATION_FORM_FIELDS_INVALID")
        if op == "drive_import":
            # Operator-selected file IDs from the host configuration, never browser arbitrary IDs/URLs.
            from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.mcp import (
                google_api as configured_google_api,
            )
            from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.google import _import

            value = next(
                (x for x in self.config.get("drive_files", []) if x["key"] == p["drive_key"]), None
            )
            if value is None:
                raise PermissionError("DRIVE_FILE_NOT_AUTHORIZED")
            from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.store import authorize

            authorize(cfg, "meeting_import", cid)
            api = self.google_api or configured_google_api(self.db, cfg, cid)
            meta, raw = api.drive(value["file_id"])
            if value.get("sha256") and sha256(raw).hexdigest() != value["sha256"]:
                raise ValueError("DRIVE_FILE_HASH_CHANGED")
            meeting = (
                self.store.get_link(cid, "GOOGLE_MEETING", p["meeting_key"])
                if p.get("meeting_key")
                else None
            )
            return _import(
                self.db,
                cfg,
                case_id=cid,
                raw=raw,
                source="google-drive://" + value["file_id"],
                version=meta.get("version"),
                kind=value["kind"],
                meeting=meeting,
                suffix=Path(meta["name"]).suffix.lower(),
                source_details=meta,
                execution_kind=api.execution_kind,
            )
        payload = copy.deepcopy(p)
        if op in {"gitlab_prepare", "gitlab_submit"}:
            d = self.document(cid, p["document_key"])
            r = d["record"]
            if d.get("native_lifecycle"):
                raise ValueError("SELECT_REVIEW_ANNEX_NATIVE_TARGET_ALREADY_MANAGED_BY_LIFECYCLE")
            latest = self.rows(
                "design_document_artifact_v1",
                "WHERE domain_id=? AND design_id=? ORDER BY revision DESC LIMIT 1",
                (r["domain_id"], r["design_id"]),
            )
            if latest[0]["revision"] != r["revision"]:
                raise ValueError("SUBMISSION_REVISION_IS_NOT_CURRENT")
            payload = {
                "design_id": r["design_id"],
                "revision": r["revision"],
                "scope": r["domain_id"],
            }
            if self.rows("lifecycle_change_v1", "WHERE change_id=?", (cid,)):
                payload["change_id"] = cid
        if op == "formal_prepare":
            reviewers = self.config.get("reviewers", [])
            v = next((v for v in reviewers if v["key"] == p["reviewer_key"]), None)
            if not v:
                raise PermissionError("REVIEWER_NOT_CONFIGURED")
            payload = {
                "submission_id": p["submission_id"],
                "reviewer_id": v["id"],
                "request_id": "WEB-REVIEW-" + jid[:32],
            }
        return execute(
            self.db,
            cfg,
            {
                "schema": "ila.eca.collaboration-request.v1",
                "case_id": cid,
                "operation": op,
                "payload": payload,
            },
            google_api=self.google_api,
            gitlab_api=self.gitlab_api,
            approval_host=self.approval_host,
        )

    def close(self):
        self.closed = True
        self.pool.shutdown(wait=True, cancel_futures=True)

    def public_settings(self):
        calendars = []
        if self.config.get("collaboration_config"):
            cfg = json.loads(Path(self.config["collaboration_config"]).read_bytes())
            calendars = [
                {
                    "key": data_digest(x),
                    "name": self.config.get("calendar_names", {}).get(
                        x, "許可済みテストカレンダー " + str(i + 1)
                    ),
                }
                for i, x in enumerate(cfg.get("google", {}).get("calendar_ids", []))
            ]
        return {
            "routes": ROUTES,
            "mode": self.mode,
            "generation_enabled": bool(
                self.config.get("generation_enabled") or self.config.get("demo")
            ),
            "max_upload_bytes": self.config.get("max_upload_bytes", 64 * 1024 * 1024),
            "collaboration_configured": bool(self.config.get("collaboration_config")),
            "calendars": calendars,
            "drive_files": [
                {"key": v["key"], "name": v["name"]} for v in self.config.get("drive_files", [])
            ],
            "reviewers": [
                {"key": v["key"], "name": v["name"]} for v in self.config.get("reviewers", [])
            ],
            "changes": [
                {"key": r["change_id"], "name": r["purpose"], "status": r["status"]}
                for r in self.rows("lifecycle_change_v1")
                if r["change_id"] in self.config.get("allowed_change_ids", [])
            ],
            "startup_resume": "NO_AUTOMATIC_RESEND",
            "approval": "EXISTING_GITLAB_IDENTITY_AND_BOUND_VERSION_REQUIRED",
        }

    def evidence_sections(self, cid):
        self.authorize(cid)
        output = []
        for m in self.links(cid, "WEB_UPLOAD"):
            if not m.get("source_id"):
                continue
            # Render only original case-owned source, verify its original hash first.
            self.upload_path(m)
            from ILA_ECA_REAL_DISCOVERY_LAB.knowledge.intake import _read_source

            with closing(connect(self.db)) as con:
                con.row_factory = sqlite3.Row
                r, meta = _read_source(con, m["source_id"], "lab")
            output.append(
                {
                    "key": m["key"],
                    "title": m["name"],
                    "source_id": m["source_id"],
                    "sha256": m["sha256"],
                    "kind": m["kind"],
                    "text": r["text_data"],
                    "version": m["sha256"],
                    "retrieval": "LOCAL_HASH_EMBEDDING_NOT_QUALITY_EVIDENCE",
                }
            )
        return output

    def document_view(self, cid, key):
        d = self.document(cid, key)
        sources = self.evidence_sections(cid)
        quotes = []

        def walk(node):
            if isinstance(node, dict):
                if isinstance(node.get("quote"), str):
                    quotes.append(node["quote"])
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(d["data"])
        citations = []
        for quote in dict.fromkeys(quotes):
            for s in sources:
                start = s["text"].find(quote)
                if quote and start >= 0:
                    citations.append(
                        {
                            "quote": quote,
                            "material_key": s["key"],
                            "title": s["title"],
                            "start": start,
                            "end": start + len(quote),
                            "sha256": s["sha256"],
                        }
                    )
        # A's renderer retains source offsets instead of duplicating source text.
        refs = {r["id"]: r for r in d["data"].get("references", [])}
        for decision in d["data"].get("model_design", {}).get("decisions", []):
            for ref in decision["source_refs"]:
                r = refs[ref]
                s = next((x for x in sources if x["source_id"] == r["source_id"]), None)
                if s:
                    for part in r["context_parts"]:
                        quote = s["text"][part["start"] : part["end"]]
                        citations.append(
                            {
                                "quote": quote,
                                "material_key": s["key"],
                                "title": decision["proposal"] + " → " + s["title"],
                                "start": part["start"],
                                "end": part["end"],
                                "sha256": s["sha256"],
                            }
                        )
        origin = next(x for x in self.documents(cid) if x["key"] == key).get(
            "creation_setting", "UNKNOWN_HISTORICAL_RECORD"
        )
        return {
            "markdown": Path(d["path"]).read_text("utf-8-sig"),
            "citations": citations,
            "artifact_sha256": d["record"]["artifact_sha256"],
            "approval_granted": False,
            "display_kind": "SAVED_RESULT_REDISPLAY",
            "creation_setting": origin,
        }
