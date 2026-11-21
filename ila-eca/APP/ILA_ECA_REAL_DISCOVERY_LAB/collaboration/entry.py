"""Existing command entry extension, with host-injected credentials and adapters."""

import re
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.mcp import (
    google_api as configured_google_api,
    gitlab_api as configured_gitlab_api,
)
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.store import Store, authorize
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration import google as google, gitlab as gitlab


def execute(db, config, request, *, google_api=None, gitlab_api=None, approval_host=None):
    try:
        return _execute(
            db,
            config,
            request,
            google_api=google_api,
            gitlab_api=gitlab_api,
            approval_host=approval_host,
        )
    except Exception as exc:
        from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.adapters import ServiceError

        reason = (
            exc.code
            if isinstance(exc, ServiceError)
            else (str(exc) if re.fullmatch("[A-Z][A-Z0-9_]*", str(exc)) else type(exc).__name__)
        )
        try:
            Store(db).evidence(
                request["case_id"],
                "collaboration_failure_v1",
                {
                    "operation": request.get("operation"),
                    "reason": reason,
                    "exception_class": type(exc).__name__,
                    "automatic_retry": False,
                    "approval_granted": False,
                },
            )
        except Exception:
            pass  # An unauthorized/unknown case must not be created to log its failure.
        raise


def _execute(db, config, request, *, google_api=None, gitlab_api=None, approval_host=None):
    if (
        set(request) != {"schema", "case_id", "operation", "payload"}
        or request.get("schema") != "ila.eca.collaboration-request.v1"
    ):
        raise ValueError("COLLABORATION_REQUEST_INVALID")
    case = request["case_id"]
    action = request["operation"]
    p = request.get("payload", {})
    fields = {
        "status": set(),
        "google_sync": {"calendar_id", "start", "end"},
        "google_collect": {"meeting_key", "conference_record"},
        "file_import": {"path", "meeting_key"},
        "meeting_analyze": {"receipt_id", "profile", "model_path", "resume"},
        "gitlab_prepare": {"design_id", "revision", "scope", "change_id"},
        "gitlab_submit": {"design_id", "revision", "scope", "change_id"},
        "gitlab_reconcile": {"submission_id"},
        "gitlab_refresh": {"submission_id"},
        "formal_prepare": {"submission_id", "reviewer_id", "request_id"},
        "formal_status": {"submission_id"},
        "formal_reconcile": {"submission_id", "request_id"},
        "formal_receive": {"submission_id", "body_base64", "headers"},
        "formal_resume": {"submission_id", "receipt_id"},
        "formal_approve": {"submission_id", "challenge_id", "target_sha256", "request_id"},
        "formal_revoke": {"submission_id", "target_sha256", "request_id"},
    }
    if action not in fields or not isinstance(p, dict) or set(p) - fields[action]:
        raise ValueError("COLLABORATION_PAYLOAD_FIELDS_INVALID")
    from ILA_ECA_REAL_DISCOVERY_LAB.core.workflows import (
        Cursor,
        Execution,
        StateGraph,
        START,
        END,
        invoke,
        wait_for_request,
    )

    flow = Execution()
    graph = StateGraph(Cursor)

    def status():
        authorize(config, "status", case)
        flow.output = Store(db).status(case)

    def google_connection():
        authorize(config, "google_read", case)
        flow.values["google"] = google_api or configured_google_api(db, config, case)

    def google_sync():
        flow.output = google.sync_events(db, config, flow.values["google"], case_id=case, **p)

    def google_collect():
        flow.output = google.collect(db, config, flow.values["google"], case_id=case, **p)

    def file_import():
        flow.output = google.import_file(db, config, case_id=case, **p)

    def meeting_analyze():
        flow.output = google.analyze(db, config, case_id=case, **p)

    def gitlab_connection():
        flow.values["gitlab"] = gitlab_api or configured_gitlab_api(db, config, case)

    def gitlab_prepare():
        result = gitlab.prepare(db, config, flow.values["gitlab"], case_id=case, **p)
        flow.output = {k: v for k, v in result.items() if k != "files"}

    def gitlab_submit():
        flow.output = gitlab.submit(
            db, config, flow.values["gitlab"], selection={"case_id": case, **p}
        )

    def submission():
        saved = Store(db).submission(p["submission_id"])
        if saved["case_id"] != case:
            raise PermissionError("SUBMISSION_CASE_MISMATCH")

    def gitlab_refresh():
        flow.output = gitlab.refresh(db, config, flow.values["gitlab"], **p)

    def gitlab_reconcile():
        flow.output = gitlab.submit(
            db, config, flow.values["gitlab"], submission_id=p["submission_id"], reconcile=True
        )

    def formal_review():
        from ILA_ECA_REAL_DISCOVERY_LAB.collaboration import approval

        flow.output = approval.execute(
            db,
            config,
            flow.values["gitlab"],
            request,
            approval_host or approval.GitLabApprovalHost(None),
        )

    nodes = {
        "status": status,
        "google_connection": google_connection,
        "google_sync": google_sync,
        "google_collect": google_collect,
        "file_import": file_import,
        "meeting_analyze": meeting_analyze,
        "gitlab_connection": gitlab_connection,
        "gitlab_prepare": gitlab_prepare,
        "gitlab_submit": gitlab_submit,
        "submission": submission,
        "gitlab_refresh": gitlab_refresh,
        "gitlab_reconcile": gitlab_reconcile,
        "formal_review": formal_review,
        "wait": wait_for_request,
    }
    for name, function in nodes.items():
        flow.node(graph, name, function)
    first = (
        "google_connection"
        if action in {"google_sync", "google_collect"}
        else "gitlab_connection" if action.startswith(("gitlab_", "formal_")) else action
    )
    graph.add_edge(START, first)
    graph.add_conditional_edges("google_connection", lambda _: flow.choose(action))
    graph.add_conditional_edges(
        "gitlab_connection",
        lambda _: flow.choose(
            "formal_review"
            if action.startswith("formal_")
            else "submission" if action in {"gitlab_refresh", "gitlab_reconcile"} else action
        ),
    )
    graph.add_conditional_edges("submission", lambda _: flow.choose(action))
    for name in (
        "status",
        "google_sync",
        "google_collect",
        "file_import",
        "meeting_analyze",
        "gitlab_prepare",
        "gitlab_submit",
        "gitlab_refresh",
        "gitlab_reconcile",
    ):
        graph.add_edge(name, END)
    graph.add_conditional_edges(
        "formal_review",
        lambda _: flow.choose(
            lambda: (
                END
                if isinstance(flow.output, dict)
                and (
                    flow.output.get("approval_granted") or flow.output.get("test_approval_granted")
                )
                else "wait"
            )
        ),
    )
    # Resume performs a fresh native identity/permission/version/commit check.
    # The interrupt payload cannot grant approval or change its target.
    graph.add_edge("wait", "gitlab_connection")
    family = "collaboration-review" if action.startswith("formal_") else "collaboration"
    identity = [case, p.get("submission_id")] if action.startswith("formal_") else [case, action]
    return invoke(graph, db, family, identity, flow, resume_wait=action.startswith("formal_"))
