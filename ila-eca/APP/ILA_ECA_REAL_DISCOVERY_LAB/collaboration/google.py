"""Calendar/Meet/Drive receipts -> existing E analysis and document registry."""

from pathlib import Path
from hashlib import sha256
from urllib.parse import urlsplit
from datetime import datetime, timezone
import copy
import json
import re
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.store import Store, authorize, safe
from ILA_ECA_REAL_DISCOVERY_LAB.collaboration.adapters import ServiceError
from ILA_ECA_REAL_DISCOVERY_LAB.core.cases import timestamp
from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import canonical_json, data_digest


def meeting_code(url):
    u = urlsplit(url)
    if (
        u.scheme != "https"
        or u.netloc != "meet.google.com"
        or u.query
        or u.fragment
        or not re.fullmatch("/[a-z]{3}-[a-z]{4}-[a-z]{3}", u.path)
    ):
        raise ValueError("MEET_LINK_INVALID")
    return u.path[1:]


def sync_events(db, config, api, *, case_id, calendar_id, start, end):
    authorize(config, "google_read", case_id)
    store = Store(db)
    store.case(case_id)
    if calendar_id not in config.get("google", {}).get("calendar_ids", []):
        raise PermissionError("CALENDAR_NOT_ALLOWED")
    if timestamp(start) >= timestamp(end):
        raise ValueError("CALENDAR_WINDOW_INVALID")
    events = api.events(calendar_id, start, end)
    result = []
    for event in events:
        url = event.get("hangoutLink") or next(
            (
                x.get("uri")
                for x in event.get("conferenceData", {}).get("entryPoints", [])
                if x.get("entryPointType") == "video"
            ),
            None,
        )
        if not url:
            continue
        meeting_code(url)
        begin = event.get("start", {}).get("dateTime")
        finish = event.get("end", {}).get("dateTime")
        if not begin or not finish:
            continue
        timestamp(begin)
        timestamp(finish)
        value = {
            "calendar_id": calendar_id,
            "meeting_id": event["id"],
            "start": begin,
            "end": finish,
            "meet_url": url,
            "status": event.get("status"),
            "calendar_event_version": event.get("etag") or event.get("updated"),
            "original_start": event.get("originalStartTime"),
            "title": event.get("summary", ""),
            "service_execution_kind": api.execution_kind,
        }
        key = data_digest([calendar_id, event["id"]])
        store.link(case_id, "GOOGLE_MEETING", key, value)
        result.append({"meeting_key": key, **value})
    return result


def _import(
    db,
    config,
    *,
    case_id,
    raw,
    source,
    version,
    kind,
    meeting=None,
    segments=None,
    suffix=None,
    source_details=None,
    execution_kind="LOCAL_FILE",
):
    authorize(config, "meeting_import", case_id)
    safe(source)
    if kind not in {"TEXT", "AUDIO"} or not raw:
        raise ValueError("MEETING_MATERIAL_INVALID")
    if kind == "TEXT":
        safe(raw.decode("utf-8-sig"))
    payload = {
        "source": source,
        "version": str(version),
        "sha256": sha256(raw).hexdigest(),
        "kind": kind,
        "meeting": meeting,
        "segments": segments or [],
        "source_details": source_details,
        "intake_origin": (
            "MANUAL_FILE" if source.startswith("manual-file://") else "GOOGLE_API_READ"
        ),
        "speaker_identity": "UNKNOWN_NOT_VERIFIED",
        "service_execution_kind": execution_kind,
    }
    suffix = ".txt" if kind == "TEXT" else suffix
    if suffix not in {".txt", ".wav", ".mp3", ".mp4", ".m4a", ".ogg", ".flac"}:
        raise ValueError("MEETING_MEDIA_TYPE_UNSUPPORTED")
    return Store(db).material(case_id, payload, raw, suffix)


def import_file(db, config, *, case_id, path, meeting_key=None):
    authorize(config, "meeting_import", case_id)
    p = Path(path).resolve(strict=True)
    if p.suffix.lower() not in {".txt", ".vtt", ".wav", ".mp3", ".mp4", ".m4a", ".ogg", ".flac"}:
        raise ValueError("MEETING_FILE_TYPE_UNSUPPORTED")
    raw = p.read_bytes()
    h = sha256(raw).hexdigest()
    store = Store(db)
    meeting = (
        store.get_link(case_id, "GOOGLE_MEETING", meeting_key)
        if meeting_key
        else {"meeting_id": "MANUAL-" + h[:24], "start": None, "end": None, "meet_url": None}
    )
    # File identity is content based: moving/renaming the identical manual file is not another intake.
    return _import(
        db,
        config,
        case_id=case_id,
        raw=raw,
        source="manual-file://" + h,
        version=h,
        kind="TEXT" if p.suffix.lower() in {".txt", ".vtt"} else "AUDIO",
        meeting=meeting,
        suffix=p.suffix.lower(),
    )


def collect(db, config, api, *, case_id, meeting_key, conference_record=None):
    authorize(config, "google_read", case_id)
    authorize(config, "meeting_import", case_id)
    store = Store(db)
    meeting = store.get_link(case_id, "GOOGLE_MEETING", meeting_key)
    if (
        meeting.get("calendar_id") not in api.calendars
        or meeting.get("calendar_id") not in config.get("google", {}).get("calendar_ids", [])
        or meeting.get("status") == "cancelled"
    ):
        raise PermissionError("MEETING_ACCESS_OR_CANCELLED")
    code = meeting_code(meeting["meet_url"])
    receipts = []
    unavailable = []
    records = api.conferences(code, meeting["start"], meeting["end"])
    if conference_record:
        records = [r for r in records if r.get("name") == conference_record]
        if not records:
            raise PermissionError("CONFERENCE_NOT_IN_ALLOWED_MEETING_WINDOW")
    elif len(records) > 1:
        result = {
            "receipts": [],
            "unavailable": [
                {
                    "reason": "AMBIGUOUS_CONFERENCE_EXPLICIT_SELECTION_REQUIRED",
                    "candidates": [r["name"] for r in records],
                }
            ],
            "automatic_join": False,
            "automatic_recording": False,
        }
        store.evidence(case_id, "google_artifact_intake_v1", result)
        return result
    for record in records:
        if not record.get("endTime"):
            unavailable.append({"conference": record.get("name"), "reason": "CONFERENCE_NOT_ENDED"})
            continue
        if timestamp(record["startTime"]) > timestamp(meeting["end"]) or timestamp(
            record["endTime"]
        ) < timestamp(meeting["start"]):
            raise ValueError("CONFERENCE_OUTSIDE_EVENT_WINDOW")
        name = record["name"]
        # Each artifact endpoint may have a different availability/permission outcome.
        base = "https://meet.googleapis.com/v2/" + name
        if not re.fullmatch(r"conferenceRecords/[A-Za-z0-9_-]+", name):
            raise ValueError("CONFERENCE_NAME_INVALID")
        for key in ("transcripts", "recordings"):
            try:
                artifacts = api.pages(base + "/" + key, key)
            except ServiceError as e:
                unavailable.append({"conference": name, "kind": key, "reason": e.code})
                continue
            for artifact in artifacts:
                try:
                    if artifact.get("state") != "FILE_GENERATED":
                        unavailable.append(
                            {"artifact": artifact.get("name"), "reason": "ARTIFACT_NOT_GENERATED"}
                        )
                        continue
                    if key == "transcripts":
                        try:
                            entries = api.entries(artifact["name"])
                        except ServiceError as e:
                            doc_id = artifact.get("docsDestination", {}).get("documentId")
                            if not doc_id:
                                raise
                            meta, raw = api.drive(doc_id)
                            receipts.append(
                                _import(
                                    db,
                                    config,
                                    case_id=case_id,
                                    raw=raw,
                                    source="google-drive://" + doc_id,
                                    version=meta.get("version") or data_digest(meta),
                                    kind="TEXT",
                                    meeting={**meeting, "conference_record": name},
                                    source_details=meta,
                                    execution_kind=api.execution_kind,
                                )
                            )
                            unavailable.append(
                                {
                                    "artifact": artifact["name"],
                                    "reason": e.code,
                                    "fallback": "DRIVE_DOC_TEXT_WITHOUT_ENTRY_TIMESTAMPS",
                                }
                            )
                            continue
                        segments = []
                        for entry in entries:
                            a = timestamp(entry["startTime"])
                            z = timestamp(entry["endTime"])
                            if z < a:
                                raise ValueError("TRANSCRIPT_TIME_RANGE_INVALID")
                            segments.append(
                                {
                                    "start": entry["startTime"],
                                    "end": entry["endTime"],
                                    "text": entry["text"],
                                    "participant_ref": entry.get("participant"),
                                    "name": entry.get("name"),
                                }
                            )
                        segments.sort(key=lambda x: timestamp(x["start"]))
                        if not segments:
                            unavailable.append(
                                {"artifact": artifact["name"], "reason": "NO_TRANSCRIPT_ENTRIES"}
                            )
                            continue
                        text = "\n".join(
                            "[" + s["start"] + " — " + s["end"] + "] " + s["text"] for s in segments
                        )
                        raw = text.encode()
                        version = data_digest({"resource": artifact, "entries": entries})
                        receipts.append(
                            _import(
                                db,
                                config,
                                case_id=case_id,
                                raw=raw,
                                source=artifact["name"],
                                version=version,
                                kind="TEXT",
                                meeting={**meeting, "conference_record": name},
                                segments=segments,
                                source_details={"artifact": artifact, "entries": entries},
                                execution_kind=api.execution_kind,
                            )
                        )
                    else:
                        file_id = artifact["driveDestination"]["fileId"]
                        meta, raw = api.drive(file_id)
                        receipts.append(
                            _import(
                                db,
                                config,
                                case_id=case_id,
                                raw=raw,
                                source="google-drive://" + file_id,
                                version=meta.get("version") or data_digest(meta),
                                kind="AUDIO",
                                meeting={**meeting, "conference_record": name},
                                suffix=Path(meta["name"]).suffix.lower(),
                                source_details=meta,
                                execution_kind=api.execution_kind,
                            )
                        )
                except ServiceError as e:
                    unavailable.append({"artifact": artifact.get("name"), "reason": e.code})
    if not records:
        unavailable.append(
            {"reason": "NO_ACCESSIBLE_CONFERENCE_RECORD", "manual_file_import_available": True}
        )
    if records and not receipts and not unavailable:
        unavailable.append(
            {"reason": "NO_ACCESSIBLE_ARTIFACT", "manual_file_import_available": True}
        )
    result = {
        "receipts": receipts,
        "unavailable": unavailable,
        "automatic_join": False,
        "automatic_recording": False,
        "service_execution_kind": api.execution_kind,
    }
    store.evidence(case_id, "google_artifact_intake_v1", result)
    return result


def analyze(db, config, *, case_id, receipt_id, profile=None, model_path=None, resume=False):
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
    store = r = payload = result = None

    def claim():
        nonlocal store, r
        authorize(config, "meeting_analyze", case_id)
        store = Store(db)
        r = store.receipt(receipt_id)
        if r["case_id"] != case_id:
            raise PermissionError("MEETING_RECEIPT_CASE_MISMATCH")
        if sha256(Path(r["path"]).read_bytes()).hexdigest() != r["sha256"]:
            raise ValueError("MEETING_ORIGINAL_MATERIAL_CHANGED")
        if r["state"] == "DONE":
            flow.output = r["result"]
            return
        if r["state"] == "ANALYZING" and not resume:
            raise ValueError("MEETING_ANALYSIS_PENDING_EXPLICIT_RESUME_REQUIRED")
        if r["state"] == "READY":
            with store.open() as c, c:
                if (
                    c.execute(
                        "UPDATE collaboration_material_v1 SET state='ANALYZING' WHERE receipt_id=? AND state='READY'",
                        (receipt_id,),
                    ).rowcount
                    != 1
                ):
                    raise ValueError("MEETING_ANALYSIS_ALREADY_CLAIMED")

    def prepare_material():
        nonlocal payload
        payload = {}
        if r["kind"] == "AUDIO":
            if not model_path:
                raise ValueError("LOCAL_ASR_MODEL_PATH_REQUIRED_FILE_RETAINED")
            from ILA_ECA_REAL_DISCOVERY_LAB.meeting.review import transcribe

            asr = transcribe(
                db,
                scope="lab",
                path=r["path"],
                model_path=model_path,
                source={
                    "meeting_id": r["meeting"]["meeting_id"],
                    "raw_sha256": r["sha256"],
                    "receipt_id": receipt_id,
                },
            )
            payload["asr_evidence_id"] = asr["evidence_id"]
        else:
            payload["text"] = Path(r["path"]).read_text("utf-8-sig")

    def analyze():
        nonlocal result
        from ILA_ECA_REAL_DISCOVERY_LAB.run_structured_design_v2 import dispatch

        # Source/times stay in the receipt and its evidence. The existing model contract is unchanged.
        result = dispatch(
            db,
            {
                "schema": "ila.eca.full-route-request.v1",
                "route": "E",
                "scope": "lab",
                "request_id": "MEETING-" + receipt_id[:40],
                "profile": profile,
                "payload": payload,
            },
        )

    def link_document():
        safe(result)
        if result.get("document"):
            store.link(
                case_id,
                "MEETING_DOCUMENT",
                receipt_id,
                {
                    "receipt_id": receipt_id,
                    "document": result["document"],
                    "meeting": r["meeting"],
                    "segments": r["segments"],
                    "source_sha256": r["sha256"],
                },
            )

    def finish():
        with store.open() as c, c:
            c.execute(
                "UPDATE collaboration_material_v1 SET state='DONE',result_json=? WHERE receipt_id=? AND state='ANALYZING'",
                (canonical_json(result), receipt_id),
            )
        flow.output = result

    for name, function in {
        "claim": claim,
        "prepare_material": prepare_material,
        "analyze": analyze,
        "link_document": link_document,
        "finish": finish,
    }.items():
        flow.node(graph, name, function)
    graph.add_edge(START, "claim")
    graph.add_conditional_edges(
        "claim", lambda _: flow.choose(END if flow.output is not None else "prepare_material")
    )
    for first, second in [
        ("prepare_material", "analyze"),
        ("analyze", "link_document"),
        ("link_document", "finish"),
        ("finish", END),
    ]:
        graph.add_edge(first, second)
    return invoke(graph, db, "meeting-analysis", [case_id, receipt_id], flow)
