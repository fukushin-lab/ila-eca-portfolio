"""One optional localhost UI entry; existing Windows commands are unchanged."""

from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import parse_json

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote, quote
import argparse
import hashlib
import json
import os
import socket
import sys
import threading
from ILA_ECA_REAL_DISCOVERY_LAB.webapp.portal import Portal, reason, checked

ASSETS = Path(__file__).with_name("web")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, address, portal):
        self.portal = portal
        super().__init__(address, Handler)

    def handle_error(self, request, client_address):
        pass  # Never dump request context or raw traceback to logs.


class Handler(BaseHTTPRequestHandler):
    server_version = "ILA-ECA-Web"

    def log_message(self, *args):
        pass  # No URLs, query values or submitted bodies in access logs.

    def send(self, status, raw, ctype="application/json; charset=utf-8", filename=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'none'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        )
        if filename:
            self.send_header(
                "Content-Disposition", "attachment; filename*=UTF-8''" + quote(filename, safe="")
            )
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # The accepted job survives a closed tab.

    def json(self, value, status=200):
        self.send(status, json.dumps(value, ensure_ascii=False, allow_nan=False).encode())

    def boundary(self):
        expected = "127.0.0.1:" + str(self.server.server_port)
        if self.headers.get("Host") != expected or self.client_address[0] != "127.0.0.1":
            raise PermissionError("LOCALHOST_ONLY")
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + expected:
            raise PermissionError("CROSS_ORIGIN_DENIED")
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise PermissionError("CROSS_ORIGIN_DENIED")
        if self.path.startswith("/api/") and self.headers.get("X-ILA-UI") != "same-origin":
            raise PermissionError("UI_REQUEST_HEADER_REQUIRED")

    def parse_body(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("CHUNKED_REQUEST_NOT_SUPPORTED")
        n = int(self.headers.get("Content-Length", "0"))
        if n < 1 or n > self.server.portal.config.get("max_upload_bytes", 64 * 1024 * 1024) * 2:
            raise ValueError("REQUEST_SIZE_INVALID")
        if self.headers.get("Content-Type") != "application/json":
            raise ValueError("JSON_TRANSPORT_REQUIRED")

        value = parse_json(
            self.rfile.read(n).decode("utf8"),
            duplicate_error="DUPLICATE_REQUEST_FIELD",
            nonfinite_error="NONFINITE_REQUEST_NUMBER",
        )
        if type(value) is not dict:
            raise ValueError("OBJECT_REQUEST_REQUIRED")
        checked(value)
        return value

    def do_OPTIONS(self):
        self.send(405, b"")

    def do_GET(self):
        self.handle_request(False)

    def do_POST(self):
        self.handle_request(True)

    def handle_request(self, post):
        try:
            self.boundary()
            u = urlsplit(self.path)
            parts = [unquote(x) for x in u.path.split("/") if x]
            q = parse_qs(u.query)
            p = self.server.portal
            if not post and u.path in {"/", "/app.js", "/request-view.js", "/style.css"}:
                name = {
                    "/": "index.html",
                    "/app.js": "app.js",
                    "/request-view.js": "request-view.js",
                    "/style.css": "style.css",
                }[u.path]
                self.send(
                    200,
                    (ASSETS / name).read_bytes(),
                    {
                        "index.html": "text/html; charset=utf-8",
                        "app.js": "text/javascript; charset=utf-8",
                        "request-view.js": "text/javascript; charset=utf-8",
                        "style.css": "text/css; charset=utf-8",
                    }[name],
                )
                return
            body = self.parse_body() if post else {}
            if parts == ["api", "settings"] and not post:
                result = p.public_settings()
            elif parts == ["api", "cases"]:
                if post:
                    if (
                        set(body) != {"form", "request_key"}
                        or not isinstance(body["request_key"], str)
                        or len(body["request_key"]) > 200
                    ):
                        raise ValueError("REGISTRATION_FORM_INVALID")
                    result = p.create_case(body["form"], body["request_key"])
                else:
                    result = p.list_cases(q.get("q", [""])[0])
            elif len(parts) == 3 and parts[:2] == ["api", "jobs"] and not post:
                result = p.job(parts[2])
            elif len(parts) >= 3 and parts[:2] == ["api", "cases"]:
                cid = parts[2]
                p.authorize(cid)
                if len(parts) == 3 and not post:
                    result = p.detail(cid)
                elif len(parts) == 4 and parts[3] == "sources" and not post:
                    result = p.evidence_sections(cid)
                elif len(parts) == 4 and parts[3] == "upload" and post:
                    if (
                        set(body) - {"name", "content_base64", "kind", "meeting_key"}
                        or not {"name", "content_base64", "kind"} <= body.keys()
                    ):
                        raise ValueError("UPLOAD_FORM_INVALID")
                    import base64

                    result = p.save_upload(
                        cid,
                        body["name"],
                        base64.b64decode(body["content_base64"], validate=True),
                        body["kind"],
                        body.get("meeting_key"),
                    )
                elif len(parts) == 4 and parts[3] == "document-view" and not post:
                    result = p.document_view(cid, q.get("key", [""])[0])
                elif len(parts) == 4 and parts[3] == "actions" and post:
                    if (
                        set(body) - {"operation", "payload", "action_key"}
                        or not {"operation", "payload"} <= body.keys()
                    ):
                        raise ValueError("ACTION_FORM_INVALID")
                    payload = body["payload"]
                    if body["operation"] == "google_sync":
                        cfg = json.loads(Path(p.config["collaboration_config"]).read_bytes())
                        key = payload.pop("calendar_key", None)
                        from ILA_ECA_REAL_DISCOVERY_LAB.core.artifacts import data_digest

                        selected = next(
                            (
                                x
                                for x in cfg.get("google", {}).get("calendar_ids", [])
                                if data_digest(x) == key
                            ),
                            None,
                        )
                        if selected is None:
                            raise PermissionError("CALENDAR_NOT_ALLOWED")
                        payload["calendar_id"] = selected
                    key = (
                        body.get("action_key")
                        if body["operation"]
                        in {
                            "gitlab_refresh",
                            "formal_status",
                            "google_sync",
                            "google_collect",
                            "drive_import",
                        }
                        else None
                    )
                    if key is not None and (not isinstance(key, str) or len(key) > 100):
                        raise ValueError("ACTION_KEY_INVALID")
                    result = p.enqueue(cid, body["operation"], payload, key=key)
                elif len(parts) == 4 and parts[3] == "stop" and post:
                    result = p.stop(cid, body["job_id"])
                elif len(parts) == 4 and parts[3] == "download" and not post:
                    raw, name = p.download(
                        cid, q.get("kind", [""])[0], q.get("key", [""])[0], q.get("format", [""])[0]
                    )
                    self.send(200, raw, "application/octet-stream", name)
                    return
                else:
                    raise ValueError("ENDPOINT_NOT_AVAILABLE")
            else:
                raise ValueError("ENDPOINT_NOT_AVAILABLE")
            self.json(
                result, 202 if post and isinstance(result, dict) and result.get("job_id") else 200
            )
        except PermissionError as exc:
            self.json({"error": reason(exc), "automatic_retry": False}, 403)
        except Exception as exc:
            self.json({"error": reason(exc), "automatic_retry": False}, 400)


def main():
    parser = argparse.ArgumentParser(description="ILA/ECA localhost UI, existing database only")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    cfg = json.loads(Path(args.config).read_text("utf-8-sig"))
    if cfg.get("host", "127.0.0.1") != "127.0.0.1":
        raise PermissionError("MULTIUSER_AUTH_NOT_CONFIGURED_LOCALHOST_ONLY")
    portal = Portal(cfg)
    server = Server(("127.0.0.1", cfg.get("port", 8766)), portal)
    print("ILA/ECA UI: http://127.0.0.1:" + str(server.server_port), flush=True)
    print(
        "Mode: " + portal.mode + "; no automatic resend, merge, construction or baseline update.",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        portal.close()


if __name__ == "__main__":
    main()
