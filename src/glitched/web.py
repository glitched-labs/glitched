"""
`glitched ui`: the robot scan UI, served locally.

A small JSON API plus a static page, on 127.0.0.1 only (see
docs/decisions/0001-robot-scan-ui-runs-locally.md). Every request must carry
the token printed at start-up (set as a SameSite=Strict cookie by the URL that
opens the browser), and a Host header naming this server - so other web pages
in the browser can't read results or start scans. Scans and rechecks run as
background jobs the page polls, under the same safety rules as the CLI.
"""

from __future__ import annotations

import json
import mimetypes
import re
import secrets
import threading
import traceback
import uuid
import webbrowser
from datetime import date, datetime
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

import glitched
from glitched import catalog, safety
from glitched import findings as robot_findings
from glitched import progress, robots, scanning
from glitched import visuals as robot_visuals
from glitched import device_profile
from glitched.device_profile import DeviceProfile
from glitched.db import run_in_transaction

STATIC = Path(__file__).resolve().parent / "web_static"
COOKIE = "glitched_token"
# Nothing loads from the internet; no inline scripts or styles on the page.
PAGE_CSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'"
DRAWING_CSP = "default-src 'none'; style-src 'unsafe-inline'"
MAX_SBOM_BYTES = 10 * 1024 * 1024
IMAGE_CSP = "default-src 'none'"


class ApiError(Exception):
    def __init__(self, status: int, message: str, **extra: Any):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


# --------------------------------------------------------------------------
# Jobs: scans and rechecks run in the background; the page polls them.
# --------------------------------------------------------------------------


class Jobs:
    def __init__(self) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def start(self, activity: str, work: Callable[[Callable[[dict], None]], Any]) -> str:
        """Run work(report) in the background; report(event) records scan progress for the page."""
        job_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._jobs[job_id] = {"id": job_id, "state": "running", "activity": activity, "steps": [],
                                  "manual": None}

        def report(event: dict) -> None:
            with self._lock:
                progress.apply(self._jobs[job_id], event)

        def run() -> None:
            try:
                update = {"state": "done", "result": work(report)}
            except SystemExit as exc:  # a safety rule or a friendly error
                update = {"state": "error", "error": str(exc.code)}
            except Exception as exc:  # noqa: BLE001 - report anything to the page
                traceback.print_exc()
                update = {"state": "error", "error": f"{type(exc).__name__}: {exc}"}
            with self._lock:
                self._jobs[job_id].update(update)

        threading.Thread(target=run, daemon=True).start()
        return job_id

    def get(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            if job_id not in self._jobs:
                raise ApiError(404, "no such job")
            return json.loads(json.dumps(self._jobs[job_id], default=_json_default))  # a snapshot


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------


class Api:
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.jobs = Jobs()

    def _tx(self, work: Callable[[Any], Any]) -> Any:
        from glitched.cli import SCHEMA  # the app schema, including findings

        out: dict[str, Any] = {}

        def write(cur: Any) -> None:
            out["value"] = work(cur)

        try:
            run_in_transaction(self.database_url, SCHEMA, write)
        except SystemExit as exc:
            raise ApiError(400, str(exc.code)) from None
        return out.get("value")

    def _require_ack(self) -> None:
        if not safety.is_acknowledged():
            raise ApiError(409, "Accept the authorized-use notice first.", notice=safety.NOTICE)

    # --- routes -------------------------------------------------------------

    def state(self) -> dict:
        return {"version": glitched.__version__, "acknowledged": safety.is_acknowledged(),
                "notice": safety.NOTICE}

    def acknowledge(self, body: dict) -> dict:
        if body.get("accept") is not True:
            raise ApiError(400, "Tick the box to accept the notice.")
        safety.record_acknowledgement()
        return self.state()

    def robots(self) -> list[dict]:
        def read(cur: Any) -> list[dict]:
            cur.execute(
                """SELECT d.id, d.name, d.host, d.last_scanned_at, d.enabled,
                          count(f.id) FILTER (WHERE f.status IN ('open', 'fix_applied')) AS open,
                          count(f.id) FILTER (WHERE f.status IN ('open', 'fix_applied')
                                              AND f.kind IN ('observed', 'declared')) AS urgent
                   FROM devices d
                   LEFT JOIN device_findings f ON f.device_id = d.id AND d.last_scanned_at IS NOT NULL
                   GROUP BY d.id ORDER BY d.name""")
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]

        return self._tx(read)

    def robot(self, robot_id: int) -> dict:
        def read(cur: Any) -> dict:
            cur.execute("SELECT id, name, host, authz_note, last_scanned_at, last_unreachable_at, profile_id "
                        "FROM devices WHERE id = %s", (robot_id,))
            row = cur.fetchone()
            if row is None:
                raise ApiError(404, "no such robot")
            robot = dict(zip([c[0] for c in cur.description], row, strict=True))
            robot["scanned"] = robot_findings.scanned(cur, robot_id)
            # Findings change only when a scan runs (answers and software lists wait for it).
            robot["findings"] = (robot_findings.list_findings(cur, robot_id, include_closed=True)
                                 if robot["scanned"] else [])
            robot["profile_changed"] = robot["scanned"] and _profile_changed_since_scan(cur, robot_id)
            robot["visual"] = robot_visuals.get(cur, robot_id, _platforms(cur, robot_id))
            robot["parts"] = {}
            for f in robot["findings"]:
                if f["status"] in robot_findings.ACTIVE:
                    robot["parts"][f["part"]] = robot["parts"].get(f["part"], 0) + 1
            return robot

        return self._tx(read)

    def scan_plan(self, robot_id: int) -> dict:
        from glitched.cli import scan_plan

        return self._tx(lambda cur: scan_plan(cur, robot_id))

    def questions(self) -> dict:
        return device_profile.questionnaire()

    def create_robot(self, body: dict) -> dict:
        """
        Add a robot: the same checks as `glitched device add` (single host,
        public addresses only with explicit approval, the notice accepted),
        with the profile built from the form's answers.
        """
        self._require_ack()
        from glitched.cli import _store_profile

        try:
            new = robots.check_new_robot(body)
            target = safety.resolve(new.host)
        except robots.RobotError as exc:
            raise ApiError(400, exc.message, field=exc.field) from None
        except SystemExit as exc:
            raise ApiError(400, str(exc.code), field="host") from None
        name, host, authorization, every = new.name, new.host, new.authorization, new.every_hours
        allow_public = body.get("allow_public") is True
        if target.public and not allow_public:
            raise ApiError(400, f"{host} is a public internet address ({', '.join(target.addresses)}), not a lab "
                                "or home network. Only continue if you're authorized to test it.",
                           field="host", code="public_address")

        def write(cur: Any) -> dict:
            cur.execute("SELECT 1 FROM devices WHERE name = %s", (name,))
            if cur.fetchone():
                raise ApiError(409, f"There's already a robot called {name!r}.", field="name")
            cur.execute("SELECT yaml FROM profiles WHERE name = %s", (name,))
            row = cur.fetchone()
            base = DeviceProfile.from_yaml(row[0]) if row else DeviceProfile(name=name)
            profile = self._profile_from(body, base)
            profile_id = _store_profile(cur, profile)
            cur.execute(
                """INSERT INTO devices (name, host, authz_note, profile_id, scan_interval_hours, allow_public)
                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                (name, host, authorization, profile_id, every, target.public and allow_public),
            )
            robot_id = cur.fetchone()[0]
            if new.template:
                robot_visuals.choose_template(cur, robot_id, new.template)
            return {"id": robot_id}

        return self._tx(write)

    def _profile_from(self, body: dict, base: DeviceProfile) -> DeviceProfile:
        try:
            return robots.profile_from(body, base)
        except robots.RobotError as exc:
            raise ApiError(400, exc.message) from None

    def robot_profile(self, robot_id: int) -> dict:
        def read(cur: Any) -> dict:
            return robots.profile_view(_profile(cur, robot_id))

        return self._tx(read)

    def update_profile(self, robot_id: int, body: dict) -> dict:
        from glitched.cli import _store_profile

        def write(cur: Any) -> dict:
            profile = self._profile_from(body, _profile(cur, robot_id))
            _link_profile(cur, robot_id, _store_profile(cur, profile))
            return {"ok": True}

        return self._tx(write)

    def upload_sbom(self, robot_id: int, data: bytes) -> dict:
        from glitched.cli import _store_profile

        def write(cur: Any) -> dict:
            profile = _profile(cur, robot_id)
            try:
                merged = robots.software_from(data, profile)
            except robots.RobotError as exc:
                raise ApiError(400, exc.message) from None
            _link_profile(cur, robot_id, _store_profile(cur, merged))
            return {"components": len(merged.components),
                    "added": len(merged.components) - len(profile.components)}

        return self._tx(write)

    def library(self) -> list[dict]:
        return robot_visuals.library()

    def set_visual(self, robot_id: int, body: dict) -> dict:
        """Choose a library drawing ({"template"}) or save part positions ({"anchors", "labels"})."""
        def write(cur: Any) -> dict:
            _robot_exists(cur, robot_id)
            platforms = _platforms(cur, robot_id)
            if "template" in body:
                robot_visuals.choose_template(cur, robot_id, str(body["template"]))
            else:
                anchors, labels = body.get("anchors", {}), body.get("labels", {})
                if not isinstance(anchors, dict) or not isinstance(labels, dict):
                    raise ApiError(400, "anchors and labels must be objects")
                robot_visuals.set_anchors(cur, robot_id, platforms, anchors, labels)
            return robot_visuals.get(cur, robot_id, platforms)

        return self._tx(write)

    def upload_image(self, robot_id: int, data: bytes) -> dict:
        def write(cur: Any) -> dict:
            _robot_exists(cur, robot_id)
            robot_visuals.save_upload(cur, robot_id, data)
            return robot_visuals.get(cur, robot_id, _platforms(cur, robot_id))

        return self._tx(write)

    def image(self, robot_id: int) -> tuple[bytes, str]:
        return self._tx(lambda cur: robot_visuals.image(cur, robot_id))

    def finding(self, finding_id: int) -> dict:
        def read(cur: Any) -> dict:
            detail = robot_findings.finding_detail(cur, finding_id)
            if not robot_findings.scanned(cur, detail["device_id"]):
                raise ApiError(404, "no findings before the robot's first scan")
            return detail

        return self._tx(read)

    def set_status(self, finding_id: int, body: dict) -> dict:
        status = body.get("status")
        days = body.get("days")
        if days is not None and (not isinstance(days, int) or not 1 <= days <= 3650):
            raise ApiError(400, "days must be a whole number of days")

        def write(cur: Any) -> dict:
            robot_findings.set_status(cur, finding_id, status, body.get("note") or None, days)
            return robot_findings.finding_detail(cur, finding_id)

        return self._tx(write)

    def recheck(self, finding_id: int) -> dict:
        self._require_ack()
        detail = self.finding(finding_id)
        if detail["kind"] != "observed":
            raise ApiError(400, detail["recheck_help"] or "This finding can't be rechecked automatically.")
        activity = catalog.CHECK_ACTIVITY.get(detail["ref_id"], "Rechecking…")

        return {"job": self.jobs.start(activity, lambda report: scanning.recheck_finding(self.database_url, finding_id)),
                "activity": activity}

    def scan(self, robot_id: int) -> dict:
        self._require_ack()

        def work(report: Callable[[dict], None]) -> dict:
            result = scanning.scan_device(self.database_url, robot_id, report)
            if not result:
                raise SystemExit("This robot is already being scanned - wait for that scan to finish.")
            return result

        activity = "Scanning: connecting to common ports, reading greetings, TLS handshakes, one GET / per web port…"
        return {"job": self.jobs.start(activity, work), "activity": activity}


def _robot_exists(cur: Any, robot_id: int) -> None:
    cur.execute("SELECT 1 FROM devices WHERE id = %s", (robot_id,))
    if cur.fetchone() is None:
        raise ApiError(404, "no such robot")


def _profile(cur: Any, robot_id: int) -> DeviceProfile:
    """The robot's profile, or an empty one named after it (CLI devices may have none)."""
    cur.execute("SELECT d.name, p.yaml FROM devices d LEFT JOIN profiles p ON p.id = d.profile_id WHERE d.id = %s",
                (robot_id,))
    row = cur.fetchone()
    if row is None:
        raise ApiError(404, "no such robot")
    return DeviceProfile.from_yaml(row[1]) if row[1] else DeviceProfile(name=row[0])


def _profile_changed_since_scan(cur: Any, robot_id: int) -> bool:
    """Answers or software list saved after the last scan: the findings don't reflect them yet."""
    cur.execute("SELECT p.updated_at > d.last_scanned_at FROM devices d JOIN profiles p ON p.id = d.profile_id "
                "WHERE d.id = %s", (robot_id,))
    row = cur.fetchone()
    return bool(row and row[0])


def _link_profile(cur: Any, robot_id: int, profile_id: int) -> None:
    cur.execute("UPDATE devices SET profile_id = %s WHERE id = %s", (profile_id, robot_id))


def _platforms(cur: Any, robot_id: int) -> list[str]:
    cur.execute("SELECT p.yaml FROM devices d JOIN profiles p ON p.id = d.profile_id WHERE d.id = %s", (robot_id,))
    row = cur.fetchone()
    return DeviceProfile.from_yaml(row[0]).platforms if row else []


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

ROUTES: list[tuple[str, re.Pattern[str], str]] = [
    ("GET", re.compile(r"^/api/state$"), "state"),
    ("POST", re.compile(r"^/api/acknowledge$"), "acknowledge"),
    ("GET", re.compile(r"^/api/robots$"), "robots"),
    ("GET", re.compile(r"^/api/robots/(\d+)$"), "robot"),
    ("POST", re.compile(r"^/api/robots/(\d+)/scans$"), "scan"),
    ("GET", re.compile(r"^/api/robots/(\d+)/scan-plan$"), "scan_plan"),
    ("GET", re.compile(r"^/api/library$"), "library"),
    ("GET", re.compile(r"^/api/questions$"), "questions"),
    ("POST", re.compile(r"^/api/robots$"), "create_robot"),
    ("GET", re.compile(r"^/api/robots/(\d+)/profile$"), "robot_profile"),
    ("PUT", re.compile(r"^/api/robots/(\d+)/profile$"), "update_profile"),
    ("POST", re.compile(r"^/api/robots/(\d+)/sbom$"), "upload_sbom"),
    ("PUT", re.compile(r"^/api/robots/(\d+)/visual$"), "set_visual"),
    ("POST", re.compile(r"^/api/robots/(\d+)/image$"), "upload_image"),
    ("GET", re.compile(r"^/api/robots/(\d+)/image$"), "image"),
    ("GET", re.compile(r"^/api/findings/(\d+)$"), "finding"),
    ("PATCH", re.compile(r"^/api/findings/(\d+)$"), "set_status"),
    ("POST", re.compile(r"^/api/findings/(\d+)/recheck$"), "recheck"),
    ("GET", re.compile(r"^/api/jobs/([0-9a-f]+)$"), "job"),
]


def _json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"can't serialise {type(value).__name__}")


def load_static() -> dict[str, bytes]:
    """
    The page's files, read once when the server starts. An already-running
    server keeps serving the page that matches its own code: updating Glitched
    on disk never mixes a new page with an old server (restart to update).
    """
    return {str(p.relative_to(STATIC)): p.read_bytes() for p in STATIC.rglob("*") if p.is_file()}


def make_handler(api: Api, token: str, port: int,
                 static: dict[str, bytes] | None = None) -> type[BaseHTTPRequestHandler]:
    files = static if static is not None else load_static()
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{host}" for host in allowed_hosts}

    class Handler(BaseHTTPRequestHandler):
        server_version = "glitched"

        def log_message(self, format: str, *args: Any) -> None:  # quiet
            pass

        # --- guards --------------------------------------------------------

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts

        def _token_ok(self) -> bool:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            return COOKIE in cookie and secrets.compare_digest(cookie[COOKIE].value, token)

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            return origin is None or origin in allowed_origins

        # --- responses -----------------------------------------------------

        def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None,
                  csp: str = PAGE_CSP) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", csp)
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, payload: Any) -> None:
            self._send(status, json.dumps(payload, default=_json_default).encode(), "application/json")

        def _error(self, status: int, message: str, **extra: Any) -> None:
            self._json(status, {"error": message, **extra})

        # --- dispatch ------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        def do_PATCH(self) -> None:  # noqa: N802
            self._handle("PATCH")

        def do_PUT(self) -> None:  # noqa: N802
            self._handle("PUT")

        def _handle(self, method: str) -> None:
            if not self._host_ok():
                return self._error(HTTPStatus.MISDIRECTED_REQUEST, "wrong host")
            url = urlparse(self.path)

            # The URL printed at start-up carries the token once; swap it for a cookie.
            if method == "GET" and url.path == "/" and "token" in parse_qs(url.query):
                given = parse_qs(url.query)["token"][0]
                if not secrets.compare_digest(given, token):
                    return self._error(HTTPStatus.FORBIDDEN, "wrong token - use the link `glitched ui` printed")
                return self._send(HTTPStatus.SEE_OTHER, b"", "text/plain", {
                    "Location": "/",
                    "Set-Cookie": f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200",
                })
            if not self._token_ok():
                return self._send(HTTPStatus.FORBIDDEN, b"Open Glitched with the link `glitched ui` printed.",
                                  "text/plain; charset=utf-8")
            if method != "GET" and not self._origin_ok():
                return self._error(HTTPStatus.FORBIDDEN, "cross-origin request refused")

            if url.path.startswith("/api/"):
                return self._api(method, url.path)
            return self._static(url.path)

        def _api(self, method: str, path: str) -> None:
            for route_method, pattern, name in ROUTES:
                match = pattern.match(path)
                if not match or route_method != method:
                    continue
                try:
                    args: list[Any] = [int(a) if a.isdigit() else a for a in match.groups()]
                    if name == "upload_image":
                        args.append(self._raw_body(robot_visuals.MAX_IMAGE_BYTES))
                    elif name == "upload_sbom":
                        args.append(self._raw_body(MAX_SBOM_BYTES, image=False))
                    elif method in ("POST", "PATCH", "PUT") and name not in ("scan", "recheck"):
                        args.append(self._body())
                    if name == "image":
                        data, content_type = api.image(*args)
                        return self._send(HTTPStatus.OK, data, content_type, csp=IMAGE_CSP)
                    result = api.jobs.get(*args) if name == "job" else getattr(api, name)(*args)
                    return self._json(HTTPStatus.OK, result)
                except ApiError as exc:
                    return self._error(exc.status, exc.message, **exc.extra)
            self._error(HTTPStatus.NOT_FOUND, "no such endpoint")

        def _raw_body(self, limit: int, image: bool = True) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            if length > limit:
                raise ApiError(413, f"That file is larger than {limit // (1024 * 1024)} MB.")
            data = self.rfile.read(length)
            if image and robot_visuals.image_kind(data) is None:  # check before touching the database
                raise ApiError(400, "Upload a PNG, JPEG or WebP photo.")
            return data

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 64 * 1024:
                raise ApiError(413, "request too large")
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                raise ApiError(400, "body must be JSON") from None
            if not isinstance(body, dict):
                raise ApiError(400, "body must be a JSON object")
            return body

        def _static(self, path: str) -> None:
            name = "index.html" if path in ("/", "") else path.lstrip("/")
            # Only names loaded at start-up are served - nothing else on disk is reachable.
            if name not in files:
                return self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
            content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
            if content_type.startswith("text/") or content_type.endswith("javascript"):
                content_type += "; charset=utf-8"
            # SVGs carry their own <style>; as images they can't run scripts.
            csp = DRAWING_CSP if name.endswith(".svg") else PAGE_CSP
            self._send(HTTPStatus.OK, files[name], content_type, csp=csp)

    return Handler


def serve(database_url: str, port: int = 0, open_browser: bool = True) -> None:
    """Run the UI until Ctrl+C. Port 0 picks a free one."""
    robot_visuals.library()  # read the picture list now, together with the page files
    from rich.console import Console

    console = Console()
    token = secrets.token_urlsafe(24)
    api = Api(database_url)
    server = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    server.RequestHandlerClass = make_handler(api, token, server.server_address[1])
    url = f"http://127.0.0.1:{server.server_address[1]}/?token={token}"
    console.print(f"[bold]Glitched UI[/bold] running on this computer only.\n  {url}\n"
                  "[dim]The link holds a one-time key - don't share it. Ctrl+C stops the UI.[/dim]")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\nStopped.")
    finally:
        server.server_close()
