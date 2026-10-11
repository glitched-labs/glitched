"""
The passive checks: what a scan actually sends to a robot, and how the answers
are read. Standard library (+ glitched.catalog) only, so the on-site runner can
use them without the rest of Glitched or a database.

Every check takes a target - a host name, or a targets.Target whose pinned
address is connected to (the name is only used for TLS SNI and the HTTP Host
header) - and an optional progress callback, and returns
(status, detail, evidence_text).
"""

from __future__ import annotations

import base64
import http.client
import os
import re
import socket
import ssl
from collections.abc import Callable

from glitched import catalog
from glitched.targets import Target, endpoint

# Small, robotics-relevant common-port list. Connect-only, non-destructive.
COMMON_PORTS = {
    22: "ssh", 23: "telnet", 80: "http", 443: "https", 554: "rtsp",
    1883: "mqtt", 8883: "mqtt-tls", 5683: "coap", 8080: "http-alt",
    8443: "https-alt", 9090: "rosbridge", 11311: "ros-master", 2222: "ssh-alt",
}

# --------------------------------------------------------------------------
# Passive checks (non-destructive recon only)
# --------------------------------------------------------------------------

# A passive check returns (status, detail, evidence_text).
CheckResult = tuple[str, str, str]
CheckFn = Callable[..., CheckResult]  # (host, progress=None)
# Scan progress events (for the UI): {"type": "plan" | "start" | "item" | "done" | "manual", ...}.
Progress = Callable[[dict], None]


def _report(progress: Progress | None, **event) -> None:
    if progress:
        progress(event)


def _port_result(probe: dict) -> str:
    """One port's outcome in a few words, for live progress."""
    if probe["ssh"]:
        return "open · SSH"
    if probe["tls"]:
        return f"open · {probe['banner'] or 'TLS'}"
    if probe["open"]:
        return "open · " + ("plaintext" if probe["port"] in catalog.PLAINTEXT_PORTS else "unknown")
    return "closed" if probe.get("refused") else "no answer"


def _probe_ports(target: str | Target, progress: Progress | None) -> list[dict]:
    probes = []
    for port in sorted(COMMON_PORTS):
        probe = _probe_port(target, port)
        probes.append(probe)
        _report(progress, type="item", label=f"{port}/{COMMON_PORTS[port]}", result=_port_result(probe),
                flag=probe["open"] and _encryption(probe) == "PLAINTEXT")
    return probes


def _read_greeting(sock: socket.socket, timeout: float = 0.5) -> bytes:
    """What the server says first, without us sending anything (SSH announces itself)."""
    sock.settimeout(timeout)
    try:
        return sock.recv(256)
    except OSError:
        return b""


def _probe_port(target: str | Target, port: int, timeout: float = 2.0) -> dict:
    """Connect-only probe: is the port open, is it SSH, and does it speak TLS?"""
    address, host = endpoint(target)
    result = {"port": port, "open": False, "tls": None, "ssh": False, "banner": "", "refused": False}
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            result["open"] = True
            greeting = _read_greeting(sock)
            if greeting.startswith(b"SSH-"):
                # SSH encrypts without TLS; a TLS handshake would only confuse it.
                result["ssh"] = True
                result["banner"] = greeting.split(b"\r\n", 1)[0].decode("ascii", "replace")[:80]
                return result
            sock.settimeout(timeout)
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    result["tls"] = True
                    result["banner"] = str(tls.version() or "")
            except (ssl.SSLError, OSError):
                result["tls"] = False
    except ConnectionRefusedError:
        result["refused"] = True  # the host answered: it's up, this port is just closed
    except OSError:
        pass  # timed out / no route: nothing answered
    return result


def check_plaintext_comms(target: str | Target, progress: Progress | None = None) -> CheckResult:
    """
    TID-408 Unencrypted Sensitive Data Communication.

    Scan common ports and classify each open one: SSH and TLS are encrypted;
    a port in catalog.PLAINTEXT_PORTS that doesn't speak TLS is plaintext; anything
    else is unknown rather than guessed. Passive recon (connect only), not
    exploitation.
    """
    return classify_comms(endpoint(target)[1], _probe_ports(target, progress))


def _encryption(probe: dict) -> str:
    if probe["ssh"]:
        return "SSH"
    if probe["tls"]:
        return "TLS"
    return "PLAINTEXT" if probe["port"] in catalog.PLAINTEXT_PORTS else "UNKNOWN"


UNREACHABLE = ("Nothing answered on any port: the robot may be switched off, at a different address, "
               "or behind a firewall that drops connections.")


def classify_comms(host: str, probes: list[dict]) -> CheckResult:
    open_probes = [p for p in probes if p["open"]]
    lines = [f"Target: {host}", f"Ports probed: {len(probes)}", ""]
    for p in open_probes:
        svc = COMMON_PORTS.get(p["port"], "?")
        lines.append(f"  {p['port']:>5}/{svc:<12} OPEN  {_encryption(p)}  {p['banner']}")
    evidence = "\n".join(lines)

    def names(kind: str) -> str:
        return ", ".join(f"{p['port']}/{COMMON_PORTS.get(p['port'], '?')}"
                         for p in open_probes if _encryption(p) == kind)

    if not open_probes:
        if any(p.get("refused") for p in probes):
            return ("inconclusive", f"The robot answered, but none of the {len(probes)} common ports are open.",
                    evidence)
        return "inconclusive", UNREACHABLE, evidence
    if plaintext := names("PLAINTEXT"):
        return "confirmed", f"Plaintext service(s) reachable: {plaintext}", evidence
    if unknown := names("UNKNOWN"):
        return "inconclusive", f"Couldn't tell whether these are encrypted - check by hand: {unknown}", evidence
    return "not_present", "Every reachable service is encrypted (SSH or TLS).", evidence


WEAK_TLS_VERSIONS = {"SSLv3", "TLSv1", "TLSv1.1"}


def check_weak_tls(target: str | Target, progress: Progress | None = None) -> CheckResult:
    """
    TID-411 Weak/Insecure Cryptographic Protocol.

    For every port that completes a TLS handshake, record the negotiated
    protocol version. Passive: this only observes what the server offers
    during a normal handshake, no downgrade attempts or cipher fuzzing.
    """
    host = endpoint(target)[1]
    probes = []
    for port in sorted(COMMON_PORTS):
        probe = _probe_port(target, port)
        probes.append(probe)
        result = _port_result(probe) if not probe["tls"] else f"TLS · {probe['banner']}"
        _report(progress, type="item", label=f"{port}/{COMMON_PORTS[port]}", result=result,
                flag=bool(probe["tls"]) and probe["banner"] in WEAK_TLS_VERSIONS)
    tls_probes = [p for p in probes if p["tls"]]

    lines = [f"Target: {host}", f"TLS-capable ports found: {len(tls_probes)}", ""]
    for p in tls_probes:
        svc = COMMON_PORTS.get(p["port"], "?")
        lines.append(f"  {p['port']:>5}/{svc:<12} negotiated {p['banner']}")
    evidence = "\n".join(lines)

    if not tls_probes:
        return "inconclusive", "No TLS-capable services found to assess.", evidence
    weak = [p for p in tls_probes if p["banner"] in WEAK_TLS_VERSIONS]
    if weak:
        svcs = ", ".join(f"{p['port']}/{p['banner']}" for p in weak)
        return "confirmed", f"Weak TLS version negotiated: {svcs}", evidence
    return "not_present", "All TLS services negotiated TLS 1.2 or newer.", evidence


# port -> speaks TLS. Read-only HTTP(S)/rosbridge-style endpoints only.
HTTP_PROBE_PORTS = {80: False, 8080: False, 9090: False, 443: True, 8443: True}

LOGIN_WORDS = re.compile(r"log ?in|sign ?in|signin|auth|sso|session", re.I)
PASSWORD_FIELD = re.compile(r"""<input[^>]+type\s*=\s*["']?password""", re.I)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _connect(address: str, host: str, port: int, use_tls: bool, timeout: float) -> socket.socket:
    """A socket to the pinned address; TLS (unverified, SNI = host name) if asked."""
    sock = socket.create_connection((address, port), timeout=timeout)
    if not use_tls:
        return sock
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except (OSError, ssl.SSLError):
        sock.close()
        raise


def _http_probe(target: str | Target, port: int, use_tls: bool, timeout: float = 3.0) -> dict:
    """A single benign, unauthenticated GET / - read-only, no payload, redirects not followed."""
    address, host = endpoint(target)
    result: dict = {"port": port, "reachable": False, "status": None, "location": "",
                    "auth_header": False, "content_type": "", "body": ""}
    try:
        # http.client gets an already-connected socket, so it never looks the name up again;
        # the Host header still names the robot.
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.sock = _connect(address, host, port, use_tls, timeout)
        try:
            conn.request("GET", "/")
            resp = conn.getresponse()
            result["reachable"] = True
            result["status"] = resp.status
            result["location"] = resp.getheader("Location", "")
            result["auth_header"] = resp.getheader("WWW-Authenticate") is not None
            result["content_type"] = resp.getheader("Content-Type", "").lower()
            result["body"] = resp.read(64 * 1024).decode("utf-8", "replace")
        finally:
            conn.close()
    except (OSError, http.client.HTTPException):
        pass
    return result


# rosbridge's default port: robot control over WebSocket. Always tried as a WebSocket.
WEBSOCKET_PORTS = {9090}


def _wants_websocket(probe: dict) -> bool:
    """A plain GET answered with "upgrade to WebSocket" (426, or a 400 saying so - e.g. rosbridge/tornado)."""
    body = probe.get("body", "").lower()
    return probe.get("status") == 426 or "websocket" in body


def _websocket_probe(target: str | Target, port: int, use_tls: bool, timeout: float = 3.0) -> dict:
    """
    Open a WebSocket handshake with no token and see whether it's accepted.
    Only the handshake is sent - no ROS (or any other) message - and the
    connection is closed straight away.
    """
    address, host = endpoint(target)
    result: dict = {"attempted": True, "accepted": False, "status": None}
    request = (f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}\r\n"
               "Sec-WebSocket-Version: 13\r\n\r\n").encode()
    try:
        with _connect(address, host, port, use_tls, timeout) as conn:
            conn.sendall(request)
            first_line = conn.recv(1024).split(b"\r\n", 1)[0].decode("latin-1")
            parts = first_line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                result["status"] = int(parts[1])
                result["accepted"] = result["status"] == 101
    except (OSError, ssl.SSLError):
        pass
    return result


def classify_http(probe: dict) -> tuple[str, str]:
    """
    What a port says about authentication:
      protected  - 401/403, an auth challenge, a redirect to a login page, a
                   login form, or nothing served at /
      exposed    - a WebSocket (e.g. rosbridge) accepted with no token, or
                   data (JSON) returned without logging in
      unclear    - a page that loads without logging in; may or may not show
                   anything sensitive, so a person has to look
    Returns (verdict, short description for the evidence).
    """
    ws = probe.get("websocket")
    scheme = "wss" if probe.get("tls") else "ws"
    if ws and ws["accepted"]:
        return "exposed", f"{scheme}://{probe.get('host', '')}:{probe['port']} connected · no token requested"
    if ws and ws["status"] in (401, 403):
        return "protected", f"WebSocket asks for credentials (HTTP {ws['status']})"
    if not probe["reachable"]:
        return "protected", "not reachable"
    status, body = probe["status"], probe["body"]
    title = TITLE.search(body)
    title = " ".join(title.group(1).split())[:60] if title else ""
    if status in (401, 403) or probe["auth_header"]:
        return "protected", f"HTTP {status}, asks for credentials"
    if 300 <= status < 400:
        if LOGIN_WORDS.search(probe["location"]):
            return "protected", f"HTTP {status}, redirects to login ({probe['location'][:60]})"
        return "unclear", f"HTTP {status}, redirects to {probe['location'][:60] or '?'}"
    if status >= 400:
        return "protected", f"HTTP {status}, nothing served at /"
    if PASSWORD_FIELD.search(body) or LOGIN_WORDS.search(title):
        return "protected", f"HTTP {status}, login page" + (f" ({title})" if title else "")
    if "json" in probe["content_type"]:
        return "exposed", f"HTTP {status}, returns data (JSON) without logging in"
    return "unclear", f"HTTP {status}, page loads without logging in" + (f" ({title})" if title else "")


def check_unauthenticated_access(target: str | Target, progress: Progress | None = None) -> CheckResult:
    """
    TID-406 Unauthorized Messages or Connections.

    For common HTTP(S)/rosbridge-style ports, send one benign unauthenticated
    GET / and classify the answer (classify_http). A login page or redirect to
    one counts as protected; data returned without logging in is confirmed;
    a page that loads but isn't clearly either is left for a person to check.
    Passive: one read-only request per port, no payloads, no credentials.
    """
    host = endpoint(target)[1]
    probes = []
    for port, tls in HTTP_PROBE_PORTS.items():
        probe = _http_probe(target, port, tls)
        probe.update(host=host, tls=tls)
        # rosbridge and similar answer a plain GET with an error; only a WebSocket handshake tells.
        if port in WEBSOCKET_PORTS or (probe["reachable"] and _wants_websocket(probe)):
            probe["websocket"] = _websocket_probe(target, port, tls)
            if probe["websocket"]["status"] is not None:
                probe["reachable"] = True
        probes.append(probe)
        verdict, text = classify_http(probe) if probe["reachable"] else ("protected", "no web server")
        label = f"{port}/{'https' if tls else 'http'}" + (" + WebSocket" if "websocket" in probe else "")
        _report(progress, type="item", label=label, result=text.split(" · ")[-1] if "://" in text else text,
                flag=verdict == "exposed")
    return classify_access(host, probes)


def classify_access(host: str, probes: list[dict]) -> CheckResult:
    reachable = [p for p in probes if p["reachable"]]
    verdicts = {p["port"]: classify_http(p) for p in reachable}
    lines = [f"Target: {host}", ""] + [f"  {port:>5} -> {text}" for port, (_, text) in verdicts.items()]
    evidence = "\n".join(lines)

    def ports(kind: str) -> str:
        return ", ".join(str(port) for port, (verdict, _) in verdicts.items() if verdict == kind)

    if not reachable:
        return "inconclusive", "No HTTP-style services reachable to assess.", evidence
    if exposed := ports("exposed"):
        ws = [str(p["port"]) for p in reachable if (p.get("websocket") or {}).get("accepted")]
        if ws:
            return ("confirmed", f"The robot-control channel on port {', '.join(ws)} (a rosbridge-style WebSocket) "
                    "accepts connections from anyone on the network - no login.", evidence)
        return "confirmed", f"Port {exposed} hands out data to anyone on the network - no login.", evidence
    if unclear := ports("unclear"):
        return ("inconclusive", f"Page(s) load without logging in on port(s) {unclear} - "
                "check by hand whether they show data or controls", evidence)
    return "not_present", "Every reachable web endpoint requires logging in.", evidence


# EMB3D threat ref -> automatable passive check. Everything not listed here is
# treated as an ACTIVE (human-executed, human-approved) work item - most
# EMB3D threats (hardware fault injection, bootloader/firmware integrity, OS
# privilege escalation, ...) genuinely require physical access, credentials,
# or judgment calls this agent should not make unattended.
PASSIVE_CHECKS: dict[str, CheckFn] = {
    "TID-408": check_plaintext_comms,
    "TID-411": check_weak_tls,
    "TID-406": check_unauthenticated_access,
}


def checks_to_run(profile_threats: set[str], has_host: bool) -> list[str]:
    """Which passive checks a scan runs: all of them for anything with an address."""
    return sorted(PASSIVE_CHECKS) if has_host else sorted(profile_threats & PASSIVE_CHECKS.keys())


def check_traffic() -> dict[str, str]:
    """What each passive check sends, in plain words - built from the same port lists the checks use."""
    ports = ", ".join(str(p) for p in sorted(COMMON_PORTS))
    http = ", ".join(str(p) for p, tls in HTTP_PROBE_PORTS.items() if not tls)
    https = ", ".join(str(p) for p, tls in HTTP_PROBE_PORTS.items() if tls)
    return {
        "TID-408": (f"Opens a TCP connection to each of {len(COMMON_PORTS)} common ports ({ports}), giving up after "
                    "2 seconds. On each open port it waits up to half a second for the service to announce itself, "
                    "then - unless it's SSH - starts a TLS handshake. Nothing else is sent."),
        "TID-411": ("Makes the same connections and TLS handshakes to note which TLS version each service agrees "
                    "to. No downgrade attempts, no cipher probing."),
        "TID-406": (f"Sends one plain GET / to ports {http} over HTTP and {https} over HTTPS - no login, password "
                    "or data, redirects not followed - and reads the status, headers and up to 64 KB of the page. "
                    f"On {', '.join(str(p) for p in sorted(WEBSOCKET_PORTS))} (rosbridge) and any port that asks for "
                    "a WebSocket, it also opens a WebSocket handshake with no token and closes it straight away - "
                    "no ROS messages are sent."),
    }


NEVER_SENT = (
    "No logins, password guesses or default-credential attempts.",
    "No commands to the robot: nothing that moves it, changes settings or publishes to its topics.",
    "No exploits, fuzzing or malformed traffic.",
    "Nothing to any address except this robot's.",
)




def run_checks(target: str | Target, refs: list[str], progress: Progress | None = None) -> list[dict]:
    """
    Run the given passive checks against one target, in order, reporting
    progress. No database: the results are recorded by the caller (locally,
    or by the console for an on-site runner). Returns
    [{ref_id, status, detail, evidence}].
    """
    _report(progress, type="plan", steps=[
        {"ref_id": ref, "title": catalog.CHECK_FINDINGS.get(ref, (ref, ""))[0],
         "activity": catalog.CHECK_ACTIVITY.get(ref, "")} for ref in refs])
    results = []
    for ref in refs:
        _report(progress, type="start", ref_id=ref)

        def item(event: dict, ref_id: str = ref) -> None:
            _report(progress, **event, ref_id=ref_id)

        status, detail, evidence = PASSIVE_CHECKS[ref](target, progress=item if progress else None)
        _report(progress, type="done", ref_id=ref, status=status, detail=detail)
        results.append({"ref_id": ref, "status": status, "detail": detail, "evidence": evidence})
    return results
