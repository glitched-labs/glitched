"""
The passive checks' verdicts, from recorded probe results (no network).

A robot that only exposes SSH, or a web UI behind a login page, must not be
reported as unencrypted or unauthenticated.
"""

import re
import socket
import threading
import unittest
from pathlib import Path

from glitched import cli, device_profile


def port(number, open=True, tls=None, ssh=False, banner=""):
    return {"port": number, "open": open, "tls": tls, "ssh": ssh, "banner": banner}


class PlaintextCommsTest(unittest.TestCase):
    def test_ssh_only_is_encrypted(self):
        status, detail, _ = cli.classify_comms("bot", [port(22, ssh=True, banner="SSH-2.0-OpenSSH_9.6")])
        self.assertEqual(status, "not_present")

    def test_telnet_next_to_ssh_is_plaintext(self):
        status, detail, _ = cli.classify_comms("bot", [port(22, ssh=True), port(23, tls=False)])
        self.assertEqual(status, "confirmed")
        self.assertIn("23/telnet", detail)
        self.assertNotIn("22", detail)

    def test_unidentified_service_is_not_called_plaintext(self):
        status, detail, _ = cli.classify_comms("bot", [port(2222, tls=False)])  # not SSH, not TLS
        self.assertEqual(status, "inconclusive")

    def test_tls_is_encrypted(self):
        status, _, _ = cli.classify_comms("bot", [port(443, tls=True, banner="TLSv1.3"), port(22, ssh=True)])
        self.assertEqual(status, "not_present")

    def test_nothing_answering_means_unreachable(self):
        status, detail, _ = cli.classify_comms("bot", [port(p, open=False) for p in (22, 80)])
        self.assertEqual((status, detail), ("inconclusive", cli.UNREACHABLE))

    def test_refusals_mean_the_robot_answered(self):
        refused = [{**port(p, open=False), "refused": True} for p in (22, 80)]
        status, detail, _ = cli.classify_comms("bot", refused)
        self.assertEqual(status, "inconclusive")
        self.assertNotEqual(detail, cli.UNREACHABLE)
        self.assertIn("answered", detail)

    def test_a_closed_port_is_seen_as_refused(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        free_port = server.getsockname()[1]
        server.close()  # nothing listens there now
        probe = cli._probe_port("127.0.0.1", free_port)
        self.assertFalse(probe["open"])
        self.assertTrue(probe["refused"])

    def test_ssh_greeting_is_recognised_without_sending_anything(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        received = []

        def serve():
            conn, _ = server.accept()
            conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            conn.settimeout(1)
            try:
                received.append(conn.recv(64))
            except OSError:
                received.append(b"")
            conn.close()

        thread = threading.Thread(target=serve)
        thread.start()
        probe = cli._probe_port("127.0.0.1", server.getsockname()[1])
        thread.join()
        server.close()
        self.assertTrue(probe["ssh"])
        self.assertEqual(probe["banner"], "SSH-2.0-OpenSSH_9.6")
        self.assertEqual(received, [b""])  # the probe sent nothing

    def test_detect_does_not_mark_ssh_as_unencrypted(self):
        [(reason, suggestion)] = device_profile.from_probes([port(22, ssh=True)], "bot")
        self.assertIn("SSH", reason)
        self.assertNotIn("PID-4112", suggestion.properties)


def page(status=200, body="", content_type="text/html", location="", auth_header=False, number=80):
    return {"port": number, "reachable": True, "status": status, "location": location,
            "auth_header": auth_header, "content_type": content_type, "body": body}


LOGIN_FORM = """<html><head><title>Robot Control - Sign in</title></head>
<body><form action="/session"><input name="user"><input type="password" name="pw"></form></body></html>"""


class UnauthenticatedAccessTest(unittest.TestCase):
    def verdict(self, probe):
        return cli.classify_http(probe)[0]

    def test_login_form_is_protected(self):
        self.assertEqual(self.verdict(page(body=LOGIN_FORM)), "protected")

    def test_password_field_without_login_title_is_protected(self):
        self.assertEqual(self.verdict(page(body="<input type='password'>")), "protected")

    def test_redirect_to_login_is_protected(self):
        self.assertEqual(self.verdict(page(status=302, location="/login?next=/")), "protected")

    def test_auth_challenge_is_protected(self):
        self.assertEqual(self.verdict(page(status=401, auth_header=True)), "protected")

    def test_open_json_api_is_exposed(self):
        self.assertEqual(self.verdict(page(body='{"joints": [0.1, 0.2]}', content_type="application/json")),
                         "exposed")

    def test_plain_page_needs_a_person(self):
        self.assertEqual(self.verdict(page(body="<title>Dashboard</title><div id=app></div>")), "unclear")

    def test_check_results(self):
        status, _, _ = cli.classify_access("bot", [page(body=LOGIN_FORM), page(status=302, location="/auth",
                                                                                number=8080)])
        self.assertEqual(status, "not_present")
        status, detail, _ = cli.classify_access("bot", [page(body=LOGIN_FORM),
                                                        page(body="{}", content_type="application/json",
                                                             number=8080)])
        self.assertEqual(status, "confirmed")
        self.assertIn("8080", detail)
        status, _, _ = cli.classify_access("bot", [page(body="<h1>Status</h1>")])
        self.assertEqual(status, "inconclusive")


class FakeRosbridge:
    """
    Answers like rosbridge (tornado): a plain GET gets 400 "Can 'Upgrade' only
    to 'WebSocket'"; a WebSocket handshake is accepted (101), or refused with
    401 when `require_token`. Records every byte received.
    """

    def __init__(self, require_token=False):
        self.require_token = require_token
        self.received = []
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except OSError:
                    pass
                upgrade = b"upgrade: websocket" in data.lower()
                if upgrade and not self.require_token:
                    reply = (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                             b"Sec-WebSocket-Accept: x\r\n\r\n")
                elif upgrade:
                    reply = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
                else:
                    body = b'Can "Upgrade" only to "WebSocket".'
                    reply = (b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\n\r\n" + body)
                conn.sendall(reply)
                try:  # anything the client sends after the handshake
                    extra = conn.recv(4096)
                except OSError:
                    extra = b""
                self.received.append((data, extra))

    def close(self):
        self.server.close()


class RosbridgeTest(unittest.TestCase):
    def probe(self, fake):
        probe = cli._http_probe("127.0.0.1", fake.port, False)
        probe.update(host="127.0.0.1", tls=False)
        self.assertTrue(cli._wants_websocket(probe), probe)
        probe["websocket"] = cli._websocket_probe("127.0.0.1", fake.port, False)
        return probe

    def test_open_rosbridge_is_flagged_not_called_protected(self):
        fake = FakeRosbridge()
        try:
            plain = cli._http_probe("127.0.0.1", fake.port, False)
            self.assertEqual(cli.classify_http(plain)[0], "protected")  # what the old check concluded
            status, detail, evidence = cli.classify_access("robot", [self.probe(fake)])
        finally:
            fake.close()
        self.assertEqual(status, "confirmed")
        self.assertIn("rosbridge-style WebSocket", detail)
        self.assertIn(f"ws://127.0.0.1:{fake.port} connected · no token requested", evidence)

    def test_only_the_handshake_is_sent(self):
        fake = FakeRosbridge()
        try:
            self.probe(fake)
            fake.thread.join(timeout=0.2)
        finally:
            fake.close()
        handshake, after = fake.received[-1]
        self.assertTrue(handshake.startswith(b"GET / HTTP/1.1"))
        self.assertNotIn(b"Authorization", handshake)
        self.assertEqual(after, b"")  # no ROS message, nothing after the handshake

    def test_rosbridge_with_token_is_protected(self):
        fake = FakeRosbridge(require_token=True)
        try:
            status, _, _ = cli.classify_access("robot", [self.probe(fake)])
        finally:
            fake.close()
        self.assertEqual(status, "not_present")


class ScanPreviewTest(unittest.TestCase):
    """The "what a scan sends" text must match what the checks really do."""

    def test_every_check_is_described(self):
        traffic = cli.check_traffic()
        self.assertEqual(set(traffic), set(cli.PASSIVE_CHECKS))
        for ref in cli.PASSIVE_CHECKS:
            self.assertIn(ref, cli.catalog.CHECK_FINDINGS)
            self.assertIn(ref, cli.catalog.CHECK_ACTIVITY)

    def test_descriptions_list_the_real_ports(self):
        traffic = cli.check_traffic()
        listed = {int(n) for n in re.findall(r"\b\d{2,5}\b", traffic["TID-408"].split("(")[1].split(")")[0])}
        self.assertEqual(listed, set(cli.COMMON_PORTS))
        for port in cli.HTTP_PROBE_PORTS:
            self.assertIn(str(port), traffic["TID-406"])


class CheckSelectionTest(unittest.TestCase):
    def test_a_robot_with_an_address_gets_every_check(self):
        # Even a profile that declares nothing network-related: the scan still looks.
        self.assertEqual(cli.checks_to_run(set(), has_host=True), sorted(cli.PASSIVE_CHECKS))
        self.assertEqual(cli.checks_to_run({"TID-210"}, has_host=True), sorted(cli.PASSIVE_CHECKS))

    def test_no_address_no_checks(self):
        self.assertEqual(cli.checks_to_run({"TID-210"}, has_host=False), [])


class ScanProgressTest(unittest.TestCase):
    """Checks report every port or request as they try it (the UI's live scan)."""

    def test_every_port_is_reported(self):
        events = []
        cli.check_plaintext_comms("127.0.0.1", progress=events.append)
        self.assertEqual([e["label"] for e in events], [f"{p}/{cli.COMMON_PORTS[p]}" for p in sorted(cli.COMMON_PORTS)])
        self.assertTrue(all(e["type"] == "item" and e["result"] for e in events))

    def test_open_rosbridge_is_flagged_live(self):
        fake = FakeRosbridge()
        try:
            events = []
            probe = cli._http_probe("127.0.0.1", fake.port, False)
            probe.update(host="127.0.0.1", tls=False, websocket=cli._websocket_probe("127.0.0.1", fake.port, False))
            verdict, text = cli.classify_http(probe)
            events.append({"flag": verdict == "exposed", "text": text})
        finally:
            fake.close()
        self.assertTrue(events[0]["flag"])

    def test_jobs_track_steps(self):
        from glitched import progress
        job = {"steps": [], "manual": None}
        for event in ({"type": "plan", "steps": [{"ref_id": "TID-408", "title": "t", "activity": "a"}]},
                      {"type": "start", "ref_id": "TID-408"},
                      {"type": "item", "ref_id": "TID-408", "label": "22/ssh", "result": "closed", "flag": False},
                      {"type": "done", "ref_id": "TID-408", "status": "not_present", "detail": "d"},
                      {"type": "manual", "count": 4},
                      {"type": "item", "ref_id": "TID-999", "label": "x", "result": "y", "flag": False}):
            progress.apply(job, event)
        step = job["steps"][0]
        self.assertEqual((step["state"], step["status"], len(step["items"]), job["manual"]),
                         ("done", "not_present", 1, 4))


class NoStaleCommandsTest(unittest.TestCase):
    def test_no_references_to_the_old_entry_point(self):
        src = Path(cli.__file__).resolve().parent
        stale = [f"{path.relative_to(src)}:{n}" for path in src.rglob("*")
                 if path.suffix in {".py", ".sql", ".yml"} and "transform/target" not in str(path)
                 for n, line in enumerate(path.read_text().splitlines(), 1)
                 if re.search(r"assess\.py|glitch_agent", line)]
        self.assertEqual(stale, [], "use `glitched <command>` instead of the old assess.py / glitch_agent paths")


if __name__ == "__main__":
    unittest.main()
