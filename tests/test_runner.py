"""
The on-site runner (glitched.runner): its local policy, hash-chained audit
log, state, the rules every job passes before anything is sent, and the
client. No database or console needed.
"""

import http.server
import json
import os
import socket
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from glitched.runner import client as runner_client
from glitched.runner import executor, policy
from glitched.runner.audit import AuditLog
from glitched.runner.state import Pairing, State
from glitched.targets import Target

LAB = """
[targets]
allow = ["10.20.0.0/24", "arm02.lab"]
deny = ["10.20.0.1"]
"""


def target(host, *addresses):
    return Target(host, tuple(addresses))


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.policy = policy.parse(LAB)

    def test_the_template_allows_nothing(self):
        empty = policy.parse(policy.TEMPLATE)
        self.assertFalse(empty.check(target("10.20.0.5", "10.20.0.5")).allowed)
        self.assertFalse(empty.allow_public)

    def test_allowed_networks_and_names(self):
        self.assertTrue(self.policy.check(target("10.20.0.5", "10.20.0.5")).allowed)
        self.assertTrue(self.policy.check(target("arm02.lab", "192.168.9.9")).allowed)
        self.assertTrue(self.policy.check(target("ARM02.lab.", "192.168.9.9")).allowed)

    def test_refusals(self):
        cases = {
            "deny wins inside an allowed network": target("10.20.0.1", "10.20.0.1"),
            "outside the allow list": target("10.30.0.5", "10.30.0.5"),
            "every address must pass": target("cell.lab", "10.20.0.5", "10.99.0.5"),
            "an allowed name that resolves to the internet": target("arm02.lab", "8.8.8.8"),
            "an unresolved name": target("ghost.lab"),
        }
        for why, case in cases.items():
            self.assertFalse(self.policy.check(case).allowed, why)

    def test_public_addresses_need_allow_public(self):
        public = policy.parse('[targets]\nallow = ["8.8.8.0/24"]\n')
        self.assertFalse(public.check(target("8.8.8.9", "8.8.8.9")).allowed)
        allowed = policy.parse('[targets]\nallow = ["8.8.8.0/24"]\nallow_public = true\n')
        self.assertTrue(allowed.check(target("8.8.8.9", "8.8.8.9")).allowed)

    def test_bad_policies_are_refused(self):
        for text in ('[targets]\nallow = ["*.lab"]', '[targets]\nallow = ["0.0.0.0/0"]', '[targets]\nallow = "10.0.0.1"',
                     '[targets]\nallw = []', '[target]\nallow = []', '[evidence]\nmode = "everything"',
                     '[limits]\nmax_jobs_per_hour = 0', '[targets]\nallow_public = "yes"', "not toml ["):
            with self.assertRaises(policy.PolicyError, msg=text):
                policy.parse(text)

    def test_the_console_sees_a_summary_not_the_network(self):
        summary = json.dumps(self.policy.summary())
        self.assertNotIn("10.20", summary)
        self.assertNotIn("arm02", summary)
        self.assertEqual(self.policy.summary()["allow_entries"], 2)


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "audit.jsonl"
        self.log = AuditLog(self.path, echo=False)
        for i in range(4):
            self.log.record("job.done", job=i)

    def tearDown(self):
        self.tmp.cleanup()

    def lines(self):
        return self.path.read_text().splitlines()

    def write(self, lines):
        self.path.write_text("\n".join(lines) + "\n")

    def test_an_untouched_log_verifies(self):
        self.assertEqual(self.log.verify(), (True, "4 entries, chain intact"))

    def test_edits_removals_and_reordering_are_detected(self):
        original = self.lines()
        edited = json.loads(original[1])
        edited["detail"]["job"] = 99
        tampering = {
            "edited": [original[0], json.dumps(edited, sort_keys=True)] + original[2:],
            "removed": [original[0]] + original[2:],
            "reordered": [original[1], original[0]] + original[2:],
            "truncated from the start": original[1:],
        }
        for how, lines in tampering.items():
            self.write(lines)
            ok, message = self.log.verify()
            self.assertFalse(ok, how)
        self.write(original)
        self.assertTrue(self.log.verify()[0])

    def test_new_entries_follow_on(self):
        self.log.record("runner.paused", reason="maintenance")
        self.assertEqual(self.log.entries()[-1]["seq"], 5)
        self.assertTrue(self.log.verify()[0])


class StateTest(unittest.TestCase):
    def test_replays_pause_and_pairing(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = State(Path(tmp))
            self.assertTrue(state.take("7:abc"))
            self.assertFalse(state.take("7:abc"))
            self.assertEqual(state.jobs_in_last_hour(), 1)
            state.pause("lab day")
            self.assertTrue(state.paused)
            state.resume()
            self.assertFalse(state.paused)
            state.save_pairing(Pairing("https://c.example", 3, "secret"))
            self.assertEqual(state.pairing().token, "secret")
            self.assertEqual(os.stat(Path(tmp) / "pairing.json").st_mode & 0o777, 0o600)


class ExecutorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.tmp.name))
        self.audit = AuditLog(Path(self.tmp.name) / "audit.jsonl", echo=False)
        self.policy = policy.parse(LAB)
        self.connected = []

        def connect(address, timeout=None, *args, **kwargs):
            self.connected.append(address)
            raise ConnectionRefusedError

        resolved = {"robot.lab": ("10.20.0.5",), "router.lab": ("10.20.0.1",), "evil.lab": ("10.20.0.5", "169.254.169.254")}
        patches = [mock.patch("socket.create_connection", side_effect=connect),
                   mock.patch("glitched.targets.resolve", side_effect=lambda host: Target(host, resolved[host]))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.n = 0

    def tearDown(self):
        self.tmp.cleanup()

    def job(self, kind="detect", host="robot.lab", **changes):
        self.n += 1
        job = {"id": self.n, "kind": kind, "host": host, "nonce": f"n{self.n}",
               "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()}
        job.update(changes)
        return {k: v for k, v in job.items() if v is not None}

    def run_job(self, job, **kwargs):
        return executor.execute(job, kwargs.get("policy", self.policy), self.state, self.audit,
                                kwargs.get("policy_error", ""))

    def test_detect_probes_only_the_pinned_allowed_address(self):
        outcome = self.run_job(self.job())
        self.assertEqual(outcome["status"], "done", outcome)
        self.assertEqual({address for address, port in self.connected}, {"10.20.0.5"})
        self.assertEqual(sorted(port for _, port in self.connected), sorted(executor.DETECT_PORTS))

    def test_preflight_sends_nothing(self):
        allowed = self.run_job(self.job("preflight"))
        denied = self.run_job(self.job("preflight", host="router.lab"))
        self.assertEqual(self.connected, [])
        self.assertEqual((allowed["result"]["allowed"], denied["result"]["allowed"]), (True, False))
        self.assertIn("denies", denied["result"]["reason"])

    def test_refusals_send_nothing(self):
        past = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        cases = {
            "denied host": (self.job(host="router.lab"), {}),
            "one address outside the policy": (self.job(host="evil.lab"), {}),
            "scan isn't run by this version": (self.job("scan"), {}),
            "unknown kind": (self.job("shell"), {}),
            "extra fields (ports, payloads)": (self.job(ports=[22, 80]), {}),
            "expired": (self.job(expires_at=past), {}),
            "no expiry": (self.job(expires_at=None), {}),
            "no nonce": (self.job(nonce=None), {}),
            "no usable policy": (self.job(), {"policy": None, "policy_error": "no policy file"}),
            "a range": (self.job(host="10.20.0.0/24"), {}),
        }
        for why, (job, kwargs) in cases.items():
            self.assertEqual(self.run_job(job, **kwargs)["status"], "refused", why)
        self.assertEqual(self.connected, [])
        refused = [e for e in self.audit.entries() if e["event"] == "job.refused"]
        self.assertEqual(len(refused), len(cases))

    def test_replays_are_refused(self):
        job = self.job("preflight")
        self.assertEqual(self.run_job(job)["status"], "done")
        self.assertEqual(self.run_job(job)["status"], "refused")

    def test_the_pause_switch(self):
        self.state.pause()
        self.assertEqual(self.run_job(self.job())["status"], "refused")
        self.assertEqual(self.connected, [])

    def test_hourly_limit(self):
        limited = policy.parse(LAB + "\n[limits]\nmax_jobs_per_hour = 2\n")
        statuses = [self.run_job(self.job("preflight"), policy=limited)["status"] for _ in range(4)]
        self.assertEqual(statuses, ["done", "done", "refused", "refused"])

    def test_minimal_evidence_sends_no_banners(self):
        minimal = policy.parse(LAB + '\n[evidence]\nmode = "minimal"\n')
        with mock.patch("glitched.checks._probe_port",
                        side_effect=lambda t, port: {"port": port, "open": True, "tls": None, "ssh": True,
                                                     "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu", "refused": False}):
            outcome = self.run_job(self.job(), policy=minimal)
        self.assertTrue(all(p["banner"] == "" for p in outcome["result"]["probes"]))


class Redirector(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        Redirector.seen.append((self.path, self.headers.get("Authorization")))
        self.send_response(307)
        self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/stolen")
        self.end_headers()

    def log_message(self, *args):
        pass


class ClientTest(unittest.TestCase):
    def test_https_unless_development(self):
        with self.assertRaises(ValueError):
            runner_client.Client("http://console.example.com")
        with self.assertRaises(ValueError):
            runner_client.Client("https://console.example.com/path")
        self.assertEqual(runner_client.Client("http://console:8000", allow_http=True).console, "http://console:8000")

    def test_redirects_are_not_followed_with_the_token(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), Redirector)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            client = runner_client.Client(f"http://127.0.0.1:{server.server_port}", "secret-token", allow_http=True)
            with self.assertRaises(runner_client.ConsoleError) as caught:
                client.post("/runner/v1/jobs/next", {})
            self.assertEqual(caught.exception.status, 307)
            self.assertEqual([path for path, _ in Redirector.seen], ["/runner/v1/jobs/next"])  # never /stolen
        finally:
            server.shutdown()
        self.assertIsNotNone(socket)


if __name__ == "__main__":
    unittest.main()
