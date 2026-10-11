"""
Scan execution split from persistence (glitched.scanning, checks, targets):

- probes connect only to the address the host was resolved to once
- checks/targets/catalog/progress import without the CLI's dependencies (the
  on-site runner ships without them)
- run_checks reports plan/start/item/done events
- no database transaction is open while a robot is probed (needs a database
  with the threat intel: set $GLITCHED_TEST_INTEL_URL, e.g. one made with
  `glitched setup --snapshot`; it's used as a template and never written to)
"""

import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from glitched import checks, progress, targets

INTEL_URL = os.environ.get("GLITCHED_TEST_INTEL_URL")


class PinnedAddressTest(unittest.TestCase):
    """Every probe connects to Target.address; the name is only used for SNI and the Host header."""

    TARGET = targets.Target("robot.lab", ("10.9.8.7",))

    def setUp(self):
        self.connected = []

        def refuse(address, timeout=None, *args, **kwargs):
            self.connected.append(address[0])
            raise ConnectionRefusedError

        patcher = mock.patch("socket.create_connection", side_effect=refuse)
        patcher.start()
        self.addCleanup(patcher.stop)
        resolver = mock.patch("socket.getaddrinfo", side_effect=AssertionError("probes must not resolve again"))
        resolver.start()
        self.addCleanup(resolver.stop)

    def test_every_check_connects_only_to_the_pinned_address(self):
        for ref in checks.PASSIVE_CHECKS:
            checks.PASSIVE_CHECKS[ref](self.TARGET)
        self.assertTrue(self.connected)
        self.assertEqual(set(self.connected), {"10.9.8.7"})

    def test_tls_names_the_host_but_connects_to_the_address(self):
        sock = mock.MagicMock()
        context = mock.MagicMock()
        with mock.patch("socket.create_connection", return_value=sock) as connect, \
                mock.patch("ssl.create_default_context", return_value=context):
            checks._connect("10.9.8.7", "robot.lab", 443, True, 1.0)
        connect.assert_called_once()
        self.assertEqual(connect.call_args.args[0], ("10.9.8.7", 443))
        self.assertEqual(context.wrap_socket.call_args.kwargs["server_hostname"], "robot.lab")

    def test_a_target_prefers_ipv4_and_a_bare_string_is_used_as_is(self):
        self.assertEqual(targets.Target("h", ("fe80::1", "10.0.0.2")).address, "10.0.0.2")
        self.assertEqual(targets.endpoint("10.0.0.3"), ("10.0.0.3", "10.0.0.3"))
        self.assertEqual(targets.endpoint(self.TARGET), ("10.9.8.7", "robot.lab"))


class StandaloneImportTest(unittest.TestCase):
    def test_runner_modules_need_no_third_party_packages(self):
        # Block the CLI's dependencies, then import what the runner will use.
        code = """
import sys
class Block:
    def find_spec(self, name, path=None, target=None):
        if name.split('.')[0] in {'rich', 'psycopg2', 'yaml', 'questionary', 'requests', 'fastapi',
                                  'pydantic', 'dotenv', 'boto3', 'argon2', 'defusedxml'}:
            raise ImportError('blocked: ' + name)
sys.meta_path.insert(0, Block())
import glitched.checks, glitched.targets, glitched.catalog, glitched.progress
import glitched.runner.main, glitched.runner.executor, glitched.runner.client
"""
        src = str(Path(checks.__file__).resolve().parents[1])
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                                env={**os.environ, "PYTHONPATH": src})
        self.assertEqual(result.returncode, 0, result.stderr)


class RunChecksTest(unittest.TestCase):
    def test_events_follow_each_check_and_results_come_back_in_order(self):
        refs = sorted(checks.PASSIVE_CHECKS)
        def fake(ref):
            def check(target, progress=None):
                if progress:
                    progress({"type": "item", "label": "80/http", "result": "open", "flag": False})
                return "not_present", f"{ref} fine", f"evidence {ref}"
            return check

        fakes = {ref: fake(ref) for ref in refs}
        events = []
        with mock.patch.dict(checks.PASSIVE_CHECKS, fakes):
            results = checks.run_checks("10.0.0.1", refs, events.append)
        self.assertEqual([r["ref_id"] for r in results], refs)
        self.assertEqual(results[0]["evidence"], f"evidence {refs[0]}")
        self.assertEqual([e["type"] for e in events], ["plan"] + ["start", "item", "done"] * len(refs))
        job = {"steps": [], "manual": None}
        for event in events:
            progress.apply(job, event)
        self.assertTrue(all(step["state"] == "done" and len(step["items"]) == 1 for step in job["steps"]))


@unittest.skipUnless(INTEL_URL, "set GLITCHED_TEST_INTEL_URL to a database with the threat intel")
class NoTransactionDuringProbeTest(unittest.TestCase):
    def setUp(self):
        import psycopg2

        self.psycopg2 = psycopg2
        base, template = INTEL_URL.rsplit("/", 1)
        self.name = f"glitched_test_{uuid.uuid4().hex[:8]}"
        self.admin = f"{base}/postgres"
        self.url = f"{base}/{self.name}"
        self._admin(f'CREATE DATABASE "{self.name}" TEMPLATE "{template}"')
        self.tmp = tempfile.TemporaryDirectory()
        for patch in (mock.patch("glitched.scanning.EVIDENCE_DIR", Path(self.tmp.name)),
                      mock.patch("glitched.safety.require_acknowledgement")):
            patch.start()
            self.addCleanup(patch.stop)

    def tearDown(self):
        self._admin(f'DROP DATABASE IF EXISTS "{self.name}"')
        self.tmp.cleanup()

    def _admin(self, statement):
        conn = self.psycopg2.connect(self.admin)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(statement)
        conn.close()

    def test_device_scan_and_recheck(self):
        from glitched import scanning
        from glitched.cli import SCHEMA
        from glitched.db import run_in_transaction

        def add(cur):
            cur.execute("INSERT INTO devices (name, host, authz_note) VALUES ('bot', '127.0.0.1', 'lab') RETURNING id")
            return cur.fetchone()[0]

        box = {}
        run_in_transaction(self.url, SCHEMA, lambda cur: box.update(id=add(cur)))
        open_during_probe = []

        def watch():
            conn = self.psycopg2.connect(self.url)
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid() "
                            "AND state LIKE 'idle in transaction%%'", (self.name,))
                open_during_probe.append(cur.fetchone()[0])
            conn.close()

        def fake_run_checks(target, refs, progress=None):
            watch()
            return [{"ref_id": ref, "status": "confirmed" if ref == "TID-406" else "not_present",
                     "detail": f"{ref} detail", "evidence": f"{ref} evidence"} for ref in refs]

        with mock.patch("glitched.checks.run_checks", side_effect=fake_run_checks):
            result = scanning.scan_device(self.url, box["id"])
        self.assertEqual(open_during_probe, [0])
        self.assertIn("TID-406", result["confirmed"])

        def fake_check(target, progress=None):
            watch()
            return "not_present", "Needs a token now.", "401"

        def finding(cur):
            cur.execute("SELECT id FROM device_findings WHERE ref_id = 'TID-406' AND kind = 'observed'")
            return cur.fetchone()[0]

        run_in_transaction(self.url, SCHEMA, lambda cur: box.update(finding=finding(cur)))
        with mock.patch.dict(checks.PASSIVE_CHECKS, {"TID-406": fake_check}):
            outcome = scanning.recheck_finding(self.url, box["finding"])
        self.assertEqual(open_during_probe, [0, 0])
        self.assertEqual(outcome["to_status"], "resolved")

        def stored(cur):
            cur.execute("SELECT f.evidence, a.checked_at IS NOT NULL FROM findings f "
                        "JOIN assessments a ON a.id = f.assessment_id WHERE f.ref_id = 'TID-406'")
            return cur.fetchone()

        run_in_transaction(self.url, SCHEMA, lambda cur: box.update(stored=stored(cur)))
        self.assertEqual(box["stored"], ("TID-406 evidence", True))

    def test_a_device_being_scanned_is_not_scanned_twice(self):
        from glitched import scanning
        from glitched.cli import SCHEMA
        from glitched.db import run_in_transaction

        def add(cur):
            cur.execute("INSERT INTO devices (name, host, authz_note, scan_started_at) "
                        "VALUES ('bot', '127.0.0.1', 'lab', now()) RETURNING id")
            return cur.fetchone()[0]

        box = {}
        run_in_transaction(self.url, SCHEMA, lambda cur: box.update(id=add(cur)))
        with mock.patch("glitched.checks.run_checks", side_effect=AssertionError("must not probe")):
            self.assertEqual(scanning.scan_device(self.url, box["id"]), {})


if __name__ == "__main__":
    unittest.main()
