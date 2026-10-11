"""
A robot's findings lifecycle (glitched.findings.plan_sync), without a database:
what a scan, a profile change or the user's decision does to each status.
"""

import unittest
from datetime import datetime, timedelta, timezone

from glitched.findings import Existing, Item, plan_sync

NOW = datetime(2026, 10, 4, tzinfo=timezone.utc)


def observed(assessment=2, ref="TID-406"):
    return Item("observed", "check", ref, "network", "Missing authentication", assessment_id=assessment)


def declared(ref="PID-15"):
    return Item("declared", "profile", ref, "debug_port", "Exposed debug interface")


def transitions(existing, present, absent=None):
    plan = plan_sync(existing, present, absent or {}, NOW)
    return plan, [(t[1], t[2], t[3]) for t in plan.transitions]


class LifecycleTest(unittest.TestCase):
    def test_new_finding_is_inserted_open(self):
        plan, moves = transitions({}, [observed()])
        self.assertEqual([i.ref_id for i in plan.inserts], ["TID-406"])
        self.assertEqual(moves, [])

    def test_check_passing_on_a_newer_scan_resolves(self):
        existing = {("check", "TID-406"): Existing(1, "observed", "open", last_assessment_id=1)}
        _, moves = transitions(existing, [], {("check", "TID-406"): (2, None)})
        self.assertEqual(moves, [("open", "resolved", "scan")])

    def test_fix_applied_then_check_passes_resolves(self):
        existing = {("check", "TID-406"): Existing(1, "observed", "fix_applied", last_assessment_id=1)}
        _, moves = transitions(existing, [], {("check", "TID-406"): (2, None)})
        self.assertEqual(moves, [("fix_applied", "resolved", "scan")])

    def test_fix_applied_but_newer_scan_still_sees_it_reopens(self):
        existing = {("check", "TID-406"): Existing(1, "observed", "fix_applied", last_assessment_id=1)}
        _, moves = transitions(existing, [observed(assessment=2)])
        self.assertEqual(moves, [("fix_applied", "open", "scan")])

    def test_fix_applied_survives_a_resync_of_the_same_scan(self):
        existing = {("check", "TID-406"): Existing(1, "observed", "fix_applied", last_assessment_id=2)}
        _, moves = transitions(existing, [observed(assessment=2)])
        self.assertEqual(moves, [])

    def test_inconclusive_or_unrun_check_changes_nothing(self):
        existing = {("check", "TID-406"): Existing(1, "observed", "open", last_assessment_id=1)}
        _, moves = transitions(existing, [], {})
        self.assertEqual(moves, [])

    def test_resolved_finding_that_reappears_reopens(self):
        existing = {("check", "TID-406"): Existing(1, "observed", "resolved", last_assessment_id=1)}
        _, moves = transitions(existing, [observed(assessment=3)])
        self.assertEqual(moves, [("resolved", "open", "scan")])

    def test_declared_finding_resolves_when_the_answer_changes(self):
        existing = {("profile", "PID-15"): Existing(5, "declared", "open", None)}
        _, moves = transitions(existing, [])
        self.assertEqual(moves, [("open", "resolved", "sync")])

    def test_declared_fix_applied_waits_for_the_profile(self):
        existing = {("profile", "PID-15"): Existing(5, "declared", "fix_applied", None)}
        _, moves = transitions(existing, [declared()])
        self.assertEqual(moves, [])

    def test_user_decisions_are_never_overridden(self):
        for status in ("accepted_risk", "not_applicable"):
            existing = {("check", "TID-406"): Existing(1, "observed", status, last_assessment_id=1,
                                                       accepted_until=NOW + timedelta(days=30))}
            _, still_there = transitions(existing, [observed(assessment=2)])
            _, gone = transitions(existing, [], {("check", "TID-406"): (2, None)})
            self.assertEqual((still_there, gone), ([], []), status)

    def test_an_older_scan_never_overrides_a_newer_recheck(self):
        recheck = NOW
        resolved = {("check", "TID-406"): Existing(1, "observed", "resolved", last_assessment_id=1,
                                                   last_checked_at=recheck)}
        stale = observed(assessment=1)
        stale.checked_at = recheck - timedelta(hours=1)
        _, moves = transitions(resolved, [stale])
        self.assertEqual(moves, [])
        still_open = {("check", "TID-406"): Existing(1, "observed", "open", last_assessment_id=1,
                                                     last_checked_at=recheck)}
        _, moves = transitions(still_open, [], {("check", "TID-406"): (2, recheck - timedelta(hours=1))})
        self.assertEqual(moves, [])

    def test_expired_accepted_risk_reopens(self):
        existing = {("check", "TID-406"): Existing(1, "observed", "accepted_risk", last_assessment_id=1,
                                                   accepted_until=NOW - timedelta(days=1))}
        _, moves = transitions(existing, [observed(assessment=2)])
        self.assertEqual(moves, [("accepted_risk", "open", "sync")])



class FixAdviceTest(unittest.TestCase):
    def fix(self, distro, evidence="  9090 -> ws://bot:9090 connected · no token requested"):
        from glitched.findings import fix_for
        return fix_for(None, "observed", "check", "TID-406", ros_distro=distro, evidence=evidence)

    def test_rosbridge_fix_follows_the_ros_version(self):
        self.assertIn("rosauth", self.fix("noetic"))
        ros2 = self.fix("humble")
        self.assertIn("no login of its own", ros2)
        self.assertNotIn("rosauth", ros2)

    def test_no_rosbridge_advice_without_a_websocket_or_ros(self):
        self.assertNotIn("rosbridge", self.fix("humble", evidence="  8080 -> HTTP 200, returns data (JSON)"))
        self.assertNotIn("rosbridge", self.fix(None))


class SeverityTest(unittest.TestCase):
    def test_observed(self):
        from glitched.findings import observed_severity
        self.assertEqual(observed_severity("TID-406", "Accepts WebSocket connections from anyone ... 9090"), "critical")
        self.assertEqual(observed_severity("TID-406", "Data returned without logging in on port(s): 8080"), "high")
        self.assertEqual(observed_severity("TID-408", "Plaintext service(s) reachable: 23/telnet"), "high")
        self.assertEqual(observed_severity("TID-408", "Plaintext service(s) reachable: 80/http"), "medium")
        self.assertEqual(observed_severity("TID-411", "Weak TLS version negotiated: 443/TLSv1"), "medium")

    def test_cves(self):
        from glitched.findings import cve_severity
        self.assertEqual(cve_severity(9.8, False), "critical")
        self.assertEqual(cve_severity(5.0, True), "critical")  # exploited in the wild
        self.assertEqual(cve_severity(7.5, False), "high")
        self.assertEqual(cve_severity(5.3, False), "medium")
        self.assertEqual(cve_severity(2.1, False), "low")
        self.assertEqual(cve_severity(None, False), "medium")

if __name__ == "__main__":
    unittest.main()
