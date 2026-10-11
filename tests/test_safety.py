"""Unit tests for the scanning guardrails (no network traffic is sent)."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from glitched import config, safety


class AddressTest(unittest.TestCase):
    def test_private_loopback_link_local_are_not_public(self):
        for address in ["10.1.2.3", "172.16.0.9", "192.168.50.20", "127.0.0.1", "169.254.1.1",
                        "::1", "fe80::1%en0", "fd00::5"]:
            self.assertFalse(safety.is_public(address), address)

    def test_public_addresses(self):
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "100.64.0.1"]:
            self.assertTrue(safety.is_public(address), address)

    def test_host_with_any_public_address_counts_as_public(self):
        self.assertTrue(safety.Target("mixed", ("192.168.1.2", "8.8.8.8")).public)

    def test_unresolvable_host(self):
        with self.assertRaisesRegex(SystemExit, "Can't resolve"):
            safety.resolve("no-such-host.invalid")


class ApprovalTest(unittest.TestCase):
    def target(self, *addresses):
        return mock.patch.object(safety, "resolve", return_value=safety.Target("h", addresses))

    def test_private_target_needs_no_approval(self):
        with self.target("192.168.1.5"):
            self.assertFalse(safety.approve_target("h", allow_public=False))

    def test_public_target_refused_unattended(self):
        with self.target("8.8.8.8"), mock.patch.object(safety.ui, "interactive", return_value=False):
            with self.assertRaisesRegex(SystemExit, "--allow-public"):
                safety.approve_target("h", allow_public=False)

    def test_public_target_with_flag_is_approved(self):
        with self.target("8.8.8.8"):
            self.assertTrue(safety.approve_target("h", allow_public=True))

    def test_public_target_declined_interactively(self):
        with self.target("8.8.8.8"), mock.patch.object(safety.ui, "interactive", return_value=True), \
                mock.patch.object(safety.ui, "confirm", return_value=False):
            with self.assertRaises(SystemExit):
                safety.approve_target("h", allow_public=False)

    def test_last_check_before_probing(self):
        with self.target("9.9.9.9"):
            with self.assertRaisesRegex(SystemExit, "wasn't approved"):
                safety.assert_scannable("h", approved_public=False)
            safety.assert_scannable("h", approved_public=True)  # approved: no error


class AcknowledgementTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = {k: v for k, v in os.environ.items() if k != "GLITCHED_ACKNOWLEDGED"}
        env["GLITCHED_CONFIG"] = str(Path(tmp.name) / "config.toml")
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        dotenv = mock.patch.object(config, "_dotenv", return_value=(None, {}))
        dotenv.start()
        self.addCleanup(dotenv.stop)

    def test_unattended_refuses_until_acknowledged(self):
        with mock.patch.object(safety.ui, "interactive", return_value=False):
            with self.assertRaisesRegex(SystemExit, "glitched acknowledge"):
                safety.require_acknowledgement()

    def test_acknowledging_is_remembered(self):
        with mock.patch.object(safety.ui, "confirm", return_value=True):
            safety.acknowledge()
        self.assertTrue(safety.is_acknowledged())
        with mock.patch.object(safety.ui, "interactive", return_value=False):
            safety.require_acknowledgement()  # no error, no prompt

    def test_declining_raises_and_is_not_saved(self):
        with mock.patch.object(safety.ui, "confirm", return_value=False):
            with self.assertRaises(SystemExit):
                safety.acknowledge()
        self.assertFalse(safety.is_acknowledged())

    def test_new_notice_version_asks_again(self):
        config.set_value("acknowledged", "0")
        self.assertFalse(safety.is_acknowledged())


if __name__ == "__main__":
    unittest.main()
