"""Unit tests for `glitched setup` / `doctor` helpers (no database needed).

    python -m unittest discover -s tests -t .
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import psycopg2

from glitched import maintenance


class HelpersTest(unittest.TestCase):
    def test_safe_url_hides_password(self):
        # Where the database is - never who connects or their password (URLs and key=value strings alike).
        self.assertEqual(maintenance.safe_url("postgresql://kayla:s3cret@db:5432/glitched"), "db:5432/glitched")
        self.assertEqual(maintenance.safe_url("postgresql://localhost:5432/glitched"), "localhost:5432/glitched")
        self.assertEqual(maintenance.safe_url("host=x.rds port=5432 dbname=c user=u password=s3cret sslmode=require"),
                         "x.rds:5432/c")

    def test_database_help_is_one_line_with_a_fix(self):
        message = maintenance.database_help("postgresql://u:pw@localhost:5999/g",
                                            psycopg2.OperationalError("connection refused\nmore detail"))
        self.assertIn("localhost:5999/g", message)
        self.assertNotIn("pw", message)
        self.assertIn("connection refused", message)
        self.assertNotIn("more detail", message)
        self.assertIn("brew services start", message)


class ChecksTest(unittest.TestCase):
    def test_dbt_runner_without_pipelines_is_a_warning(self):
        # The CLI is useful against an existing database, so a machine that can't build the data isn't broken.
        with mock.patch.object(maintenance.intel, "available", return_value=False):
            check = maintenance.check_dbt_runner()
        self.assertEqual(check.status, "warn")
        self.assertIn("glitched-pipelines", check.detail)

    def test_writable_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(maintenance.check_writable("Data", Path(tmp) / "glitched").status, "ok")

    def test_unwritable_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "file"
            blocker.write_text("not a folder")
            check = maintenance.check_writable("Data", blocker / "glitched")
        self.assertEqual(check.status, "fail")
        self.assertIn("GLITCHED_HOME", check.fix)

    def test_optional_key_is_info_not_failure(self):
        with mock.patch.object(maintenance, "secret", return_value=None):
            self.assertEqual(maintenance.check_key("NVD_API_KEY", "why", "fix").status, "info")


if __name__ == "__main__":
    unittest.main()


class DebugBundleTest(unittest.TestCase):
    def test_bundle_never_contains_secrets(self):
        import argparse
        import zipfile

        secret_value = "sk-ant-THIS-MUST-NOT-LEAK"
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": secret_value, "XDG_CACHE_HOME": tmp}), \
                mock.patch.object(maintenance, "run_checks", return_value=[maintenance.Check("x", "ok", "fine")]):
            log = Path(tmp) / "glitched" / "dbt" / "logs" / "dbt.log"
            log.parent.mkdir(parents=True)
            log.write_text(f"connecting with password=hunter2 and api_key: {secret_value}\n")
            out = Path(tmp) / "bundle.zip"
            maintenance.cmd_debug_bundle(argparse.Namespace(output=str(out), database_url="postgresql://u:pw@h/d"))
            with zipfile.ZipFile(out) as archive:
                text = "".join(archive.read(n).decode() for n in archive.namelist())
        self.assertNotIn(secret_value, text)
        self.assertNotIn("hunter2", text)
        self.assertIn('"value": "set"', text)
