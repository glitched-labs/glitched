"""Unit tests for settings resolution and the config file (no database needed)."""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from glitched import config


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "config.toml"
        env = {k: v for k, v in os.environ.items() if k not in {s.env for s in config.SETTINGS.values()}}
        env["GLITCHED_CONFIG"] = str(self.path)
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        # No .env file in play unless a test adds one.
        dotenv = mock.patch.object(config, "_dotenv", return_value=(None, {}))
        dotenv.start()
        self.addCleanup(dotenv.stop)

    def test_default_then_file_then_dotenv_then_environment(self):
        self.assertEqual(config.lookup("database_url"), ("postgresql://localhost:5432/glitched", "default"))
        config.set_value("database_url", "postgresql://file/db")
        self.assertEqual(config.lookup("database_url"), ("postgresql://file/db", "config file"))
        with mock.patch.object(config, "_dotenv", return_value=("/x/.env", {"DATABASE_URL": "postgresql://dotenv/db"})):
            self.assertEqual(config.lookup("database_url")[0], "postgresql://dotenv/db")
            with mock.patch.dict(os.environ, {"DATABASE_URL": "postgresql://env/db"}):
                self.assertEqual(config.lookup("database_url"), ("postgresql://env/db", "environment (DATABASE_URL)"))

    def test_file_is_private_and_round_trips_special_characters(self):
        config.set_value("nvd_api_key", 'a"b\\c')
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(config.get("nvd_api_key"), 'a"b\\c')
        self.assertTrue(config.unset("nvd_api_key"))
        self.assertIsNone(config.get("nvd_api_key"))
        self.assertFalse(config.unset("nvd_api_key"))

    def test_existing_loose_file_is_tightened(self):
        self.path.write_text("")
        self.path.chmod(0o644)
        config.set_value("research_dir", "/notes")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_display_never_shows_secrets_or_passwords(self):
        self.assertEqual(config.display("anthropic_api_key", "sk-ant-secret"), "set")
        self.assertEqual(config.display("database_url", "postgresql://u:pw@h/d"), "postgresql://u:***@h/d")
        self.assertEqual(config.display("nvd_api_key", None), "-")

    def test_secret_by_environment_name(self):
        with mock.patch.dict(os.environ, {"NVD_API_KEY": "k"}):
            self.assertEqual(config.secret("NVD_API_KEY"), "k")

    def test_unknown_setting_rejected(self):
        with self.assertRaises(KeyError):
            config.set_value("bogus", "x")


if __name__ == "__main__":
    unittest.main()
