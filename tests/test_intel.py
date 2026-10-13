"""The private pipelines are optional: commands that need them must say so, not crash."""

import sys
import unittest
from unittest import mock

from glitched import intel


class MissingPipelinesTest(unittest.TestCase):
    def test_missing_package_explains_what_to_do(self):
        with mock.patch.dict(sys.modules, {"glitched_pipelines": None}):
            with self.assertRaises(SystemExit) as raised:
                intel.load("run")
        self.assertIn("glitched-pipelines", str(raised.exception))
        self.assertIn("DATABASE_URL", str(raised.exception))

    def test_available_is_false_when_missing(self):
        with mock.patch.dict(sys.modules, {"glitched_pipelines": None}):
            self.assertFalse(intel.available())

    def test_a_missing_dependency_is_not_hidden(self):
        # Only a missing glitched_pipelines gets the friendly message; a real import error must surface.
        error = ModuleNotFoundError("No module named 'anthropic'", name="anthropic")
        with mock.patch("importlib.import_module", side_effect=[mock.Mock(), error]):
            with self.assertRaises(ModuleNotFoundError):
                intel.load("papers")


if __name__ == "__main__":
    unittest.main()
