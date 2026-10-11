"""docs/cli-reference.md's command reference is written from the CLI's own parser (glitched.cli_docs): keep it current."""

import unittest

from glitched import cli_docs
from glitched.cli import build_parser


class CliDocsTest(unittest.TestCase):
    def test_reference_matches_the_cli(self):
        current = cli_docs.DOC.read_text()
        self.assertEqual(cli_docs.updated(current, cli_docs.render(build_parser())), current,
                         "docs/cli-reference.md is out of date - run: python -m glitched.cli_docs")

    def test_every_command_and_argument_is_described(self):
        reference = cli_docs.render(build_parser())
        self.assertNotIn("| - |", reference)  # an argument with no help text
        self.assertNotIn("postgresql://", reference)  # never this machine's settings

    def test_every_command_is_in_the_reference(self):
        reference = cli_docs.render(build_parser())
        for name, _, sub in cli_docs._subcommands(build_parser()):
            self.assertIn(f"## `glitched {name}`", reference)
            for child, _, _ in cli_docs._subcommands(sub):
                self.assertIn(f"### `glitched {name} {child}`", reference)


if __name__ == "__main__":
    unittest.main()
