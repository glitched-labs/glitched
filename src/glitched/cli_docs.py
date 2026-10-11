"""
The command reference (docs/cli-reference.md), written from the CLI's own parser so it
can't drift from what `glitched --help` says:

    python -m glitched.cli_docs            # rewrite the reference section of docs/cli-reference.md
    python -m glitched.cli_docs --check    # exit 1 if it's out of date (the tests do this)

Only the part between the GENERATED markers is replaced; the introduction above
it is written by hand.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DOC = Path(__file__).resolve().parents[2] / "docs" / "cli-reference.md"
BEGIN = "<!-- BEGIN GENERATED: CLI REFERENCE (python -m glitched.cli_docs) -->"
END = "<!-- END GENERATED: CLI REFERENCE -->"


def _subcommands(parser: argparse.ArgumentParser) -> list[tuple[str, str, argparse.ArgumentParser]]:
    for action in parser._actions:  # noqa: SLF001 - argparse has no public way to walk subcommands
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            helps = {choice.dest: choice.help or "" for choice in action._choices_actions}  # noqa: SLF001
            return [(name, helps.get(name, ""), sub) for name, sub in action.choices.items()]
    return []


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _usage(parser: argparse.ArgumentParser) -> str:
    usage = parser.format_usage().removeprefix("usage: ").strip()
    return re.sub(r" \[-h\]", "", re.sub(r"\s+", " ", usage))


def _options(parser: argparse.ArgumentParser) -> list[str]:
    rows = []
    for a in parser._actions:  # noqa: SLF001
        if a.dest == "help" or isinstance(a, argparse._SubParsersAction):  # noqa: SLF001
            continue
        name = ", ".join(f"`{o}`" for o in a.option_strings) or f"`{(a.metavar or a.dest).upper()}`"
        if a.option_strings and a.nargs != 0 and not isinstance(a, argparse._StoreConstAction):  # noqa: SLF001
            name += f" `{a.metavar or a.dest.upper()}`"
        what = a.help or ""
        if a.choices:
            what += f"{' - ' if what else ''}one of {', '.join(f'`{c}`' for c in a.choices)}"
        # Defaults read from this machine's settings or environment (a database URL, say) are never written down.
        machine = a.dest in ("database_url", "console", "org") or isinstance(a, argparse._VersionAction)  # noqa: SLF001
        if a.default not in (None, False, "", argparse.SUPPRESS) and not machine and "default" not in what:
            what += f"{' ' if what else ''}(default `{a.default}`)"
        if not a.option_strings and a.nargs in ("?", "*"):
            what = f"optional. {what}" if what else "optional"
        rows.append(f"| {name} | {_cell(what) or '-'} |")
    return rows


def render(parser: argparse.ArgumentParser) -> str:
    out = [BEGIN, "", "Generated from the CLI itself - `glitched <command> --help` says the same.", ""]
    index = []
    sections = []

    def walk(p: argparse.ArgumentParser, path: str, depth: int) -> None:
        for name, help_, sub in _subcommands(p):
            full = f"{path} {name}"
            children = _subcommands(sub)
            anchor = re.sub(r"[^a-z0-9-]", "", full.replace(" ", "-").lower())
            index.append(f"{'  ' * depth}- [`{full}`](#{anchor}) - {help_}")
            mark = "##" if depth == 0 else "###"  # commands, then their subcommands (the page outline)
            sections.append(f"{mark} `{full}`\n\n{help_[:1].upper() + help_[1:]}.\n" if help_ else f"{mark} `{full}`\n")
            if not children:
                sections.append(f"```\n{_usage(sub)}\n```\n")
                rows = _options(sub)
                if rows:
                    sections.append("| Argument | What it does |\n|---|---|\n" + "\n".join(rows) + "\n")
            walk(sub, full, depth + 1)

    walk(parser, "glitched", 0)
    out += index + ["", "## Global options", "", "Every command also takes these:", "",
                    "| Option | What it does |", "|---|---|", *_options(parser), ""] + sections + [END]
    return "\n".join(out).rstrip() + "\n"


def updated(text: str, reference: str) -> str:
    if BEGIN in text and END in text:
        return text[:text.index(BEGIN)] + reference.rstrip("\n") + text[text.index(END) + len(END):]
    return text.rstrip("\n") + "\n\n" + reference


def main(argv: list[str] | None = None) -> int:
    from glitched.cli import build_parser

    check = "--check" in (argv if argv is not None else sys.argv[1:])
    current = DOC.read_text() if DOC.exists() else ""
    wanted = updated(current, render(build_parser()))
    if check:
        if wanted != current:
            print("docs/cli-reference.md is out of date - run: python -m glitched.cli_docs", file=sys.stderr)
            return 1
        return 0
    DOC.write_text(wanted)
    print(f"wrote {DOC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
