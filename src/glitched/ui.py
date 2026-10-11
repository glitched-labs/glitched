"""
Interactive prompts for the CLI: arrow-key menus, checkboxes and yes/no.

Every prompt in cli.py / device_profile.py goes through here so the CLI
behaves the same everywhere:

  ↑/↓ move · Space toggles a checkbox · Enter confirms · Ctrl-C cancels

When stdin isn't a terminal (piped answers, scripts, CI) the same calls fall
back to plain typed input, so automation keeps working.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import TypeVar

import questionary
from questionary import Choice, Style
from rich.prompt import Confirm, Prompt

T = TypeVar("T")

STYLE = Style([
    ("qmark", "fg:ansicyan bold"),
    ("question", "bold"),
    ("pointer", "fg:ansicyan bold"),
    ("highlighted", "fg:ansicyan bold"),
    ("selected", "fg:ansigreen"),
    ("answer", "fg:ansigreen bold"),
    ("instruction", "fg:ansibrightblack"),
])


def interactive() -> bool:
    """True when a person can answer prompts (stdin and stdout are terminals)."""
    return _interactive()


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _ask(question: questionary.Question):
    answer = question.ask()
    if answer is None:  # Ctrl-C / Esc
        raise SystemExit("cancelled")
    return answer


def select(message: str, choices: Sequence[tuple[str, T]], default: T | None = None) -> T:
    """Pick one. `choices` are (label, value) pairs."""
    if not _interactive():
        values = [str(v) for _, v in choices]
        picked = Prompt.ask(message, choices=values,
                            default=str(default) if default is not None else None)
        return next(v for _, v in choices if str(v) == picked)
    items = [Choice(title=label, value=value) for label, value in choices]
    start = next((c for c in items if c.value == default), None)
    return _ask(questionary.select(message, choices=items, default=start, style=STYLE,
                                   instruction="(↑/↓, Enter)"))


def checkbox(message: str, choices: Sequence[tuple[str, T]],
             checked: Sequence[T] = ()) -> list[T]:
    """Pick any number. `checked` values start ticked."""
    if not _interactive():
        values = [str(v) for _, v in choices]
        raw = Prompt.ask(f"{message} - comma-separated from {values}", default="")
        picked = {p.strip() for p in raw.split(",") if p.strip()}
        return [v for _, v in choices if str(v) in picked]
    items = [Choice(title=label, value=value, checked=value in checked) for label, value in choices]
    return _ask(questionary.checkbox(message, choices=items, style=STYLE,
                                     instruction="(↑/↓, Space to tick, Enter when done)"))


def confirm(message: str, default: bool = True) -> bool:
    if not _interactive():
        return Confirm.ask(message, default=default)
    return _ask(questionary.confirm(message, default=default, style=STYLE))


def text(message: str, default: str = "", required: bool = False) -> str:
    if not _interactive():
        while True:
            answer = Prompt.ask(message, default=default).strip()
            if answer or not required:
                return answer
    validate = (lambda s: bool(s.strip()) or "Required") if required else None
    return _ask(questionary.text(message, default=default, style=STYLE,
                                 validate=validate)).strip()


def path(message: str, default: str = "") -> str:
    """Text input with Tab-completion of file paths."""
    if not _interactive():
        return Prompt.ask(message, default=default).strip()
    return _ask(questionary.path(message, default=default, style=STYLE)).strip()


def password(message: str) -> str:
    """Hidden input, for API keys (keeps them out of shell history and the screen)."""
    if not _interactive():
        import getpass

        return getpass.getpass(f"{message}: ").strip()
    return _ask(questionary.password(message, style=STYLE)).strip()
