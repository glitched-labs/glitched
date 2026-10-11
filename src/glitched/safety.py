"""
Guardrails that hold no matter how Glitched is run.

  Acknowledgement   Before Glitched sends anything to a device, the user
                    accepts a one-time authorized-use notice (stored in the
                    config file as `acknowledged`). Unattended runs, such as
                    `autoscan` from cron, never prompt: they refuse until it's
                    been accepted.

  Private targets   A target that resolves to a public address (anything but
                    private, loopback or link-local) needs explicit approval:
                    a confirmation prompt, or --allow-public in scripts. The
                    approval is stored with the assessment or device, and the
                    check runner verifies it again right before probing - so a
                    hostname that later resolves somewhere public is caught too.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from glitched import config, targets, ui
from glitched.targets import Target, is_public  # noqa: F401 - re-exported

console = Console()

# Bump when the notice's substance changes; everyone re-accepts once.
NOTICE_VERSION = "1"

NOTICE = """\
Glitched connects to the devices you point it at: it opens network
connections to common service ports, attempts TLS handshakes and sends plain
HTTP GET requests (see "What a scan sends" in the README).

Only use it on devices you own, or are explicitly authorized in writing to
test, on a network you control - ideally an isolated lab network. Scanning
other people's devices or networks can be illegal and can disrupt them.

Active steps (anything that sends crafted input or changes a device) are
never run by Glitched itself; they are listed for you to perform and record."""


def is_acknowledged() -> bool:
    return config.get("acknowledged") == NOTICE_VERSION


def require_acknowledgement() -> None:
    """Ask once (interactive), or refuse (unattended) until the notice is accepted."""
    if is_acknowledged():
        return
    if not ui.interactive():
        raise SystemExit("Glitched needs a one-time acknowledgement before it contacts any device. "
                         "Run `glitched acknowledge` in a terminal first.")
    acknowledge()


def acknowledge() -> None:
    console.print(Panel(NOTICE, title="Before you scan", border_style="yellow"))
    if not ui.confirm("I will only scan devices I own or am authorized to test", default=False):
        raise SystemExit("Not acknowledged - nothing was scanned.")
    record_acknowledgement()
    console.print("[green]✓[/green] Acknowledged. You won't be asked again.")


def record_acknowledgement() -> None:
    """Store that the current notice was accepted (by the prompt above or the web UI's checkbox)."""
    config.set_value("acknowledged", NOTICE_VERSION)


def resolve(host: str) -> Target:
    try:
        return targets.resolve(host)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def approve_target(host: str, allow_public: bool) -> bool:
    """
    Check a target before it's stored or probed. Returns whether it's an
    approved public address (to store with the assessment or device). Raises
    SystemExit if it's public and not approved.
    """
    target = resolve(host)
    if not target.public:
        return False
    where = f"{host} ({', '.join(target.addresses)})" if target.addresses != (host,) else host
    if allow_public:
        console.print(f"[yellow]![/yellow] {where} is a public address - scanning it because --allow-public was given.")
        return True
    if ui.interactive():
        console.print(f"[yellow]![/yellow] {where} is a [bold]public[/bold] address, not a private or lab network.")
        if ui.confirm("Are you authorized to scan this public address?", default=False):
            return True
        raise SystemExit("Not scanning a public address without authorization.")
    raise SystemExit(f"{where} is a public address. Glitched only scans public addresses with explicit "
                     "approval: re-run with --allow-public if you're authorized to test it.")


def assert_scannable(host: str, approved_public: bool) -> None:
    """Last check right before probing: a public address must have been approved."""
    target = resolve(host)
    if target.public and not approved_public:
        raise SystemExit(f"{host} now resolves to a public address ({', '.join(target.addresses)}), "
                         "which wasn't approved - not scanning it.")
