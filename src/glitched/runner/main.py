"""
glitched-runner: the on-site runner.

  glitched-runner pair --console https://console.example.com --code ABCDE-FGHJK
  glitched-runner run                      take jobs from the console (outbound long-poll)
  glitched-runner policy template          print a starting policy.toml
  glitched-runner policy check HOST        would this host be allowed? (resolves it; sends nothing to it)
  glitched-runner audit [--verify] [--tail N]
  glitched-runner pause [REASON] | resume  stop/start taking jobs, from this machine
  glitched-runner status

Settings: --state DIR (or GLITCHED_RUNNER_STATE) for the pairing, pause switch
and audit log; --policy FILE (or GLITCHED_RUNNER_POLICY, default
<state>/policy.toml) for the local policy.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import sys
import time
from pathlib import Path

import glitched
from glitched import targets
from glitched.runner import PROTOCOL, executor
from glitched.runner import policy as runner_policy
from glitched.runner.audit import AuditLog
from glitched.runner.client import Client, ConsoleError
from glitched.runner.state import Pairing, State, default_dir


def _paths(args: argparse.Namespace) -> tuple[State, Path, AuditLog]:
    state_dir = Path(args.state) if args.state else default_dir()
    policy_path = Path(args.policy or os.environ.get("GLITCHED_RUNNER_POLICY") or state_dir / "policy.toml")
    return State(state_dir), policy_path, AuditLog(state_dir / "audit.jsonl", echo=args.command == "run")


def _load_policy(path: Path) -> tuple[runner_policy.Policy | None, str]:
    try:
        return runner_policy.load(path), ""
    except runner_policy.PolicyError as exc:
        return None, str(exc)


def heartbeat(state: State, policy: runner_policy.Policy | None, policy_error: str) -> dict:
    return {"version": glitched.__version__, "protocol": PROTOCOL, "kinds": list(executor.KINDS),
            "paused": state.paused, "policy": policy.summary() if policy else {"error": policy_error},
            "platform": f"{platform.system()} {platform.machine()}"}


def cmd_pair(args: argparse.Namespace) -> None:
    state, policy_path, audit = _paths(args)
    if state.pairing() and not args.force:
        raise SystemExit("This runner is already paired. Use --force to pair it again (the old pairing is dropped).")
    try:
        client = Client(args.console, allow_http=args.allow_http)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    try:
        _, body = client.post("/runner/v1/pair", {"code": args.code.strip().upper(), "name": args.name,
                                                 "version": glitched.__version__, "protocol": PROTOCOL})
    except ConsoleError as exc:
        raise SystemExit(f"Pairing failed: {exc.message}") from None
    except OSError as exc:
        raise SystemExit(f"Couldn't reach the console at {client.console}: {exc}") from None
    state.save_pairing(Pairing(client.console, int(body["runner_id"]), body["token"], args.allow_http))
    audit.record("runner.paired", console=client.console, runner_id=body["runner_id"], org=body.get("org_name"))
    print(f"Paired with {client.console} as runner {body['runner_id']} for {body.get('org_name')}.")
    if not policy_path.exists():
        print(f"Next: write the policy at {policy_path} (glitched-runner policy template), then glitched-runner run.")


def cmd_run(args: argparse.Namespace) -> None:
    state, policy_path, audit = _paths(args)
    pairing = state.pairing()
    if pairing is None:
        raise SystemExit("This runner isn't paired yet: glitched-runner pair --console URL --code CODE")
    client = Client(pairing.console, pairing.token, allow_http=pairing.allow_http)
    stopping: list[bool] = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
    audit.record("runner.started", console=pairing.console, runner_id=pairing.runner_id, policy=str(policy_path))
    backoff = 1.0
    while not stopping:
        policy, policy_error = _load_policy(policy_path)  # re-read each round: edits take effect without a restart
        try:
            status, body = client.post("/runner/v1/jobs/next", heartbeat(state, policy, policy_error), timeout=40)
            backoff = 1.0
        except ConsoleError as exc:
            if exc.status == 401:
                audit.record("runner.revoked", console=pairing.console)
                raise SystemExit("The console no longer accepts this runner (revoked). Pair it again.") from None
            if exc.status == 426:
                raise SystemExit(f"The console needs a newer runner: {exc.message}") from None
            print(f"console error {exc.status}: {exc.message}", file=sys.stderr, flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue
        except OSError as exc:
            print(f"can't reach the console ({exc}); retrying in {backoff:.0f}s", file=sys.stderr, flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue
        job = body.get("job") if status == 200 else None
        if not job:
            if args.once:
                return
            continue
        outcome = executor.execute(job, policy, state, audit, policy_error)
        try:
            client.post(f"/runner/v1/jobs/{int(job['id'])}/result", outcome)
        except (ConsoleError, OSError) as exc:
            audit.record("job.report_failed", job=job.get("id"), error=str(exc))
        if args.once:
            return
    audit.record("runner.stopped")


def cmd_policy(args: argparse.Namespace) -> None:
    state, policy_path, _ = _paths(args)
    if args.policy_command == "template":
        print(runner_policy.TEMPLATE, end="")
        return
    policy, error = _load_policy(policy_path)
    if policy is None:
        raise SystemExit(error)
    if args.policy_command == "show":
        print(json.dumps({"path": str(policy_path), **policy.summary(),
                          "allow": sorted(map(str, policy.allow_networks)) + sorted(policy.allow_hosts),
                          "deny": sorted(map(str, policy.deny_networks)) + sorted(policy.deny_hosts)}, indent=2))
        return
    try:
        target = targets.resolve(targets.validate_single_host(args.host))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    verdict = policy.check(target)
    print(("ALLOWED  " if verdict.allowed else "REFUSED  ") + verdict.reason)
    raise SystemExit(0 if verdict.allowed else 1)


def cmd_audit(args: argparse.Namespace) -> None:
    _, _, audit = _paths(args)
    if args.verify:
        ok, message = audit.verify()
        print(("OK  " if ok else "BROKEN  ") + message)
        raise SystemExit(0 if ok else 1)
    for entry in audit.entries()[-args.tail:]:
        print(f"{entry['seq']:>6}  {entry['at']}  {entry['event']:<18} {json.dumps(entry['detail'], sort_keys=True)}")


def cmd_pause(args: argparse.Namespace) -> None:
    state, _, audit = _paths(args)
    state.pause(args.reason)
    audit.record("runner.paused", reason=args.reason)
    print("Paused: jobs from the console are refused until glitched-runner resume.")


def cmd_resume(args: argparse.Namespace) -> None:
    state, _, audit = _paths(args)
    state.resume()
    audit.record("runner.resumed")
    print("Resumed.")


def cmd_status(args: argparse.Namespace) -> None:
    state, policy_path, audit = _paths(args)
    pairing = state.pairing()
    policy, error = _load_policy(policy_path)
    ok, chain = audit.verify()
    print(json.dumps({
        "version": glitched.__version__, "protocol": PROTOCOL, "state": str(state.dir),
        "paired": {"console": pairing.console, "runner_id": pairing.runner_id} if pairing else None,
        "paused": state.paused, "policy": policy.summary() if policy else {"error": error},
        "audit": {"ok": ok, "detail": chain}, "jobs_last_hour": state.jobs_in_last_hour(),
    }, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glitched-runner", description=__doc__.split("\n\n")[0].strip(),
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"glitched-runner {glitched.__version__}")
    parser.add_argument("--state", default=None, help="state directory (pairing, pause switch, audit log)")
    parser.add_argument("--policy", default=None, help="policy file (default <state>/policy.toml)")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("pair", help="pair with a console using a one-time code from its Runners page")
    p.add_argument("--console", required=True)
    p.add_argument("--code", required=True)
    p.add_argument("--name", default=platform.node()[:60] or "runner")
    p.add_argument("--allow-http", action="store_true", help="accept a plain-HTTP console (local development only)")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_pair)
    p = sub.add_parser("run", help="take jobs from the console")
    p.add_argument("--once", action="store_true", help="one long-poll round, then exit")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("policy", help="the local policy")
    psub = p.add_subparsers(dest="policy_command", required=True)
    psub.add_parser("template")
    psub.add_parser("show")
    pp = psub.add_parser("check")
    pp.add_argument("host")
    p.set_defaults(func=cmd_policy)
    p = sub.add_parser("audit", help="the local audit log")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--tail", type=int, default=50)
    p.set_defaults(func=cmd_audit)
    p = sub.add_parser("pause", help="refuse jobs until resumed")
    p.add_argument("reason", nargs="?", default="")
    p.set_defaults(func=cmd_pause)
    sub.add_parser("resume").set_defaults(func=cmd_resume)
    sub.add_parser("status").set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
