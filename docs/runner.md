# The on-site runner

The runner is for teams that use a **Glitched console** (a hosted web app for a team
and a fleet, available separately). It scans robots from inside their own network
on the console's behalf. It's open source, here, so you can read exactly what it can
and can't do before you run it on your network.


Each company runs `glitched-runner` on a machine that can reach its robots.
It uses only the Python standard library (`Dockerfile.runner` installs
nothing else), runs as a non-root user, and listens on no port. It only
connects out to the console, so no firewall changes are needed.

```bash
glitched-runner pair --console https://console.example.com --code ABCDE-FGHJK   # code from the Runners page
glitched-runner policy template > policy.toml    # then list your robots' networks or addresses
glitched-runner policy check arm02.lab           # would it be allowed? (resolves; sends nothing to it)
glitched-runner run                              # take jobs
glitched-runner pause "maintenance" / resume     # stop taking jobs, from site
glitched-runner audit --verify                   # check the local log hasn't been altered
```

**The runner decides, not the console.** Assume the console could be
compromised; it still can't use a runner to probe anything else on your
network:
- **The local policy denies everything by default.** It lives in
  `policy.toml` on your machine, mounted read-only in the container. The
  console only sees a summary: counts and a digest, never your addresses.
- **Each robot's name is resolved once.** Every address it resolves to must be
  allowed and not denied, and the probes connect only to that pinned address.
  Public addresses are refused unless the policy sets `allow_public = true`.
- **Jobs come from a short fixed list:** address check, service detection,
  and (soon) scan and recheck. Each names one host and never carries ports,
  URLs, payloads or code.
- **Jobs expire, and a job is never run twice.**
- **There's an hourly limit** set in the policy.
- **A pause switch on site** stops the runner taking jobs.
- **Everything the runner does or refuses is logged locally,** in a
  hash-chained audit log that is also printed to `docker logs`.
- **The runner never follows redirects,** and accepts plain HTTP only with
  `--allow-http`, which is for development.

For local testing, `dev/fake_robot.py` is a deliberately insecure fake robot and
`dev/runner-policy.toml` an example policy that allows only it.
