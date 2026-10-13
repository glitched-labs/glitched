# Security policy

Glitched is used to test robots, so problems in it can matter. Thank you for reporting
them responsibly.

## Reporting a vulnerability

Please **don't open a public issue.** Use GitHub's private reporting instead: the
repository's **Security** tab → **Report a vulnerability**. Include what you found, how
to reproduce it, and what an attacker could do with it.

You'll get an acknowledgement within a few working days. We'll keep you updated while
it's fixed, and credit you in the release notes if you'd like.

## What's in scope

- The `glitched` CLI and the local scan UI (`glitched ui`):
  for example, the UI being reachable from another machine or another website, a scan
  reaching a host it shouldn't, or the guardrails being bypassed.
- The runner (`glitched-runner`): anything that lets a console - or anyone else - make
  it probe beyond its local policy, run something it shouldn't, or tamper with its
  audit log.

Vulnerabilities in the robots you test with Glitched should go to their vendors.
