# Contributing to Glitched

Thanks for helping. Glitched is security tooling that people point at real robots, so
the bar is: **safe by default, explained in plain words, and tested.**

## Set up

```bash
git clone https://github.com/glitched-labs/glitched && cd glitched
uv venv && uv pip install -e ".[charts,docs]"
uvx ruff check src tests
python -m unittest discover -s tests -t .
```

Database tests run when `GLITCHED_TEST_DATABASE_URL` points at a PostgreSQL server (see
the README's "Tests"). `glitched setup` against a local PostgreSQL gives you the threat data.

## What a good change looks like

- **Safety first.** Scans stay passive and connect-only, against one host, after the
  authorized-use notice. Anything that sends crafted input or changes a device is
  listed for a person to do, never automated. A change that weakens a guardrail needs
  a strong reason in its description.
- **The runner stays dependency-free** (standard library only) and keeps its local
  deny-by-default policy. It never trusts what it's sent.
- **Plain words.** Messages and docs say what happened and what to do next, for someone
  who isn't a security specialist.
- **Tests** for new behaviour, and `ruff` clean.
- **Docs.** If you change the CLI, run `python -m glitched.cli_docs` to regenerate
  [the reference](docs/cli-reference.md) (CI checks it's current). Preview the docs site
  with `python -m glitched.docsite serve`.

## Pull requests

Keep them focused. Describe the problem, what you changed, and how you checked it. By
contributing, you agree that your contribution is licensed under the Apache License 2.0,
the project's licence.

## Reporting security problems

Not in an issue, please - see [SECURITY.md](SECURITY.md).
