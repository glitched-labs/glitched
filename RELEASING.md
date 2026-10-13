# Releasing Glitched

## 1. Cut the release

```bash
git switch main && git pull
# 1. Set the version in src/glitched/__init__.py, e.g. __version__ = "0.2.0"
# 2. In CHANGELOG.md, change "[0.2.0] - unreleased" to today's date
python -m glitched.cli_docs --check      # the CLI reference is current
git commit -am "Release 0.2.0"
git tag -a v0.2.0 -m "Glitched 0.2.0"
git push origin main v0.2.0
```

Pushing the tag runs CI. When lint, tests, the Docker checks
and the secret scan pass, the **Release** job publishes a GitHub Release with the wheel and
generated notes. Then set the version to the next dev version (`0.2.1.dev0`) on `main`.

## 2. What people run

```bash
uv tool install "git+https://github.com/glitched-labs/glitched@v0.2.0"
glitched doctor        # with DATABASE_URL pointing at a database that has the threat intel
```

Upgrading: `uv tool install --reinstall "git+https://github.com/glitched-labs/glitched@v0.3.0"`.
Devices, scans, profiles and config are kept: the app's tables are only ever extended in
place. The threat-intel data and its snapshots are built and released from the private glitched-pipelines repo.

## 3. The console

The hosted Glitched console builds on this package from a pinned tag. After a release that
changes something the console uses (device profiles, the pipelines, the runner protocol,
the docs-site builder), bump its pin and run its tests.
