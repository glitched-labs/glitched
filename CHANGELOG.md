# Changelog

All notable changes to Glitched. Versions follow [semantic versioning](https://semver.org/);
while the major version is 0, minor versions may include breaking changes.

## [0.2.0] - unreleased

The first open-source release, under the Apache License 2.0.

The threat-intel pipelines (extract, load, dbt transform, snapshots) are not part of this package: they live in
the private glitched-pipelines package. Without it the CLI reads an existing database (`DATABASE_URL`); `setup`,
`snapshot` and `exposure --refresh` need it and say so.

### Added
- The command line: `onboard`, `exposure`, SBOM and package-list import, connect-only
  `profile detect`, assessments (`create`, `plan`, `run`, `approve`, `report`, `posture`),
  registered devices with `autoscan`, and findings tracked across scans.
- `glitched ui`: the same on `127.0.0.1`, with robot pictures and findings pinned to parts.
- `glitched-runner`: the dependency-free on-site runner for a Glitched console, with a local
  deny-by-default policy and a hash-chained audit log.
- The docs site (`python -m glitched.docsite`), the CLI guide and a generated command
  reference that CI keeps current.
- CONTRIBUTING.md and SECURITY.md (private vulnerability reporting).
