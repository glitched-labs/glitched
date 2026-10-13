# CLI reference

Every `glitched` command and option. For what to use when, with examples, see
[the command line guide](cli.md).

<!-- BEGIN GENERATED: CLI REFERENCE (python -m glitched.cli_docs) -->

Generated from the CLI itself - `glitched <command> --help` says the same.

- [`glitched setup`](#glitched-setup) - build the threat-intel database (needs glitched-pipelines; re-run to refresh)
- [`glitched snapshot`](#glitched-snapshot) - export or import a threat-intel snapshot (needs glitched-pipelines)
  - [`glitched snapshot export`](#glitched-snapshot-export) - write the raw threat intel (ATLAS, EMB3D, NVD) to a .zip
  - [`glitched snapshot import`](#glitched-snapshot-import) - load a snapshot's raw tables (use `setup --snapshot` to also build)
- [`glitched doctor`](#glitched-doctor) - check the install; exit 1 if something is broken
- [`glitched debug-bundle`](#glitched-debug-bundle) - write a .zip of versions, checks and settings (no device data) to attach to a bug report
- [`glitched acknowledge`](#glitched-acknowledge) - read and accept the authorized-use notice (needed once before scanning)
- [`glitched config`](#glitched-config) - show or change settings (database, API keys, ...)
  - [`glitched config show`](#glitched-config-show) - every setting, its value (secrets hidden) and where it came from
  - [`glitched config set`](#glitched-config-set) - save a setting to the config file; omit VALUE to be prompted (hidden for keys)
  - [`glitched config unset`](#glitched-config-unset) - remove a setting from the config file
  - [`glitched config path`](#glitched-config-path) - print the config file's location
- [`glitched properties`](#glitched-properties) - list EMB3D device properties
- [`glitched onboard`](#glitched-onboard) - describe your device (questions, SBOM, scan) and see which vulns affect it
- [`glitched exposure`](#glitched-exposure) - what affects your profiled device; flags new items
- [`glitched profile`](#glitched-profile) - add to a device profile from an SBOM or a scan
  - [`glitched profile import-sbom`](#glitched-profile-import-sbom) - merge an SBOM (CycloneDX/SPDX JSON) or a package list (dpkg-query -W, dpkg -l, pip freeze, ros2 pkg list) into the profile
  - [`glitched profile detect`](#glitched-profile-detect) - suggest additions from a connect-only scan of one host
- [`glitched create`](#glitched-create) - create an assessment (prompts interactively for anything not passed as a flag)
- [`glitched scan`](#glitched-scan) - one-shot: create + plan + run, styled summary table (prompts interactively for anything not passed as a flag)
- [`glitched device`](#glitched-device) - register devices for automatic re-scanning
  - [`glitched device add`](#glitched-device-add) - register (or update) a device you own or are authorized to test
  - [`glitched device list`](#glitched-device-list) - registered devices and their latest results
  - [`glitched device plan`](#glitched-device-plan) - show exactly what scanning a device would send (sends nothing)
  - [`glitched device remove`](#glitched-device-remove) - stop tracking a device (past scans are kept)
  - [`glitched device pause`](#glitched-device-pause) - skip a device in autoscan
  - [`glitched device resume`](#glitched-device-resume) - include a paused device again
- [`glitched findings`](#glitched-findings) - a registered device's findings, across scans
  - [`glitched findings list`](#glitched-findings-list) - bring a device's findings up to date and list them
  - [`glitched findings recheck`](#glitched-findings-recheck) - re-run only the check behind an observed finding
  - [`glitched findings set`](#glitched-findings-set) - change a finding's status
- [`glitched ui`](#glitched-ui) - open the robot scan UI in your browser (runs on this computer only)
- [`glitched autoscan`](#glitched-autoscan) - re-scan every registered device that's due; exit code 1 if a new issue was confirmed
- [`glitched plan`](#glitched-plan) - select applicable threats -> planned findings (prompts for assessment id if omitted)
- [`glitched run`](#glitched-run) - run passive checks; gate active steps (prompts for assessment id if omitted)
- [`glitched approve`](#glitched-approve) - record an operator-executed active step (prompts interactively for anything not passed as a flag)
- [`glitched report`](#glitched-report) - summarise findings and evidence (prompts for assessment id if omitted)
- [`glitched posture`](#glitched-posture) - roll findings up into a security-posture summary (prompts for assessment id if omitted)

## Global options

Every command also takes these:

| Option | What it does |
|---|---|
| `--database-url` `DATABASE_URL` | PostgreSQL to use (default: the DATABASE_URL setting - see `glitched config show`) |
| `-v`, `--verbose` | show debug logging |
| `--version` | show program's version number and exit |

## `glitched setup`

Build the threat-intel database (needs glitched-pipelines; re-run to refresh).

```
glitched setup [--skip-nvd] [--papers] [--classify-limit CLASSIFY_LIMIT] [--snapshot FILE] [--refresh]
```

| Argument | What it does |
|---|---|
| `--skip-nvd` | skip NVD (it takes about a minute without an API key) |
| `--papers` | also load research papers (classification needs the [papers] extra and ANTHROPIC_API_KEY) |
| `--classify-limit` `CLASSIFY_LIMIT` | classify at most this many new papers |
| `--snapshot` `FILE` | start from a snapshot (glitched snapshot export) instead of downloading |
| `--refresh` | with --snapshot: also fetch anything newer |

## `glitched snapshot`

Export or import a threat-intel snapshot (needs glitched-pipelines).

### `glitched snapshot export`

Write the raw threat intel (ATLAS, EMB3D, NVD) to a .zip.

```
glitched snapshot export [--include {research,papers}] path
```

| Argument | What it does |
|---|---|
| `PATH` | the .zip to write |
| `--include` `INCLUDE` | also include your curated CVE notes and/or research papers (repeatable) - one of `research`, `papers` |

### `glitched snapshot import`

Load a snapshot's raw tables (use `setup --snapshot` to also build).

```
glitched snapshot import path
```

| Argument | What it does |
|---|---|
| `PATH` | the .zip to load (from `glitched snapshot export`) |

## `glitched doctor`

Check the install; exit 1 if something is broken.

```
glitched doctor
```

## `glitched debug-bundle`

Write a .zip of versions, checks and settings (no device data) to attach to a bug report.

```
glitched debug-bundle [--output OUTPUT]
```

| Argument | What it does |
|---|---|
| `--output` `OUTPUT` | file to write (default glitched-debug-<time>.zip) |

## `glitched acknowledge`

Read and accept the authorized-use notice (needed once before scanning).

```
glitched acknowledge
```

## `glitched config`

Show or change settings (database, API keys, ...).

### `glitched config show`

Every setting, its value (secrets hidden) and where it came from.

```
glitched config show
```

### `glitched config set`

Save a setting to the config file; omit VALUE to be prompted (hidden for keys).

```
glitched config set key [value]
```

| Argument | What it does |
|---|---|
| `KEY` | the setting, e.g. nvd_api_key (see `glitched config show`) |
| `VALUE` | optional. its value; omit to be prompted |

### `glitched config unset`

Remove a setting from the config file.

```
glitched config unset key
```

| Argument | What it does |
|---|---|
| `KEY` | the setting, e.g. nvd_api_key (see `glitched config show`) |

### `glitched config path`

Print the config file's location.

```
glitched config path
```

## `glitched properties`

List EMB3D device properties.

```
glitched properties
```

## `glitched onboard`

Describe your device (questions, SBOM, scan) and see which vulns affect it.

```
glitched onboard [--profile PROFILE] [--name NAME] [--host HOST] [--authorization AUTHORIZATION] [--limit LIMIT] [--related] [--allow-public]
```

| Argument | What it does |
|---|---|
| `--profile` `PROFILE` | device profile file (default: glitch.yaml) |
| `--name` `NAME` | device name; omit to be prompted |
| `--host` `HOST` | for optional scan-detect; omit to be prompted |
| `--authorization` `AUTHORIZATION` | for optional scan-detect; omit to be prompted |
| `--limit` `LIMIT` | max rows to show (0 = all) (default `25`) |
| `--related` | also list CVEs in other products that share an interface (wifi, mqtt, ...) |
| `--allow-public` | allow a public (non-private) address; you must be authorized to test it |

## `glitched exposure`

What affects your profiled device; flags new items.

```
glitched exposure [--profile PROFILE] [--refresh] [--limit LIMIT] [--related]
```

| Argument | What it does |
|---|---|
| `--profile` `PROFILE` | device profile file (default: glitch.yaml) |
| `--refresh` | re-run the threat-intel loaders first |
| `--limit` `LIMIT` | max rows to show (0 = all) (default `25`) |
| `--related` | also list CVEs in other products that share an interface (wifi, mqtt, ...) |

## `glitched profile`

Add to a device profile from an SBOM or a scan.

### `glitched profile import-sbom`

Merge an SBOM (CycloneDX/SPDX JSON) or a package list (dpkg-query -W, dpkg -l, pip freeze, ros2 pkg list) into the profile.

```
glitched profile import-sbom [--profile PROFILE] [--name NAME] sbom
```

| Argument | What it does |
|---|---|
| `SBOM` | the SBOM or package-list file |
| `--profile` `PROFILE` | device profile file (default: glitch.yaml) |
| `--name` `NAME` | device name if creating a new profile |

### `glitched profile detect`

Suggest additions from a connect-only scan of one host.

```
glitched profile detect [--host HOST] [--authorization AUTHORIZATION] [--profile PROFILE] [--name NAME] [--allow-public]
```

| Argument | What it does |
|---|---|
| `--host` `HOST` | isolated lab host; omit to be prompted |
| `--authorization` `AUTHORIZATION` | omit to be prompted |
| `--profile` `PROFILE` | device profile file (default: glitch.yaml) |
| `--name` `NAME` | device name if creating a new profile |
| `--allow-public` | allow a public (non-private) address; you must be authorized to test it |

## `glitched create`

Create an assessment (prompts interactively for anything not passed as a flag).

```
glitched create [--target-name TARGET_NAME] [--host HOST] [--authorization AUTHORIZATION] [--properties PROPERTIES] [--allow-public]
```

| Argument | What it does |
|---|---|
| `--target-name` `TARGET_NAME` | omit to be prompted |
| `--host` `HOST` | target IP/hostname (isolated lab only); omit to be prompted |
| `--authorization` `AUTHORIZATION` | attestation that you own or are authorized to test this device; omit to be prompted |
| `--properties` `PROPERTIES` | comma-separated EMB3D property ids (PID-...) |
| `--allow-public` | allow a public (non-private) address; you must be authorized to test it |

## `glitched scan`

One-shot: create + plan + run, styled summary table (prompts interactively for anything not passed as a flag).

```
glitched scan [--target-name TARGET_NAME] [--host HOST] [--authorization AUTHORIZATION] [--properties PROPERTIES] [--profile PROFILE] [--allow-public]
```

| Argument | What it does |
|---|---|
| `--target-name` `TARGET_NAME` | omit to be prompted |
| `--host` `HOST` | target IP/hostname (isolated lab only); omit to be prompted |
| `--authorization` `AUTHORIZATION` | attestation that you own or are authorized to test this device; omit to be prompted |
| `--properties` `PROPERTIES` | comma-separated EMB3D property ids; omit for an interactive choice |
| `--profile` `PROFILE` | glitch.yaml - scope the scan to the threats this device profile exposes |
| `--allow-public` | allow a public (non-private) address; you must be authorized to test it |

## `glitched device`

Register devices for automatic re-scanning.

### `glitched device add`

Register (or update) a device you own or are authorized to test.

```
glitched device add [--name NAME] [--host HOST] [--authorization AUTHORIZATION] [--profile PROFILE] [--every EVERY] [--allow-public]
```

| Argument | What it does |
|---|---|
| `--name` `NAME` | omit to be prompted |
| `--host` `HOST` | one IP/hostname on an isolated lab network; omit to be prompted |
| `--authorization` `AUTHORIZATION` | Authorization attestation (confirm you own or are authorized to test this device); omit to be prompted |
| `--profile` `PROFILE` | glitch.yaml - scope scans to this device profile |
| `--every` `EVERY` | hours between scans (default 24) |
| `--allow-public` | allow a public (non-private) address; you must be authorized to test it |

### `glitched device list`

Registered devices and their latest results.

```
glitched device list
```

### `glitched device plan`

Show exactly what scanning a device would send (sends nothing).

```
glitched device plan name
```

| Argument | What it does |
|---|---|
| `NAME` | the device's name (see `glitched device list`) |

### `glitched device remove`

Stop tracking a device (past scans are kept).

```
glitched device remove name
```

| Argument | What it does |
|---|---|
| `NAME` | the device's name (see `glitched device list`) |

### `glitched device pause`

Skip a device in autoscan.

```
glitched device pause name
```

| Argument | What it does |
|---|---|
| `NAME` | the device's name (see `glitched device list`) |

### `glitched device resume`

Include a paused device again.

```
glitched device resume name
```

| Argument | What it does |
|---|---|
| `NAME` | the device's name (see `glitched device list`) |

## `glitched findings`

A registered device's findings, across scans.

### `glitched findings list`

Bring a device's findings up to date and list them.

```
glitched findings list [--all] [--limit LIMIT] [device]
```

| Argument | What it does |
|---|---|
| `DEVICE` | optional. device name (optional if there's only one) |
| `--all` | include resolved, accepted and not-applicable findings |
| `--limit` `LIMIT` | max rows to show (0 = all) (default `25`) |

### `glitched findings recheck`

Re-run only the check behind an observed finding.

```
glitched findings recheck finding_id
```

| Argument | What it does |
|---|---|
| `FINDING_ID` | the finding's id (see `glitched findings list`) |

### `glitched findings set`

Change a finding's status.

```
glitched findings set [--note NOTE] [--days DAYS] finding_id {open,fix_applied,accepted_risk,not_applicable}
```

| Argument | What it does |
|---|---|
| `FINDING_ID` | the finding's id (see `glitched findings list`) |
| `STATUS` | one of `open`, `fix_applied`, `accepted_risk`, `not_applicable` |
| `--note` `NOTE` | why (required for accepted_risk) |
| `--days` `DAYS` | accepted_risk: ask again after this many days (90) |

## `glitched ui`

Open the robot scan UI in your browser (runs on this computer only).

```
glitched ui [--port PORT] [--no-browser]
```

| Argument | What it does |
|---|---|
| `--port` `PORT` | port on 127.0.0.1 (default: any free port) |
| `--no-browser` | print the link instead of opening a browser |

## `glitched autoscan`

Re-scan every registered device that's due; exit code 1 if a new issue was confirmed.

```
glitched autoscan [--device DEVICE] [--force]
```

| Argument | What it does |
|---|---|
| `--device` `DEVICE` | scan only this device now (repeatable) |
| `--force` | scan every enabled device now, due or not |

## `glitched plan`

Select applicable threats -> planned findings (prompts for assessment id if omitted).

```
glitched plan [--all] [assessment_id]
```

| Argument | What it does |
|---|---|
| `ASSESSMENT_ID` | optional. the assessment's id; omit to be asked |
| `--all` | plan every EMB3D threat, not just ones tied to declared properties |

## `glitched run`

Run passive checks; gate active steps (prompts for assessment id if omitted).

```
glitched run [assessment_id]
```

| Argument | What it does |
|---|---|
| `ASSESSMENT_ID` | optional. the assessment's id; omit to be asked |

## `glitched approve`

Record an operator-executed active step (prompts interactively for anything not passed as a flag).

```
glitched approve [--status STATUS] [--detail DETAIL] [--evidence EVIDENCE] [finding_id]
```

| Argument | What it does |
|---|---|
| `FINDING_ID` | optional. the finding's id; omit to be asked |
| `--status` `STATUS` | one of ['awaiting_approval', 'confirmed', 'inconclusive', 'not_present', 'planned', 'skipped'] |
| `--detail` `DETAIL` | what you did and saw, in a sentence or two |
| `--evidence` `EVIDENCE` | evidence text or path to an artifact file |

## `glitched report`

Summarise findings and evidence (prompts for assessment id if omitted).

```
glitched report [assessment_id]
```

| Argument | What it does |
|---|---|
| `ASSESSMENT_ID` | optional. the assessment's id; omit to be asked |

## `glitched posture`

Roll findings up into a security-posture summary (prompts for assessment id if omitted).

```
glitched posture [assessment_id]
```

| Argument | What it does |
|---|---|
| `ASSESSMENT_ID` | optional. the assessment's id; omit to be asked |

<!-- END GENERATED: CLI REFERENCE -->
