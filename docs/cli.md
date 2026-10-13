# The `glitched` command line

`glitched` checks robots and IoT devices you own, or are authorized to test, against
a local threat database built from MITRE EMB3D, MITRE ATLAS and NIST's NVD. It
answers "what affects my device?" from a description of it, and verifies that on a
lab device with passive, connect-only checks. It also keeps each device's findings
from first seen to fixed.

Run `glitched` with no command for an interactive menu, or `glitched <command> --help`
for any command. The [command reference](cli-reference.md) lists every one.

## Install and first run

```bash
uv tool install "git+https://github.com/glitched-labs/glitched"   # or: pipx install "git+https://..."
glitched setup                           # build the threat-intel database (needs glitched-pipelines)
glitched doctor                          # check everything; prints a fix for anything broken
glitched acknowledge                     # accept the authorized-use notice (once, before scanning)
```

You need a PostgreSQL database that holds the threat intel. By default it's
`postgresql://localhost:5432/glitched`; see [Settings](#settings) to change that. The data is built by
the private `glitched-pipelines` package: with it installed, `glitched setup` creates and refreshes the
database (and `glitched setup --snapshot intel.zip` starts from a snapshot). Without it, point
`database_url` at a database someone else built; every other command works the same.

## What affects my device?

Describe the device once, in plain terms. You don't need to know any CVE or EMB3D IDs:

```bash
glitched onboard          # ~15 yes/no questions -> writes glitch.yaml
glitched exposure         # the vulnerabilities that apply, ranked, each with why; anything new is flagged NEW
```

Add detail whenever you have it. Merging never removes anything:

```bash
glitched profile import-sbom sbom.json      # CycloneDX or SPDX JSON
dpkg-query -W > packages.txt && glitched profile import-sbom packages.txt   # no SBOM? a package list works
glitched profile detect --host 192.168.50.20 # connect-only port scan; you confirm each suggestion
glitched exposure --refresh                  # pull the latest threat intel first
```

`glitch.yaml` is plain YAML. Write it by hand if you like, and check it into the robot's repository:

```yaml
name: warehouse-amr-v3
platforms: [ros, unitree]          # ros, universal-robots, unitree, lerobot
ros_distro: humble                 # for ROS robots: decides which ROS CVEs apply
interfaces: [wifi, bluetooth, mqtt]
ml: true                           # also match MITRE ATLAS ML techniques
properties: [PID-41, PID-275]      # EMB3D ids; onboard fills these in
```

## Check a lab device

```bash
glitched scan --profile glitch.yaml --host 192.168.50.20 --authorization "self-owned lab device"
```

`scan` creates an assessment, plans the threats your profile exposes, runs the
**passive** checks and prints a summary. To go step by step:

```bash
glitched create --target-name arm-02 --host 192.168.50.20 --authorization "self-owned lab device"
glitched plan 7               # one planned finding per threat (--all: the whole EMB3D catalogue)
glitched run 7                # passive checks run; active steps wait for you
glitched approve 31 --status confirmed --detail "Telnet accepted the default login" --evidence telnet.txt
glitched report 7             # findings, each tied to its threat and evidence
glitched posture 7            # roll it up into a posture grade
```

Run `glitched device plan <name>` first to see exactly what a scan would send to a
registered device (it sends nothing). The guardrails:

- **One host at a time.** Ranges, lists and CIDR blocks are refused.
- **Private addresses only**, unless you confirm a public one (or pass `--allow-public`).
  That approval is re-checked right before probing.
- **Automated checks are passive.** They make TCP connects, read greetings, attempt TLS
  handshakes, and send one unauthenticated `GET /`. Anything active is listed for you to
  do yourself and record with `glitched approve`; Glitched never runs it.

[Safety](safety.md) lists every packet a scan sends.

## Scan on a schedule

Register a device once; `autoscan` re-scans whatever is due and reports what changed:

```bash
glitched device add --name arm-02 --host 192.168.50.20 \
  --authorization "self-owned lab device" --profile glitch.yaml --every 24
glitched device list
glitched autoscan                      # scan whatever is due
```

```cron
0 * * * * /path/to/glitched autoscan >> ~/glitched-autoscan.log 2>&1
```

Running it every hour is cheap, since devices are only scanned when they're due.
Overlapping runs are safe, and unattended runs never prompt.

## Work through findings

Each registered device keeps one list of findings across scans:

```bash
glitched findings list arm-02                       # open findings, most urgent first (--all: closed too)
glitched findings set 12 fix_applied                 # the next scan confirms it, or reopens it
glitched findings set 14 accepted_risk --note "isolated lab network" --days 30
glitched findings recheck 12                         # re-run just the check behind it, now
```

Every finding says how it's known: **observed** (a scan saw it), **declared** (your
profile says so), **known vuln** (a CVE matched by platform, or by SBOM component and
version) or **possible** (fits the profile, not tested). Accepted risks need a reason,
and they come back when their time is up.

Prefer a browser? `glitched ui` opens the same data and actions on `127.0.0.1` only.

## Exit codes

Scripts and schedulers can rely on these:

| Command | `0` | `1` |
|---|---|---|
| `glitched doctor` | all checks pass | something is broken (each has a fix printed) |
| `glitched autoscan` | no new confirmed issue | a scan confirmed an issue that wasn't there last time |

Other commands exit non-zero with a one-line explanation when something goes wrong
(for example, the database isn't set up yet, or there's no terminal to ask a question in).

## Settings

Each setting is read from, in order: the environment variable, a `.env` file in the
current folder (or a parent folder), then the config file (`glitched config path`).

| Setting | Environment variable | What |
|---|---|---|
| `database_url` | `DATABASE_URL` | PostgreSQL connection string (default `postgresql://localhost:5432/glitched`) |
| `nvd_api_key` | `NVD_API_KEY` | NVD API key: optional, makes NVD loads about 10x faster |
| `anthropic_api_key` | `ANTHROPIC_API_KEY` | optional: classifies research papers (`setup --papers`, glitched-pipelines) |
| `dbt_command` | `DBT_COMMAND` | how to run dbt (default: dbt-core + dbt-postgres via uvx) |

```bash
glitched config show                 # every setting, where its value came from (secrets hidden)
glitched config set nvd_api_key      # prompts, hidden; stored readable only by you
```

## Share threat intel offline

These two commands need the private `glitched-pipelines` package.

```bash
glitched snapshot export intel.zip            # raw EMB3D, ATLAS and NVD tables
glitched setup --snapshot intel.zip --refresh # on another machine: load it, then fetch anything newer
```

## The runner

`glitched-runner` is a separate, dependency-free program for scanning robots from inside
their own network on behalf of a Glitched console. It only connects *out*, and it only
probes the hosts and ports its local policy file allows. The console can't change that
policy. See [`src/glitched/runner`](../src/glitched/runner) and `glitched-runner --help`.
