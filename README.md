
# GLITCHED

Scan and analyse security risks in robotics & physical-AI systems from a CLI.

Glitched builds a local threat-intel data system from public sources, then runs
evidence-collecting assessments against a device you own to build up a security
posture over time.

> **New to Glitched?** Start with [TESTING.md](TESTING.md), a 15-minute guided first run.

## Install

Needs Python 3.11+, a running PostgreSQL, and [uv](https://docs.astral.sh/uv/)
(the data pipelines run dbt through it).

```bash
uv tool install /path/to/glitched            # or: pipx install /path/to/glitched
uv tool install "/path/to/glitched[papers]"  # + Claude classification of research papers
glitched setup                               # create the database, load all threat intel (~1 min)
glitched doctor                              # check everything; prints a fix for any problem
```

For development, from a checkout: `uv venv && uv pip install -e ".[papers,charts]"`.

Every command, with examples and exit codes: [docs/cli.md](docs/cli.md) (and the [full reference](docs/cli-reference.md)).

The docs are also a website: `python -m glitched.docsite serve` previews it at http://127.0.0.1:8001/docs/ while you edit (`docs/nav.toml` sets the pages and their order; it needs the `docs` extra).

Settings come from, in order: environment variables, a `.env` file in the
current folder (see `.env.example`), the config file
(`~/.config/glitched/config.toml`), then defaults. `glitched config show` lists
each setting and where its value came from (API keys are never printed):

```bash
glitched config show
glitched config set nvd_api_key          # prompts with hidden input
glitched config set database_url postgresql://localhost:5432/glitched
glitched config unset research_dir
```

| Setting | Env variable | Purpose |
|---|---|---|
| `database_url` | `DATABASE_URL` | PostgreSQL connection (default `postgresql://localhost:5432/glitched`) |
| `nvd_api_key` | `NVD_API_KEY` | optional; ~10x faster NVD loads |
| `anthropic_api_key` | `ANTHROPIC_API_KEY` | optional; research paper classification |
| `dbt_command` | `DBT_COMMAND` | optional; how to run dbt (default: via `uvx`) |
| `research_dir` | `GLITCHED_RESEARCH_DIR` | optional; folder of curated `CVE-*.md` notes |

Scan evidence and charts are written to `~/.local/share/glitched`
(`$GLITCHED_HOME`).

### Run with Docker

No Python, uv or PostgreSQL needed - just Docker. From a checkout:

```bash
docker compose run --rm glitched setup       # builds the image, starts PostgreSQL, loads threat intel
docker compose run --rm glitched doctor
docker compose run --rm glitched onboard     # glitch.yaml is saved in this folder
docker compose run --rm glitched scan --profile glitch.yaml --host 192.168.1.50
```

- The current folder is mounted at `/work`, so profiles, SBOMs and snapshot
  files go here (`setup --snapshot glitched-intel-v0.1.0.zip`).
- Everything else - the database, settings, the acknowledgement, scan
  evidence - lives in Docker volumes and survives restarts. `docker compose
  down -v` deletes it all.
- The database is only reachable from the glitched container. `NVD_API_KEY`
  and `ANTHROPIC_API_KEY` are passed through from your shell or a `.env` file
  next to `compose.yaml`.
- Scans from the container reach devices on your network as usual. To scan
  something running on this computer itself, use `--host host.docker.internal`
  (Docker Desktop).

## Onboard your robot: what affects me?

Describe your device once in plain terms (no CVE or EMB3D knowledge needed)
and get a ranked list of the vulnerabilities that apply to it, each with the
reason it applies. Run these after loading the threat
intel (next section).

```bash
glitched onboard          # 1. answer ~15 yes/no questions -> writes glitch.yaml
glitched exposure         # 2. re-check any time; anything new is flagged NEW
glitched scan --profile glitch.yaml --host <robot-ip> \
  --authorization "self-owned lab device"   # 3. verify on a lab device, scoped to your profile
```

Add detail to the profile at any time (merging never removes anything):

```bash
glitched profile import-sbom sbom.json      # CycloneDX or SPDX JSON
glitched profile detect --host <robot-ip>   # connect-only port scan; you confirm each suggestion
glitched exposure --refresh                 # re-pull MITRE + research CVEs first
```

`glitch.yaml` is plain YAML, so you can write it by hand or check it into your repo:

```yaml
name: warehouse-amr-v3
platforms: [ros, unitree]          # ros, universal-robots, unitree, lerobot
ros_distro: humble                 # for ROS robots: decides which ROS CVEs apply
interfaces: [wifi, bluetooth, mqtt]
ml: true                           # also match MITRE ATLAS ML techniques
properties: [PID-41, PID-275]      # EMB3D ids; the questionnaire fills these in
```

A CVE applies when it names a platform the device is built on, or when NVD lists
one of the SBOM's components as affected - and, if the SBOM gives a version,
that version is in NVD's affected range. ROS is an ecosystem rather than one
product, so for ROS robots set the distro (`ros_distro: humble` in `glitch.yaml`,
or the onboarding question): core ROS CVEs then apply by ROS generation and
distro, while CVEs about one package (nav2, MoveIt, ...) apply only when the SBOM
lists it (Debian names like `ros-humble-navigation2` are understood).

You don't need a formal SBOM: on the robot, run `dpkg-query -W` (or `dpkg -l`,
`pip freeze`, `ros2 pkg list`) and paste the output into **Robot details** in the
UI, or save it to a file and run `glitched profile import-sbom packages.txt`.
Debian versions are compared by their upstream part (`1:1.3.11-1jammy…` → 1.3.11). CVEs in
other products that merely share a keyword (Wi-Fi, MQTT, "ROS") are hidden;
`glitched exposure --related` lists them, each with why.

## Threat-intel data system

`glitched setup` loads every source into a local Postgres database and builds
the warehouse with dbt once at the end. Re-run it to refresh: every loader is
idempotent and only fetches what's new. Options: `--skip-nvd` (NVD takes about a
minute without an API key) and `--papers` (research papers; classification needs
the `[papers]` extra and `ANTHROPIC_API_KEY`).

**Start from a snapshot** instead of downloading everything: someone with a
loaded database exports one, and you set up from it in seconds.

```bash
glitched snapshot export intel.zip                 # ATLAS, EMB3D, NVD (~0.6 MB)
glitched setup --snapshot intel.zip                # import + build, no downloads
glitched setup --snapshot intel.zip --refresh      # ...then fetch anything newer
```

A snapshot holds only the raw data (every release, plus NVD's incremental
cursors); dbt rebuilds everything else on import, so it always matches your
version of Glitched. Your curated CVE notes and research papers are left out
unless you add `--include research` / `--include papers` (paper abstracts carry
their sites' terms; check before sharing).

Each source can also be loaded on its own (each runs its own dbt build):

```bash
python -m glitched.pipelines.mitre      # MITRE ATLAS   - AI/ML adversary tactics & techniques
python -m glitched.pipelines.emb3d      # MITRE EMB3D   - embedded-device threats, mitigations, properties
python -m glitched.pipelines.research   # research CVEs - curated robotics CVEs ($GLITCHED_RESEARCH_DIR)
python -m glitched.pipelines.nvd        # NVD CVEs      - CVEs mentioning ROS, Unitree, Universal Robots, LeRobot, MQTT, ...
python -m glitched.pipelines.papers     # papers        - robot / embodied-AI security research, classified by Claude
```

**NVD:**
- **What it searches:** NVD for each keyword marked `nvd_search` in `src/glitched/pipelines/transform/seeds/platform_keywords.csv`. Keep that list to specific platforms; a generic word like "firmware" matches thousands of CVEs.
- **What it keeps:** only CVEs where the keyword appears as a whole word, because NVD's own search also matches inside words ("ros" finds "roster").
- **Repeat runs** fetch only CVEs modified since the last one.
- **Speed:** without an API key a run takes about a minute (NVD allows 5 requests per 30 seconds). [Request a free key](https://nvd.nist.gov/developers/request-an-api-key) and set `NVD_API_KEY` in your environment or a `.env` file to go about 10x faster.

**Research papers:**
- **Sources:**
  - Hugging Face Papers searches; Papers with Code now redirects there. Edit `SEARCH_QUERIES` and `PINNED_PAPERS` in `src/glitched/pipelines/extract/research_papers.py`.
  - arXiv searches, scoped to the Robotics and Security categories plus attacks on vision-language-action models. Edit `ARXIV_QUERIES` in `src/glitched/pipelines/extract/arXiv.py`. Each run fetches only papers submitted since the last one. A new search starts with its 50 newest papers rather than the full backlog (thousands).
  - NVIDIA Research publications in the Security, Resilience and Safety, Robotics and Physical AI areas. From Robotics and Physical AI, only titles that mention a security term are kept. Edit `RESEARCH_AREAS` in `src/glitched/pipelines/extract/nvidia_research_papers.py`. Each publication page is fetched only once.
  - A paper found on several sites is one row, keyed by its arXiv id. NVIDIA papers with no arXiv id are keyed `nvidia:<slug>`.
- **What Claude extracts** (`src/glitched/pipelines/classify/papers.py`), in terms the assessment agent already uses:
  - whether the paper is really about robot or device security
  - which ATLAS techniques and EMB3D threats it covers, and which platforms it targets
  - concrete checks, each tagged `passive`, `active` or `manual_review` like the agent's own tests
- **Cost:** classification calls the Claude API (`ANTHROPIC_API_KEY`), about $0.03 per paper, and only new papers are classified. Try it cheaply first:

```bash
python -m glitched.pipelines.papers --classify-limit 5   # classify at most 5 new papers
python -m glitched.pipelines.papers --skip-classify      # fetch and load only
```

- **Results:** the exposure report includes relevant papers. In code, `queries.get_paper_checks(tags, property_ids, ml)` returns the checks that apply to a device, each citing its paper.

### How the pipelines work (ELT)

All four loaders run the same three steps, with each step in its own folder:

| Step | Code | What it does |
|---|---|---|
| Extract | `src/glitched/pipelines/extract/{emb3d,atlas,research,nvd_cve,research_papers}.py` | Reads the source and validates it against the Pydantic models in `src/glitched/pipelines/schemas/`. Upstream fields no model knows about are logged as warnings |
| Load | `src/glitched/pipelines/load/{emb3d,atlas,research,nvd}.py` | Adds the release, unchanged, to `raw_emb3d` / `raw_atlas` / `raw_research` / `raw_nvd`. Columns are generated from the Pydantic models (`src/glitched/pipelines/load/raw.py`) |
| Transform | `src/glitched/pipelines/transform/` (dbt) | `staging` views reshape the current release; the `public.*` tables the app reads are merged in place and tested; `history.*` snapshots record every change |

**Releases and history.**
- **Raw keeps every release** (EMB3D 2.0.1, ATLAS 2026.09, and a content hash for the CVE notes). Each raw schema's `_loads` table logs every load, and the latest load decides which release is current.
- **Pinned releases.** EMB3D and ATLAS are pinned: change `EMB3D_VERSION` in `src/glitched/pipelines/extract/emb3d.py` or `ATLAS_RELEASE` in `src/glitched/pipelines/extract/atlas.py` to upgrade. The run logs a notice when a newer ATLAS release exists.
- **Nothing is deleted.** Something a new release drops stays in its `public` table with `is_current = false`, because your assessments may still point at it. `last_seen_release` says when it was last present, and the app only reads current rows.
- **History.** `history.<table>_history` has one row per version of each threat, technique, CVE and so on, valid from `dbt_valid_from` to `dbt_valid_to`.

**Platform keywords** (ROS, Unitree, BLE, …) live in `src/glitched/pipelines/transform/seeds/platform_keywords.csv`. dbt uses them to tag CVEs, and the app's onboarding reads the same file.

dbt runs through [uv](https://docs.astral.sh/uv/) in its own Python 3.12
environment, so nothing extra goes into `.venv`. Set `DBT_COMMAND` to use a dbt
you've installed yourself. To work on the models directly:

```bash
cd src/glitched/pipelines/transform
uvx --python 3.12 --from dbt-core~=1.12 --with dbt-postgres~=1.11 dbt build --profiles-dir .
uvx --python 3.12 --from dbt-core~=1.12 --with dbt-postgres~=1.11 dbt docs generate --profiles-dir .  # data dictionary
```

**Tests:**
- **Python:** `python -m unittest discover -s tests -t .` covers the source contracts, new-field warnings and raw DDL.
  Database tests run when `GLITCHED_TEST_DATABASE_URL` (a server; default `localhost`) or
  `GLITCHED_TEST_INTEL_URL` (a database built with `glitched setup --snapshot`, used as a template) is set.
- **dbt:** `dbt build` runs the data tests, unit tests for CVE-id parsing and keyword tagging, and per-table checks that current rows match staging.

## Safety: what a scan sends, and the guardrails

Only scan devices you own or are explicitly authorized to test, ideally on an
isolated lab network. Glitched enforces this as far as software can:

- **One-time notice.** The first scan asks you to accept an authorized-use
  notice (`glitched acknowledge`). Unattended runs such as `autoscan` from cron
  never prompt: they refuse until it's been accepted.
- **Private addresses only, unless approved.** A target that resolves outside
  private, loopback or link-local ranges needs an explicit confirmation, or
  `--allow-public` in scripts. The approval is stored with the assessment or
  device and re-checked right before probing, so a hostname that later
  resolves to a public address is skipped. The host is looked up once per
  scan and every probe connects to that address, so a DNS answer that changes
  mid-scan can't redirect it.
- **One host at a time.** Devices are single hosts; ranges, lists and CIDR
  blocks are refused.
- **Automated checks are passive.** Active steps (crafted input, changing the
  device) are only listed for you to perform and record with `glitched approve`.

**What a scan sends** to the one target host, one connection at a time:

| Check | Traffic |
|---|---|
| Open ports (TID-408) | A TCP connect to 13 common ports (22, 23, 80, 443, 554, 1883, 2222, 5683, 8080, 8443, 8883, 9090, 11311), 2 s timeout each. On each open port it waits half a second for the server's greeting (SSH announces itself), then, if it isn't SSH, attempts a TLS handshake. No other data is sent. SSH and TLS count as encrypted; Telnet, HTTP, MQTT, RTSP, CoAP, rosbridge and the ROS master without TLS as plaintext; anything else is reported as unknown. |
| Weak TLS (TID-411) | The same connects and handshakes; it records the negotiated TLS version. |
| Unauthenticated access (TID-406) | One `GET /` over HTTP on ports 80, 8080 and 9090 and over HTTPS on 443 and 8443, 3 s timeout, no credentials or payload; redirects aren't followed. It reads the status, headers and up to 64 KB of the page: a credentials prompt, a redirect to a login page or a login form counts as protected; data (JSON) without logging in as exposed; any other page as "check by hand". On 9090 (rosbridge) and any port that asks for a WebSocket, it also opens a WebSocket handshake with no token - accepted means exposed - and closes it at once; no ROS messages are sent. |
| `profile detect` / onboarding | The same connects (greeting, then a TLS handshake attempt) to the 13 ports above plus 29999 (Universal Robots dashboard), to suggest profile entries you confirm. |

## Assess a device

The assessment agent plans threats against a target, runs non-destructive
passive checks automatically, and gates anything intrusive for manual review.
It only ever tests a device you own or are authorized to test.

```
glitched scan                 # interactive: prompts for target, host, authorization
glitched scan --target-name "my-robot" --host <robot-ip> \
  --authorization "self-owned lab device"
```

Or step by step:

```
glitched create --target-name "my-robot" --host <robot-ip> --authorization "self-owned lab device"
glitched plan <id> --all      # writes a finding for all 81 threats
glitched run <id>             # auto-runs what's safely automatable
glitched report <id>          # full breakdown, evidence-backed
glitched posture <id>         # roll findings up into a security-posture grade
```

Run `glitched` with no command for an interactive menu of all of the above.

## Scan your devices automatically

Register each device you own (or are authorized to test) once. `autoscan` then
re-scans every device whose interval has passed and reports what changed since
its previous scan. Automatic scans run **only the passive, connect-only checks**
against that device's single registered host. Anything active is still recorded
as awaiting your approval, never run.

```bash
glitched device add --name lab-robot --host 192.168.50.20 \
  --authorization "self-owned lab device" --profile glitch.yaml --every 24
glitched device list                 # devices, last scan, confirmed issues
glitched autoscan                    # scan whatever is due now
glitched autoscan --device lab-robot # scan one device now
glitched device pause lab-robot      # skip it until `device resume`
```

`--profile` scopes the scans to the threats your device profile exposes; leave it
out to check the full EMB3D catalogue. Hosts must be single addresses: ranges,
lists and CIDR blocks are refused.

`autoscan` exits with code 1 when a scan confirms an issue that wasn't there the
previous time, so a scheduler can alert you. To make it automatic, run it hourly
(devices are only scanned when due) with cron (`crontab -e`):

```cron
0 * * * * /path/to/glitched autoscan >> ~/glitched-autoscan.log 2>&1   # `which glitched` gives the path
```

Overlapping runs are safe: each device is locked while it's being scanned.

### The robot scan UI

```bash
glitched ui
```

opens a page in your browser. **Add robot** registers one: its name, address and
why you're allowed to test it, then plain-language questions (the same ones as
`glitched onboard`) and, optionally, an SBOM; **Robot details** changes the
answers later. The page shows each robot drawn as a robot,
every open finding pinned to the part it's in, and a panel for each finding:
what's wrong, the evidence, the recommended fix, and **Recheck**, which re-runs
just that check. **Scan now** runs the passive scan; the first time for each
robot it first shows exactly what will be sent - the address, each check's
ports and requests, and what's never sent - and waits for you to start it
(**What's sent** shows this any time; `glitched device plan <name>` in a
terminal). While it runs, the panel goes through each check live - every
port and request it tries, with the result - and ends with a summary. Robots added with
`glitched device add` show up too.

**Pictures.** Each robot starts with a 3D render from the built-in library that
fits its profile (wheeled robot, robot arm, quadruped, humanoid, drone or
controller box), on a transparent background with its parts already placed
(`tools/render_library.py` makes them in Blender). **Change picture** picks another, or uploads your own photo
(PNG, JPEG or WebP, up to 8 MB). On a photo, **Edit parts** lets you click where
each part is - network, cloud link, main controller, debug port, USB/serial -
and rename them; findings for parts that aren't on the picture stay in the list.
Photos are stored with your other Glitched data (`~/.local/share/glitched/robot-images`)
and never leave your computer; location and other metadata is removed from JPEGs.

The UI runs on your computer only: it listens on `127.0.0.1`, needs the
one-time key in the link `glitched ui` prints (don't share it), and refuses
requests from other websites. It uses the same database, checks and safety
rules as the command line; nothing is sent anywhere else. `--no-browser` prints
the link instead of opening it; `--port` picks the port.

### A device's findings

Each registered device keeps one list of findings across scans, so you can
track a problem from found to fixed. Findings appear once the device's first
scan has completed (a scan that couldn't reach it doesn't count). `glitched findings` brings it up to date and
lists it, most urgent first; every finding says how we know:

| Kind | Meaning |
|---|---|
| Observed | a scan's passive check saw it |
| Declared | your answers in the device profile (e.g. a reachable debug port) |
| Known vuln | a CVE matched by platform, or by SBOM component and version |
| Possible | an EMB3D threat that fits the profile but wasn't tested |

```bash
glitched findings list lab-robot              # open findings (--all includes closed ones)
glitched findings set 12 fix_applied           # you fixed it; the next scan confirms
glitched findings set 14 accepted_risk --note "isolated lab network" --days 30
glitched findings set 15 not_applicable
```

A fix you mark as applied is resolved when a later scan's check passes, and
reopened if the scan still sees the problem. Findings only change when a scan
runs: after you change an answer or the software list, the next scan resolves
declared findings you've answered differently and CVEs whose package version has
moved out of the affected range.
Accepted risks need a reason and come back after their time is up (90 days by
default). Every change is kept with who or what made it.

## The on-site runner

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

## Run the sample report

No robot needed to see it work - point it at a throwaway local HTTP server
instead of a real device. Requires local Postgres running (`psql -d glitched`
should connect) and this repo's `.venv` set up.

**Prerequisites:** Glitched installed (see [Install](#install)), with the
threat intel loaded.

**1. Start a throwaway "device".** Nothing real is connected - this is just
something for the passive checks to observe:

```bash
python -m http.server 8080 --bind 127.0.0.1 &
SERVER_PID=$!
```

**2. Create the assessment.** `glitched create` prints the new assessment's
id (`created assessment <N> for ...`) - capture it into a variable so the rest
of the commands don't need it typed in by hand:

```bash
glitched create --target-name "sample" --host 127.0.0.1 \
  --authorization "demo run against a local stand-in, no real device involved"

ASSESSMENT_ID=$(psql -d glitched -Atc "SELECT max(id) FROM assessments;")
```

**3. Plan, run, report, and grade the posture:**

```bash
glitched plan $ASSESSMENT_ID --all     # writes a finding for all 81 EMB3D threats
glitched run $ASSESSMENT_ID            # auto-runs the passive checks
glitched report $ASSESSMENT_ID         # full breakdown, evidence-backed
glitched posture $ASSESSMENT_ID        # security-posture grade + coverage
```

**4. Stop the throwaway server:**

```bash
kill $SERVER_PID
```

**Expected result:** 81 findings planned, 3 passive checks run automatically
(TID-406, TID-408, TID-411), the rest gated `awaiting_approval` since they
need physical access, credentials, or judgment calls this agent won't make
unattended. Against the plain `http.server` stand-in, TID-406 and TID-408
come back `confirmed` (it really is an unauthenticated plaintext service) and
TID-411 comes back `inconclusive` (no TLS port to evaluate at all). `posture`
then grades it **AT RISK** at ~4% coverage - honest, because 78 threats are
still unreviewed and are counted as unverified, not as safe.

**Clean up the sample data** once you've seen the report (otherwise it stays
in the same `glitched` database your real assessments use):

```bash
psql -d glitched -c "DELETE FROM assessments WHERE target_name='sample';"
rm -rf evidence/
```

## Contributing and security

Contributions are welcome - see [CONTRIBUTING.md](CONTRIBUTING.md). Please report
security problems privately, as [SECURITY.md](SECURITY.md) describes, not in an issue.

## Licence

Apache License 2.0 - see [LICENSE](LICENSE). Threat data is downloaded from its sources
under their own terms; see [NOTICE.md](NOTICE.md).
