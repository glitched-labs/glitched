# Trying Glitched: a 15-minute first run

Thanks for trying Glitched. It checks robots and IoT devices **that you own**
for known security weaknesses: it tells you which published vulnerabilities and
attack techniques apply to your device, and runs a few safe network checks
against it.

This guide takes about 15 minutes. Everything runs on your own computer.

> [!IMPORTANT]
> Only scan devices you own or are explicitly allowed to test, on your own
> network. Glitched asks you to confirm this once, and refuses to scan public
> internet addresses unless you explicitly approve them.

## 1. Install the prerequisites

You need three things: **uv** (installs Python tools), **PostgreSQL** (the
database Glitched keeps its data in) and **Python 3.11 or newer** (uv can
provide it).

**macOS** (with [Homebrew](https://brew.sh)):

```bash
brew install uv postgresql@17
brew services start postgresql@17
```

**Linux:** install uv with `curl -LsSf https://astral.sh/uv/install.sh | sh`,
and PostgreSQL from your distribution (e.g. `sudo apt install postgresql`).

**Prefer Docker for the database?** This runs PostgreSQL reachable only from
your own machine:

```bash
docker run -d --name glitched-db -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER="${USER}" -e POSTGRES_PASSWORD=glitched -e POSTGRES_DB=glitched postgres:17
export DATABASE_URL="postgresql://${USER}:glitched@localhost:5432/glitched"
```

**Rather run all of Glitched in Docker?** Skip steps 1-2: clone this
repository, and in its folder put `docker compose run --rm` in front of every
`glitched` command in this guide, e.g. `docker compose run --rm glitched doctor`.
Keep `glitch.yaml` in that folder. See "Run with Docker" in
the README.

## 2. Install Glitched

```bash
uv tool install "git+https://github.com/glitched-labs/glitched"     # or a release: ...glitched@v0.2.0
glitched --version
```

## 3. Point Glitched at the threat data

Glitched reads the threat intel from a PostgreSQL database. Your invitation says which one: either a
`DATABASE_URL` to set, or the private `glitched-pipelines` package, which builds it locally (about a minute):

```bash
glitched setup          # only with glitched-pipelines installed; otherwise set DATABASE_URL
```

Then check that everything is working:

```bash
glitched doctor
```

Every line should be ✓ or `i` (information). Anything marked ✗ comes with a fix.

## 4. Describe your device

```bash
glitched acknowledge     # read and accept the authorized-use notice (once)
glitched onboard         # plain-language questions about your device
```

`onboard` asks things like "Does it run ROS?" and "Can it be updated over the
air?". You can import an SBOM or let it detect services on the device. It
saves your answers to `glitch.yaml` in the current folder and shows which
vulnerabilities apply, each with the reason.

To see the list again later (anything new is marked NEW):

```bash
glitched exposure
```

## 5. Scan your device

Find your device's IP address (your router's admin page lists connected
devices, or run `arp -a`). It should be a private address such as
`192.168.x.x` or `10.x.x.x`.

```bash
glitched scan --profile glitch.yaml --host 192.168.1.50 --authorization "my own robot"
glitched report <assessment id from the scan output>
glitched posture <assessment id>
```

The scan only opens connections, checks encryption and makes plain web
requests; the README's "What a scan sends" section lists every port and
request. Anything more intrusive is listed for you to try yourself and record
with `glitched approve`.

**Optional:** re-scan automatically and get told when something changes:

```bash
glitched device add --name my-robot --host 192.168.1.50 \
  --authorization "my own robot" --profile glitch.yaml --every 24
glitched autoscan        # run it now; see the README for scheduling it hourly
```

## What leaves your computer

- **Downloads**, from public sources: MITRE (emb3d.mitre.org and GitHub) and
  the NVD; Hugging Face, arXiv and NVIDIA only if you load research papers.
- **Anthropic's API** only if you load research papers *and* set an
  `ANTHROPIC_API_KEY` (to classify them).
- **Nothing about your devices** - names, addresses, profiles and scan results
  stay in your local database and `~/.local/share/glitched`.

## If something goes wrong

Run `glitched doctor` first: it checks the usual suspects and tells you how to
fix each one.

| You see | Fix |
|---|---|
| `Can't connect to postgresql://...` | PostgreSQL isn't running: `brew services start postgresql@17`, or start your Docker container. |
| `... doesn't exist yet - run glitched setup first` | The database has no threat intel yet: check `DATABASE_URL`, or run `glitched setup` if you have glitched-pipelines. |
| `Glitched needs a one-time acknowledgement` | Run `glitched acknowledge`. |
| `... is a public address` | You're pointing at an internet address, not your device. Check the IP. |
| `uvx not found` | Install uv (step 1). |
| NVD part of setup is slow | Normal without an API key (about a minute). `glitched setup --skip-nvd` skips it (glitched-pipelines only). |

## Sending feedback

Please open an issue (bug, "this was confusing" or idea). Security problems: see SECURITY.md instead.
For bugs, attach a debug bundle:

```bash
glitched debug-bundle
```

It contains versions, the `doctor` results and your settings with API keys
hidden, and **no device names, addresses or scan results**. Open the .zip to
check before you send it.

**What we'd love you to try in the first week:**

- [ ] Install, `setup` and `doctor` all green
- [ ] `onboard` a real device (or an imaginary one) and read the `exposure` list
- [ ] Scan a device you own and read the `report`
- [ ] Leave `autoscan` scheduled for a few days
- [ ] Tell us one thing that confused you and one thing you'd want next
