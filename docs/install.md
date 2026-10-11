# Install

Needs Python 3.11+, a running PostgreSQL, and [uv](https://docs.astral.sh/uv/)
(the data pipelines run dbt through it).

```bash
uv tool install "git+https://github.com/KaylaGel/glitched"   # or: pipx install "git+https://..."
uv tool install "glitched[papers] @ git+https://github.com/KaylaGel/glitched"   # + paper classification
glitched setup                               # create the database, load all threat intel (~1 min)
glitched doctor                              # check everything; prints a fix for any problem
```

For development, from a checkout: `uv venv && uv pip install -e ".[papers,charts]"`.

Every command, with examples and exit codes: [docs/cli.md](cli.md) (and the [full reference](cli-reference.md)).

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

## Run with Docker

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
