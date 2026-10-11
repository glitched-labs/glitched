# Glitched in a container: the CLI, its data pipelines and dbt, ready to run
# against the PostgreSQL in compose.yaml. See "Run with Docker" in the README.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_TOOL_DIR=/opt/uv-tools \
    UV_TOOL_BIN_DIR=/usr/local/bin

# dbt (with the Postgres adapter) is installed at build time, so `glitched
# setup` doesn't download it on every run.
RUN uv tool install --python 3.12 "dbt-core~=1.12" --with "dbt-postgres~=1.11"
ENV DBT_COMMAND=dbt

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE.md ./
COPY src ./src
RUN uv pip install --system --no-cache ".[papers]"

# Run as an unprivileged user; everything Glitched writes (config, evidence,
# dbt cache) lives in /data, a volume.
RUN useradd --create-home --uid 1000 glitched && mkdir -p /data /work && chown glitched /data /work
USER glitched
ENV GLITCHED_HOME=/data \
    XDG_CONFIG_HOME=/data/config \
    XDG_CACHE_HOME=/data/cache
VOLUME ["/data"]
WORKDIR /work

ENTRYPOINT ["glitched"]
CMD ["--help"]
