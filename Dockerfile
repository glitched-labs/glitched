# Glitched in a container: the CLI, ready to run against the PostgreSQL in compose.yaml.
# See "Run with Docker" in the README. The threat-intel pipelines are a private package and are not in this image.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /bin/

ENV PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_TOOL_DIR=/opt/uv-tools \
    UV_TOOL_BIN_DIR=/usr/local/bin

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE.md ./
COPY src ./src
RUN uv pip install --system --no-cache .

# Run as an unprivileged user; everything Glitched writes (config, acknowledgement,
# evidence) lives in /data, a volume.
RUN useradd --create-home --uid 1000 glitched && mkdir -p /data /work && chown glitched /data /work
USER glitched
ENV GLITCHED_HOME=/data \
    XDG_CONFIG_HOME=/data/config \
    XDG_CACHE_HOME=/data/cache
VOLUME ["/data"]
WORKDIR /work

ENTRYPOINT ["glitched"]
CMD ["--help"]
