#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_IMAGE="python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
PIP_TOOLS_VERSION="7.5.2"

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -v "$ROOT/backend:/work" \
  -w /work \
  "$PYTHON_IMAGE" \
  sh -lc "python -m venv /tmp/lock-venv && \
    /tmp/lock-venv/bin/pip install -q pip-tools==${PIP_TOOLS_VERSION} && \
    /tmp/lock-venv/bin/pip-compile --generate-hashes --strip-extras --output-file=requirements.lock requirements.txt && \
    /tmp/lock-venv/bin/pip-compile --allow-unsafe --generate-hashes --strip-extras --output-file=build-requirements.lock build-requirements.in"

printf 'Python lockfiles refreshed. Review the diff and rerun dependency audits before committing.\n'
