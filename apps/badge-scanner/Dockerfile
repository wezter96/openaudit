# syntax=docker/dockerfile:1.18
#
# The openaudit badge scanner: the published openaudit image plus one bundled
# script that claims jobs from the badge API. Build from the repository root:
#
#   docker build -f apps/badge-scanner/Dockerfile -t openaudit-badge-scanner .
#
# Env: SCANNER_TOKEN (required), API_URL (default https://openaudit.se),
# OPENAUDIT_BIN (default openaudit). See compose.yml.

ARG BUN_IMAGE=oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61

# --------------------------------------------------------------------------
# Stage 1: bundle the scanner (and the workspace packages it imports) into one file.
# checkov:skip=CKV_DOCKER_7:BUN_IMAGE is pinned by tag and digest (ARG above)
FROM ${BUN_IMAGE} AS build
USER 0
WORKDIR /app
COPY . .
RUN bun install --frozen-lockfile --ignore-scripts --filter ./apps/badge-scanner \
 && bun build apps/badge-scanner/src/main.ts --target bun --outfile /out/scanner.js
USER 1000

# --------------------------------------------------------------------------
# Stage 2: openaudit with its scanners, running the bundled loop.
# checkov:skip=CKV_DOCKER_7:the scanner follows the openaudit release it ships with
FROM ghcr.io/wezter96/openaudit:latest
COPY --from=build /out/scanner.js /opt/scanner/scanner.js
WORKDIR /tmp
USER 1000
# A long-running worker with no port to probe; Dokploy restarts it if it exits.
HEALTHCHECK NONE
ENTRYPOINT ["bun", "/opt/scanner/scanner.js"]
