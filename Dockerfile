# syntax=docker/dockerfile:1.18
#
# openaudit with the free scanners preinstalled.
#
#   docker build -t openaudit .                       # slim (default): no browser
#   docker build --target full -t openaudit:full .    # + Chromium, Lighthouse, pa11y
#   docker run --rm -v "$PWD:/src" -w /src openaudit .
#
# Every scanner is pinned to an exact version. Release binaries are verified against
# the checksum file the project publishes, or against the SHA-256 pinned below when
# the project publishes none (kube-linter, shellcheck, zizmor). Python and npm
# packages are pinned by version; pip and bun verify registry hashes at download.
#
# Not included: ZAP (needs Docker), Prowler (cloud credentials), gosec/staticcheck/
# govulncheck/golangci-lint (need a Go toolchain), clippy/cargo-audit (Rust),
# brakeman (Ruby), tsc/eslint/knip/mypy (need the target's own dependencies).
# Those auditors report "skipped" with an install hint.

# Base image: Debian 13 (trixie) slim with Bun, pinned by digest.
ARG BUN_IMAGE=oven/bun:1.4.2-slim@sha256:cb3bbbb08e13a4a2ff400f24c7a2a1d5efa83f6ef8544d52d95a519631e2fc61

# Release binaries.
ARG GITLEAKS_VERSION=8.30.1
ARG TRUFFLEHOG_VERSION=3.99.2
ARG OSV_SCANNER_VERSION=2.7.0
ARG TRIVY_VERSION=0.75.0
ARG GRYPE_VERSION=0.120.1
ARG SYFT_VERSION=1.54.1
ARG HADOLINT_VERSION=2.15.1
ARG ACTIONLINT_VERSION=1.7.12
ARG SCORECARD_VERSION=5.6.0
ARG UV_VERSION=0.13.0
# Projects that publish no checksum file: SHA-256 of the release archive per arch.
ARG KUBE_LINTER_VERSION=0.8.3
ARG KUBE_LINTER_SHA256_AMD64=1a6d8419b11971372971fdbc22682b684ebfb7cf1c39591662d1b6ca736c41df
ARG KUBE_LINTER_SHA256_ARM64=802e1b09eabd08f6f0a060a6b8ab2bf7bc7e6bf4f673bb2692303704c84b3e22
ARG SHELLCHECK_VERSION=0.11.0
ARG SHELLCHECK_SHA256_AMD64=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
ARG SHELLCHECK_SHA256_ARM64=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
ARG ZIZMOR_VERSION=1.30.1
ARG ZIZMOR_SHA256_AMD64=e65324f4430c2717591937edcec90ccbefaf14c174f8ec9415e03ca875b46e1a
ARG ZIZMOR_SHA256_ARM64=7ff1dce33bdd18fd2a4affe63bdd47efcccca97b2cec1c1863ec26e9e2647540

# Python tools (one isolated environment each, via uv).
ARG SEMGREP_VERSION=1.180.0
ARG BANDIT_VERSION=1.9.4
ARG PIP_AUDIT_VERSION=2.10.1
ARG CHECKOV_VERSION=3.3.29
ARG RUFF_VERSION=0.17.0
ARG MOBSFSCAN_VERSION=1.0.1

# Node tools (bun global installs).
ARG SPECTRAL_VERSION=6.17.0
ARG JSCPD_VERSION=5.4.1
ARG OXLINT_VERSION=1.88.0
ARG BIOME_VERSION=2.5.15
ARG LIGHTHOUSE_VERSION=13.5.0
ARG PA11Y_VERSION=10.0.0

# --------------------------------------------------------------------------
# Stage 1: download and verify the release binaries into /out.
# checkov:skip=CKV_DOCKER_7:BUN_IMAGE is pinned by tag and digest (ARG above)
FROM ${BUN_IMAGE} AS fetch
ARG TARGETARCH
ARG GITLEAKS_VERSION
ARG TRUFFLEHOG_VERSION
ARG OSV_SCANNER_VERSION
ARG TRIVY_VERSION
ARG GRYPE_VERSION
ARG SYFT_VERSION
ARG HADOLINT_VERSION
ARG ACTIONLINT_VERSION
ARG SCORECARD_VERSION
ARG UV_VERSION
ARG KUBE_LINTER_VERSION
ARG KUBE_LINTER_SHA256_AMD64
ARG KUBE_LINTER_SHA256_ARM64
ARG SHELLCHECK_VERSION
ARG SHELLCHECK_SHA256_AMD64
ARG SHELLCHECK_SHA256_ARM64
ARG ZIZMOR_VERSION
ARG ZIZMOR_SHA256_AMD64
ARG ZIZMOR_SHA256_ARM64

USER 0
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
 && rm -rf /var/lib/apt/lists/*

# fetch <url> <sha256 | url of a checksum file> <out>
COPY --chmod=0755 <<'EOF' /usr/local/bin/fetch
#!/bin/sh
set -eu
url=$1; want=$2; out=$3
curl -fsSL --retry 3 -o "$out" "$url"
case "$want" in
  http*)
    base=${url##*/}
    want=$(curl -fsSL --retry 3 "$want" | awk -v f="$base" '{ n = $2; sub(/^\*/, "", n); if (n == f) { print $1; exit } }')
    ;;
esac
[ -n "$want" ] || { echo "no checksum found for $url" >&2; exit 1; }
echo "$want  $out" | sha256sum -c -
EOF

WORKDIR /tmp/dl
RUN <<'EOF'
set -eux
mkdir -p /out
case "$TARGETARCH" in
  amd64) A=amd64; X=x86_64;  G=x64;   H=x86_64;   T=64bit; KL=linux;       KLSHA=$KUBE_LINTER_SHA256_AMD64; SCSHA=$SHELLCHECK_SHA256_AMD64; ZZSHA=$ZIZMOR_SHA256_AMD64 ;;
  arm64) A=arm64; X=aarch64; G=arm64; H=arm64; T=ARM64; KL=linux_arm64; KLSHA=$KUBE_LINTER_SHA256_ARM64; SCSHA=$SHELLCHECK_SHA256_ARM64; ZZSHA=$ZIZMOR_SHA256_ARM64 ;;
  *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;;
esac
gh() { echo "https://github.com/$1/releases/download/$2"; }

u=$(gh gitleaks/gitleaks "v$GITLEAKS_VERSION")
fetch "$u/gitleaks_${GITLEAKS_VERSION}_linux_$G.tar.gz" "$u/gitleaks_${GITLEAKS_VERSION}_checksums.txt" gitleaks.tgz
tar -xzf gitleaks.tgz -C /out gitleaks

u=$(gh trufflesecurity/trufflehog "v$TRUFFLEHOG_VERSION")
fetch "$u/trufflehog_${TRUFFLEHOG_VERSION}_linux_$A.tar.gz" "$u/trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" trufflehog.tgz
tar -xzf trufflehog.tgz -C /out trufflehog

u=$(gh google/osv-scanner "v$OSV_SCANNER_VERSION")
fetch "$u/osv-scanner_linux_$A" "$u/osv-scanner_SHA256SUMS" /out/osv-scanner

u=$(gh aquasecurity/trivy "v$TRIVY_VERSION")
fetch "$u/trivy_${TRIVY_VERSION}_Linux-$T.tar.gz" "$u/trivy_${TRIVY_VERSION}_checksums.txt" trivy.tgz
tar -xzf trivy.tgz -C /out trivy

u=$(gh anchore/grype "v$GRYPE_VERSION")
fetch "$u/grype_${GRYPE_VERSION}_linux_$A.tar.gz" "$u/grype_${GRYPE_VERSION}_checksums.txt" grype.tgz
tar -xzf grype.tgz -C /out grype

u=$(gh anchore/syft "v$SYFT_VERSION")
fetch "$u/syft_${SYFT_VERSION}_linux_$A.tar.gz" "$u/syft_${SYFT_VERSION}_checksums.txt" syft.tgz
tar -xzf syft.tgz -C /out syft

u=$(gh hadolint/hadolint "v$HADOLINT_VERSION")
fetch "$u/hadolint-linux-$H" "$u/checksums.sha256" /out/hadolint

u=$(gh rhysd/actionlint "v$ACTIONLINT_VERSION")
fetch "$u/actionlint_${ACTIONLINT_VERSION}_linux_$A.tar.gz" "$u/actionlint_${ACTIONLINT_VERSION}_checksums.txt" actionlint.tgz
tar -xzf actionlint.tgz -C /out actionlint

u=$(gh ossf/scorecard "v$SCORECARD_VERSION")
fetch "$u/scorecard_${SCORECARD_VERSION}_linux_$A.tar.gz" "$u/scorecard_checksums.txt" scorecard.tgz
tar -xzf scorecard.tgz -C /out scorecard

u=$(gh astral-sh/uv "$UV_VERSION")
fetch "$u/uv-$X-unknown-linux-gnu.tar.gz" "$u/uv-$X-unknown-linux-gnu.tar.gz.sha256" uv.tgz
tar -xzf uv.tgz --strip-components=1 -C /out "uv-$X-unknown-linux-gnu/uv"

u=$(gh stackrox/kube-linter "v$KUBE_LINTER_VERSION")
fetch "$u/kube-linter-$KL.tar.gz" "$KLSHA" kube-linter.tgz
tar -xzf kube-linter.tgz -C /out kube-linter

u=$(gh koalaman/shellcheck "v$SHELLCHECK_VERSION")
fetch "$u/shellcheck-v${SHELLCHECK_VERSION}.linux.$X.tar.xz" "$SCSHA" shellcheck.txz
tar -xJf shellcheck.txz --strip-components=1 -C /out "shellcheck-v${SHELLCHECK_VERSION}/shellcheck"

u=$(gh zizmorcore/zizmor "v$ZIZMOR_VERSION")
fetch "$u/zizmor-$X-unknown-linux-gnu.tar.gz" "$ZZSHA" zizmor.tgz
tar -xzf zizmor.tgz -C /out zizmor

chmod 0755 /out/*
EOF

USER 1000

# --------------------------------------------------------------------------
# Stage 2: Python scanners, one isolated environment each (so mobsfscan's semgrep
# pin cannot clash with the standalone semgrep).
FROM ${BUN_IMAGE} AS pytools
ARG SEMGREP_VERSION
ARG BANDIT_VERSION
ARG PIP_AUDIT_VERSION
ARG CHECKOV_VERSION
ARG RUFF_VERSION
ARG MOBSFSCAN_VERSION
USER 0
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /out/uv /usr/local/bin/uv
ENV UV_TOOL_DIR=/opt/uv/tools \
    UV_TOOL_BIN_DIR=/opt/uv/bin \
    UV_PYTHON=/usr/bin/python3 \
    UV_PYTHON_DOWNLOADS=never \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_CACHE=1
RUN set -eux; \
    for spec in "semgrep==$SEMGREP_VERSION" "bandit==$BANDIT_VERSION" "pip-audit==$PIP_AUDIT_VERSION" \
                "checkov==$CHECKOV_VERSION" "ruff==$RUFF_VERSION" "mobsfscan==$MOBSFSCAN_VERSION"; do \
      uv tool install "$spec"; \
    done; \
    ls /opt/uv/bin
USER 1000

# --------------------------------------------------------------------------
# Stage 3: Node scanners. Bun does not run postinstall scripts, so nothing
# downloads a browser here.
FROM ${BUN_IMAGE} AS nodetools
ARG SPECTRAL_VERSION
ARG JSCPD_VERSION
ARG OXLINT_VERSION
ARG BIOME_VERSION
ENV BUN_INSTALL=/opt/bun \
    BUN_INSTALL_BIN=/opt/bun/bin
USER 0
RUN bun add -g \
      "@stoplight/spectral-cli@$SPECTRAL_VERSION" \
      "jscpd@$JSCPD_VERSION" \
      "oxlint@$OXLINT_VERSION" \
      "@biomejs/biome@$BIOME_VERSION" \
 && ls /opt/bun/bin
USER 1000

FROM ${BUN_IMAGE} AS browsertools
ARG LIGHTHOUSE_VERSION
ARG PA11Y_VERSION
ENV BUN_INSTALL=/opt/bun-browser \
    BUN_INSTALL_BIN=/opt/bun-browser/bin
USER 0
RUN bun add -g "lighthouse@$LIGHTHOUSE_VERSION" "pa11y@$PA11Y_VERSION" \
 && ls /opt/bun-browser/bin
USER 1000

# --------------------------------------------------------------------------
# Stage 4: openaudit itself, with only the CLI's dependency graph.
FROM ${BUN_IMAGE} AS app
USER 0
WORKDIR /app
COPY . .
# --production would skip linking the workspace packages, so install the CLI's own
# workspace graph instead. Scripts are skipped (the root postinstall is for the web
# app), and the musl copy of the agent SDK's native binary is dropped: this is glibc.
RUN bun install --frozen-lockfile --ignore-scripts --filter ./apps/cli \
 && rm -rf node_modules/.bun/@anthropic-ai+claude-agent-sdk-linux-*-musl* \
 && chmod +x apps/cli/src/bin.ts

USER 1000

# --------------------------------------------------------------------------
# Stage 5: runtime. `full` extends it with a browser; `slim` is last so a plain
# `docker build .` produces the slim image.
FROM ${BUN_IMAGE} AS runtime
USER 0
# git: --diff and history scanners; python3: the uv-installed tools; ca-certificates: advisory DBs.
# No git safe.directory exception: run with --user "$(id -u):$(id -g)" so the mount's
# owner matches and git's ownership check stays on against hostile repositories.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git python3 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=fetch /out/ /usr/local/bin/
COPY --from=pytools /opt/uv/ /opt/uv/
COPY --from=nodetools /opt/bun/ /opt/bun/
COPY --from=app /app /app
# HOME is writable for any uid (`docker run --user`, pre-commit) so scanners can cache.
RUN ln -s /app/apps/cli/src/bin.ts /usr/local/bin/openaudit \
 && chmod 1777 /home/bun

ENV HOME=/home/bun \
    PATH=/opt/uv/bin:/opt/bun/bin:$PATH

LABEL org.opencontainers.image.title="openaudit" \
      org.opencontainers.image.description="Audit code, sites, containers and IaC with free open-source scanners preinstalled." \
      org.opencontainers.image.source="https://github.com/wezter96/openaudit" \
      org.opencontainers.image.url="https://github.com/wezter96/openaudit" \
      org.opencontainers.image.documentation="https://github.com/wezter96/openaudit/blob/main/integrations/README.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="openaudit"

USER 1000
WORKDIR /src
ENTRYPOINT ["openaudit"]
CMD ["--help"]

# --------------------------------------------------------------------------
# full: adds Chromium, Lighthouse and pa11y for `--browser` and the web.* auditors.
FROM runtime AS full
USER 0
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-liberation \
 && rm -rf /var/lib/apt/lists/*
COPY --from=browsertools /opt/bun-browser/ /opt/bun-browser/
ENV PATH=/opt/bun-browser/bin:$PATH \
    CHROME_PATH=/usr/bin/chromium \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    PUPPETEER_SKIP_DOWNLOAD=1
USER 1000

# --------------------------------------------------------------------------
FROM runtime AS slim
# One-shot CLI, not a service: nothing for a health check to probe.
HEALTHCHECK NONE
USER 1000
