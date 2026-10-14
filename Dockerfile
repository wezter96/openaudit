# syntax=docker/dockerfile:1.18
#
# openaudit with the free scanners preinstalled.
#
#   docker build -t openaudit .                       # slim (default): no browser
#   docker build --target full -t openaudit:full .    # + browser and language toolchains
#   docker run --rm -v "$PWD:/src" -w /src openaudit .
#
# Every scanner is pinned to an exact version. Release binaries are verified against
# the checksum file the project publishes, or against the SHA-256 pinned below when
# the project publishes none (kube-linter, shellcheck, zizmor, cargo-audit, and the
# pnpm and brakeman packages). Python and npm packages are pinned by version; pip
# and bun verify registry hashes at download. staticcheck and govulncheck are built
# from source, and `go install` checks their modules against the Go checksum database.
#
# `full` also carries the runtimes some scanners need: PHP for PHPStan, a JRE for
# PMD, a Go toolchain for gosec/staticcheck/govulncheck/golangci-lint (they
# type-check the target through it), Ruby for brakeman, and Node.js for npm and
# pnpm audit. cargo-audit runs standalone against Cargo.lock.
#
# Not included: ZAP (needs Docker), Prowler (cloud credentials), clippy (needs a
# full Rust toolchain), tsc/eslint/knip/mypy (need the target's own dependencies),
# and in slim, everything `full` adds. Those auditors report "skipped" with an
# install hint.

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
ARG KUBECONFORM_VERSION=0.8.0
ARG OASDIFF_VERSION=1.32.1
ARG TFLINT_VERSION=0.64.0
# TFLint cloud rulesets, enabled by iac.tflint from /opt/tflint-plugins.
ARG TFLINT_AWS_VERSION=0.49.0
ARG TFLINT_AZURERM_VERSION=0.32.0
ARG TFLINT_GOOGLE_VERSION=0.40.0
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
# Architecture-independent, `full` only.
ARG PHPSTAN_VERSION=2.3.1
ARG PHPSTAN_SHA256=85157dba3d95d77ca603d2b7303aa78a538f9e3b56ccad07dd794c53aa96d1ae
ARG PMD_VERSION=7.28.0
ARG PMD_SHA256=f974ba571f7bc01c73fffe11bade25fbc1f438698f9e9c00e416e8d65e9fbac2
ARG PNPM_VERSION=11.28.2
ARG PNPM_SHA256=30d4099fa03b9ba1124d81527808b1e4d8e719aeb0ddfe169426df3c4a038a5f
ARG BRAKEMAN_VERSION=8.0.6
ARG BRAKEMAN_SHA256=759cc69341115e6c2dcd47b6fd8649a0b9bd540e3585ac8a0a94e31c66fee386
# Toolchains and scanners, `full` only. go.dev publishes the Go SHA-256s on its
# download page rather than as a checksum file, so they are pinned here.
ARG GO_VERSION=1.27.1
ARG GO_SHA256_AMD64=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
ARG GO_SHA256_ARM64=3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec
ARG NODE_VERSION=24.21.0
ARG GOSEC_VERSION=2.29.0
ARG GOLANGCI_LINT_VERSION=2.14.0
ARG CARGO_AUDIT_VERSION=0.22.2
ARG CARGO_AUDIT_SHA256_AMD64=ab28a1bdb54db4d5d8ad5981cf1f959410370b3d28250dbd35f6a44248620e39
ARG CARGO_AUDIT_SHA256_ARM64=c6603814ddaa45e51263dafd31c0ac98808f688d26f7395804f9670b0fd599dd
# Built from source with the Go toolchain above (no checksummed release binaries).
ARG STATICCHECK_VERSION=0.8.1
ARG GOVULNCHECK_VERSION=1.8.0

# Python tools (one isolated environment each, via uv).
ARG SEMGREP_VERSION=1.180.0
ARG BANDIT_VERSION=1.9.4
ARG PIP_AUDIT_VERSION=2.10.1
ARG CHECKOV_VERSION=3.3.29
ARG RUFF_VERSION=0.17.0
ARG MOBSFSCAN_VERSION=1.0.1
ARG GUARDDOG_VERSION=3.2.0
ARG SSLYZE_VERSION=6.3.1

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
ARG KUBECONFORM_VERSION
ARG OASDIFF_VERSION
ARG TFLINT_VERSION
ARG TFLINT_AWS_VERSION
ARG TFLINT_AZURERM_VERSION
ARG TFLINT_GOOGLE_VERSION
ARG PHPSTAN_VERSION
ARG PHPSTAN_SHA256
ARG PMD_VERSION
ARG PMD_SHA256
ARG PNPM_VERSION
ARG PNPM_SHA256
ARG BRAKEMAN_VERSION
ARG BRAKEMAN_SHA256
ARG GO_VERSION
ARG GO_SHA256_AMD64
ARG GO_SHA256_ARM64
ARG NODE_VERSION
ARG GOSEC_VERSION
ARG GOLANGCI_LINT_VERSION
ARG CARGO_AUDIT_VERSION
ARG CARGO_AUDIT_SHA256_AMD64
ARG CARGO_AUDIT_SHA256_ARM64

USER 0
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip xz-utils \
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
  amd64) A=amd64; X=x86_64;  G=x64;   H=x86_64;   T=64bit; KL=linux;       KLSHA=$KUBE_LINTER_SHA256_AMD64; SCSHA=$SHELLCHECK_SHA256_AMD64; ZZSHA=$ZIZMOR_SHA256_AMD64; GOSHA=$GO_SHA256_AMD64; CASHA=$CARGO_AUDIT_SHA256_AMD64 ;;
  arm64) A=arm64; X=aarch64; G=arm64; H=arm64; T=ARM64; KL=linux_arm64; KLSHA=$KUBE_LINTER_SHA256_ARM64; SCSHA=$SHELLCHECK_SHA256_ARM64; ZZSHA=$ZIZMOR_SHA256_ARM64; GOSHA=$GO_SHA256_ARM64; CASHA=$CARGO_AUDIT_SHA256_ARM64 ;;
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

u=$(gh oasdiff/oasdiff "v$OASDIFF_VERSION")
fetch "$u/oasdiff_${OASDIFF_VERSION}_linux_$A.tar.gz" "$u/checksums.txt" oasdiff.tgz
tar -xzf oasdiff.tgz -C /out oasdiff

u=$(gh yannh/kubeconform "v$KUBECONFORM_VERSION")
fetch "$u/kubeconform-linux-$A.tar.gz" "$u/CHECKSUMS" kubeconform.tgz
tar -xzf kubeconform.tgz -C /out kubeconform

u=$(gh terraform-linters/tflint "v$TFLINT_VERSION")
fetch "$u/tflint_linux_$A.zip" "$u/checksums.txt" tflint.zip
unzip -q tflint.zip tflint -d /out

# Cloud rulesets get their own dir; the bundled terraform ruleset stays in tflint.
mkdir -p /out-tflint-plugins
for r in "aws:$TFLINT_AWS_VERSION" "azurerm:$TFLINT_AZURERM_VERSION" "google:$TFLINT_GOOGLE_VERSION"; do
  name=${r%%:*}
  u=$(gh "terraform-linters/tflint-ruleset-$name" "v${r#*:}")
  fetch "$u/tflint-ruleset-${name}_linux_$A.zip" "$u/checksums.txt" "ruleset-$name.zip"
  unzip -q "ruleset-$name.zip" "tflint-ruleset-$name" -d /out-tflint-plugins
done

chmod 0755 /out/* /out-tflint-plugins/*

# full only: PHPStan (runs on the PHP CLI) and PMD (runs on the JRE).
mkdir -p /out-full
fetch "https://github.com/phpstan/phpstan/releases/download/$PHPSTAN_VERSION/phpstan.phar" "$PHPSTAN_SHA256" /out-full/phpstan.phar
fetch "https://github.com/pmd/pmd/releases/download/pmd_releases%2F$PMD_VERSION/pmd-dist-$PMD_VERSION-bin.zip" "$PMD_SHA256" pmd.zip
unzip -q pmd.zip -d /out-full
mv "/out-full/pmd-bin-$PMD_VERSION" /out-full/pmd

# full only: the Go toolchain, without its own tests (test/ and testdata/, ~50 MB).
fetch "https://go.dev/dl/go$GO_VERSION.linux-$A.tar.gz" "$GOSHA" go.tgz
tar -xzf go.tgz -C /out-full
rm -rf /out-full/go/test
find /out-full/go/src -type d -name testdata -prune -exec rm -rf {} +

# full only: Node.js for npm and pnpm (headers and corepack are left out).
u="https://nodejs.org/dist/v$NODE_VERSION"
n="node-v$NODE_VERSION-linux-$G"
fetch "$u/$n.tar.xz" "$u/SHASUMS256.txt" node.txz
mkdir /out-full/node
tar -xJf node.txz --strip-components=1 -C /out-full/node "$n/LICENSE" "$n/bin/node" "$n/lib/node_modules/npm"
fetch "https://registry.npmjs.org/pnpm/-/pnpm-$PNPM_VERSION.tgz" "$PNPM_SHA256" pnpm.tgz
mkdir /out-full/pnpm
tar -xzf pnpm.tgz --strip-components=1 -C /out-full/pnpm

# full only: gosec and golangci-lint (they need the Go toolchain) and cargo-audit.
mkdir -p /out-full-bin
u=$(gh securego/gosec "v$GOSEC_VERSION")
fetch "$u/gosec_${GOSEC_VERSION}_linux_$A.tar.gz" "$u/gosec_${GOSEC_VERSION}_checksums.txt" gosec.tgz
tar -xzf gosec.tgz -C /out-full-bin gosec

u=$(gh golangci/golangci-lint "v$GOLANGCI_LINT_VERSION")
fetch "$u/golangci-lint-$GOLANGCI_LINT_VERSION-linux-$A.tar.gz" "$u/golangci-lint-$GOLANGCI_LINT_VERSION-checksums.txt" golangci-lint.tgz
tar -xzf golangci-lint.tgz --strip-components=1 -C /out-full-bin "golangci-lint-$GOLANGCI_LINT_VERSION-linux-$A/golangci-lint"

u=$(gh rustsec/rustsec "cargo-audit%2Fv$CARGO_AUDIT_VERSION")
fetch "$u/cargo-audit-$X-unknown-linux-gnu-v$CARGO_AUDIT_VERSION.tgz" "$CASHA" cargo-audit.tgz
tar -xzf cargo-audit.tgz --strip-components=1 -C /out-full-bin "cargo-audit-$X-unknown-linux-gnu-v$CARGO_AUDIT_VERSION/cargo-audit"
chmod 0755 /out-full-bin/*

# full only: the brakeman gem, installed offline in the full stage.
mkdir -p /out-gems
fetch "https://rubygems.org/downloads/brakeman-$BRAKEMAN_VERSION.gem" "$BRAKEMAN_SHA256" "/out-gems/brakeman-$BRAKEMAN_VERSION.gem"
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
ARG GUARDDOG_VERSION
ARG SSLYZE_VERSION
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
                "checkov==$CHECKOV_VERSION" "ruff==$RUFF_VERSION" "mobsfscan==$MOBSFSCAN_VERSION" \
                "guarddog==$GUARDDOG_VERSION" "sslyze==$SSLYZE_VERSION"; do \
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

# full only: staticcheck and govulncheck publish no checksummed binaries, so they
# are built with the bundled Go toolchain. `go install pkg@version` verifies every
# module against the Go checksum database.
FROM ${BUN_IMAGE} AS gotools
ARG STATICCHECK_VERSION
ARG GOVULNCHECK_VERSION
COPY --from=fetch /out-full/go /opt/go
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOBIN=/out \
    GOPATH=/tmp/gopath \
    GOCACHE=/tmp/gocache
USER 0
RUN /opt/go/bin/go install -trimpath "honnef.co/go/tools/cmd/staticcheck@v$STATICCHECK_VERSION" \
 && /opt/go/bin/go install -trimpath "golang.org/x/vuln/cmd/govulncheck@v$GOVULNCHECK_VERSION" \
 && ls /out
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
COPY --from=fetch /out-tflint-plugins/ /opt/tflint-plugins/
COPY --from=pytools /opt/uv/ /opt/uv/
COPY --from=nodetools /opt/bun/ /opt/bun/
COPY --from=app /app /app
# HOME is writable for any uid (`docker run --user`, pre-commit) so scanners can cache.
# GuardDog refreshes its popular-packages lists (typosquatting) in place, so they
# get a writable copy there too.
RUN ln -s /app/apps/cli/src/bin.ts /usr/local/bin/openaudit \
 && mkdir -p /home/bun/.cache/guarddog \
 && cp /opt/uv/tools/guarddog/lib/python3*/site-packages/guarddog/analyzer/metadata/resources/top_*.json /home/bun/.cache/guarddog/ \
 && chmod -R a+rwX /home/bun/.cache \
 && chmod 1777 /home/bun

ENV HOME=/home/bun \
    PATH=/opt/uv/bin:/opt/bun/bin:$PATH \
    GUARDDOG_TOP_PACKAGES_CACHE_LOCATION=/home/bun/.cache/guarddog

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
# full: adds Chromium, Lighthouse and pa11y for `--browser` and the web.* auditors,
# plus the language runtimes: PHP for PHPStan, a JRE for PMD, Go for the Go
# scanners, Ruby for brakeman and Node.js for npm/pnpm audit.
FROM runtime AS full
ARG BRAKEMAN_VERSION
USER 0
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium fonts-liberation php-cli default-jre-headless ruby \
 && rm -rf /var/lib/apt/lists/*
COPY --from=browsertools /opt/bun-browser/ /opt/bun-browser/
COPY --from=fetch /out-full/ /opt/
COPY --from=fetch /out-full-bin/ /usr/local/bin/
COPY --from=gotools /out/ /usr/local/bin/
# The gem file was pinned by SHA-256 in fetch. --local installs it without contacting
# rubygems.org; its one dependency, racc, is a default gem of Debian's Ruby.
# hadolint ignore=DL3028
RUN --mount=type=bind,from=fetch,source=/out-gems,target=/tmp/gems \
    gem install --local --no-document "/tmp/gems/brakeman-$BRAKEMAN_VERSION.gem"
# Node.js stays off PATH: the Bun-installed scanners (#!/usr/bin/env node) resolve
# `node` to Bun's fallback shim, and a real node earlier on PATH would silently
# move them, Lighthouse and pa11y included, onto it. npm and pnpm call it directly.
RUN printf '#!/bin/sh\nexec php /opt/phpstan.phar "$@"\n' > /usr/local/bin/phpstan \
 && printf '#!/bin/sh\nexec /opt/node/bin/node /opt/node/lib/node_modules/npm/bin/npm-cli.js "$@"\n' > /usr/local/bin/npm \
 && printf '#!/bin/sh\nexec /opt/node/bin/node /opt/pnpm/bin/pnpm.mjs "$@"\n' > /usr/local/bin/pnpm \
 && chmod 0755 /usr/local/bin/phpstan /usr/local/bin/npm /usr/local/bin/pnpm \
 && ln -s /opt/pmd/bin/pmd /usr/local/bin/pmd
# GOTOOLCHAIN=local: a target's go.mod `toolchain` line must never make go download
# and run another toolchain (the Go wrappers also pass it). No update checks either.
ENV PATH=/opt/bun-browser/bin:/opt/go/bin:$PATH \
    GOTOOLCHAIN=local \
    npm_config_update_notifier=false \
    CHROME_PATH=/usr/bin/chromium \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    PUPPETEER_SKIP_DOWNLOAD=1
USER 1000

# --------------------------------------------------------------------------
FROM runtime AS slim
# One-shot CLI, not a service: nothing for a health check to probe.
HEALTHCHECK NONE
USER 1000
