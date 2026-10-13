# Integrations

Ways to run openaudit without installing it by hand. The Docker image is the only one that also brings the scanners (gitleaks, Semgrep, Trivy and so on); the others use whatever is on `PATH`, and `openaudit doctor` shows what is missing.

## Docker

`ghcr.io/wezter96/openaudit` bundles openaudit with the free scanners, pinned to exact versions. Images are multi-arch (`linux/amd64`, `linux/arm64`) and ship with provenance and an SBOM.

| Tag | Contents |
| --- | --- |
| `latest`, `1.2.3`, `1.2`, `edge` (main) | slim: openaudit and the scanners below |
| `latest-full`, `1.2.3-full`, `edge-full` | slim plus Chromium, Lighthouse and pa11y, for `--browser` and the web auditors |

```bash
# Audit the current directory. Run as yourself: git refuses repositories owned by
# another user, and reports are written as you
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" -w /src \
  ghcr.io/wezter96/openaudit . -f html,sarif -o openaudit-report --fail-on high

# Audit a live site with a real browser
docker run --rm ghcr.io/wezter96/openaudit:latest-full https://example.com --browser

# See which tools are installed
docker run --rm ghcr.io/wezter96/openaudit doctor
```

Included: gitleaks, trufflehog, osv-scanner, Trivy, Grype, Syft, hadolint, actionlint, kube-linter, ShellCheck, zizmor, OpenSSF Scorecard, oxlint, Biome, Spectral, jscpd, Semgrep, Bandit, pip-audit, Checkov, Ruff, mobsfscan. The versions are the `ARG`s at the top of the [`Dockerfile`](../Dockerfile).

Not included: ZAP (needs Docker), Prowler (needs cloud credentials), the Go, Rust and Ruby linters (gosec, staticcheck, govulncheck, golangci-lint, clippy, cargo-audit, brakeman need their language toolchain), and tsc, ESLint, knip and mypy (need the audited project's own dependencies). Those auditors report `skipped` with an install hint. Network-backed scanners (Trivy, OSV, Semgrep rules) need outbound access; add `--offline` to forbid it.

Always pass `--user "$(id -u):$(id -g)"`. The image does not disable git's ownership check (`safe.directory`), which protects scanners from a hostile repository's `.git/config`, so a mount owned by another uid makes git-based features such as `--diff` fail with "dubious ownership". GitLab runners and pre-commit already match ownership (see below).

Build it yourself: `docker build -t openaudit .` (slim) or `docker build --target full -t openaudit:full .`.

## GitHub Action

```yaml
- uses: actions/checkout@v7
  with:
    fetch-depth: 0 # diff mode compares against the base branch
- uses: wezter96/openaudit@main # pin to a commit SHA in real use
  with:
    fail-on: high
```

Uploads SARIF to code scanning and the reports as an artifact. Inputs and outputs are listed in the [README](../README.md#ci). The action runs on the runner without the bundled scanners; to use them, run the image in a step instead:

```yaml
- run: docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src:ro" -w /src ghcr.io/wezter96/openaudit . --fail-on high
```

## GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/wezter96/openaudit/main/integrations/gitlab/openaudit.gitlab-ci.yml

variables:
  OPENAUDIT_FAIL_ON: high   # optional
```

On merge requests the job audits only changed files (`--diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME`); on the default branch and schedules it audits everything. Results:

- **openaudit report** link on the MR: the artifact folder with the HTML, SARIF, JSON and Markdown reports.
- **Code Quality** widget on the MR, converted from the findings. GitLab's `reports:sast` expects GitLab's own schema rather than SARIF, so SARIF stays a plain artifact.

The job runs as root on a root-owned checkout, so ownership matches. Pin `OPENAUDIT_IMAGE` to a version tag for reproducible runs. See the comments in the template for the other variables.

## pre-commit

```yaml
repos:
  - repo: https://github.com/wezter96/openaudit
    rev: main # pin to a tag or commit
    hooks:
      - id: openaudit          # needs Bun on PATH
      # - id: openaudit-docker # or: the Docker image, nothing else to install
```

The hooks audit the whole working tree with `--offline --fail-on high`, so staged changes are covered and a commit stays quick. They do not use `--diff`: it compares commits (`<ref>...HEAD`) and staged changes are not committed yet, so `--diff HEAD` would find nothing. To check a branch's committed changes instead, run the hook on `pre-push` with your own arguments:

```yaml
      - id: openaudit
        stages: [pre-push]
        args: [".", "--diff", "origin/main", "--fail-on", "high", "--quiet"]
```

`openaudit-docker` runs the container with your uid and gid (pre-commit does this itself), so ownership matches. Offline mode skips the checks that query advisory databases; CI covers those.

## MCP (Claude Code, Cursor, Codex)

```bash
claude mcp add openaudit -- bunx openaudit mcp
```

Setup for Cursor, VS Code and Codex, and the tools the server exposes, are in [`apps/cli/README.md`](../apps/cli/README.md#mcp-server).
