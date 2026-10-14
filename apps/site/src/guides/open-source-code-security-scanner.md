---
title: Open-source code security scanner and free SAST tool
heading: A free, open-source code security scanner
description: openaudit is a free, MIT-licensed CLI that runs Semgrep, gitleaks, Trivy, Checkov and more on your machine, merges duplicates and scores each area.
order: 4
---
If you're looking for an open-source alternative to tools like Snyk or SonarQube, openaudit is a free, MIT-licensed CLI that runs established open-source scanners on your machine and merges their output into one scored report. It also has 37 auditors of its own, so it finds issues even before you install anything else.

## Run it

```bash
bunx @openaudit/cli .
bunx @openaudit/cli doctor
```

You need Bun 1.4 or newer. `doctor` shows which optional scanners are installed. A missing scanner is skipped with an install hint. The Docker image `ghcr.io/wezter96/openaudit` bundles the free scanners, pinned to exact versions.

## The scanners it wraps

openaudit wraps 52 open-source scanners, linters and type checkers. The main ones for code security:

- **SAST:** [Semgrep](/auditors/code.semgrep/), Bandit, gosec, Brakeman and mobsfscan, next to the built-in static security rules.
- **Secrets:** [gitleaks](/auditors/code.gitleaks/) and TruffleHog, plus a built-in secret scan. A scan of git history is opt-in.
- **Dependencies:** [osv-scanner](/auditors/code.osv-scanner/), Trivy, npm, pnpm and bun audit, pip-audit and cargo-audit. govulncheck and Grype are opt-in.
- **IaC:** [Checkov](/auditors/iac.checkov/), TFLint, kube-linter, kubeconform, zizmor and actionlint. KICS and Kubescape are opt-in.
- **Containers:** Trivy for images and hadolint for Dockerfiles. Dockle is opt-in.

Run an opt-in tool with `--only <id>`, for example `--only code.grype`. The [auditor catalogue](/auditors/) lists every one.

## One finding per issue, one score per area

When gitleaks, TruffleHog and the built-in scan all find the same key, you get one finding that names who confirmed it. It's scored once.

Every finding belongs to one of ten areas, such as security, supply chain and maintainability. Each area gets a score from 0 to 100 and a grade from A to F. Info findings never lower a score. Skipped auditors are listed with the reason, so a clean result doesn't hide a check that didn't run. See the [report docs](/docs/report/) or [openaudit's audit of itself](/report/).

## SARIF upload and CI gates

`-f` writes HTML, JSON, SARIF, Markdown or CSV. The repository is also a GitHub Action. On pull requests it reports only findings in changed files, uploads SARIF to GitHub code scanning and fails the job on findings at or above `fail-on`. Outside GitHub Actions, run the CLI:

```bash
bunx @openaudit/cli . --diff origin/main -f html,sarif -o openaudit-report --fail-on high
```

`--baseline previous.json` counts only findings that are new since an earlier run. If you already use another scanner, openaudit can run alongside it: GitHub code scanning shows the results of every tool that uploads SARIF. The [CI docs](/docs/ci/) also cover GitLab and pre-commit.

## Your code stays on your machine

openaudit runs locally. Dependency checks ask OSV.dev, and `--offline` blocks network access except to the target itself. Code only leaves your machine if you turn on the agentic auditors, and they're opt-in. Wrapped tools never build or install what they scan. The [safety page](/docs/safety/) has the details.

## What it doesn't do

- It isn't a hosted dashboard. Each run writes report files, and nothing keeps your history between runs. To see what changed, keep the JSON report and pass it to `--baseline` next time.
- There's no paid support. False positives and missed findings go to GitHub issues.
- It's only as good as the tools it wraps. openaudit merges and scores what Semgrep, Trivy and the others report. Merging can't surface an issue they all miss.
- Scanners you haven't installed don't run. The report lists them as skipped.

To start, run `bunx @openaudit/cli init` in your project. It writes a commented config tailored to the project. The [CLI docs](/docs/cli/) list every flag.
