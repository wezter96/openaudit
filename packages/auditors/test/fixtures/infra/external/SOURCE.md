# Provenance of infra external-tool fixtures

Recorded from real tool runs (2026-10-13):

- `dockle-alpine.json`: dockle 0.4.15 (GitHub release binary, macOS arm64).
  `docker save alpine:latest -o alpine.tar && dockle -f json --exit-code 0 --input alpine.tar`
- `dockle-bun.json`: same command against `oven/bun:1.3.12`.

Reconstructed from documentation (not recorded):

- `dockle.json`: the Dockle README sample (kept because it covers FATAL levels).

- `kubescape.json`: kubescape 4.0.15 (brew), 2026-10-13. Scanned a copy of
  `test/fixtures/infra/k8s-bad/app.yaml` placed at `deploy/sub/app.yaml`:
  `kubescape scan ./deploy/sub/app.yaml --format json --output report.json --keep-local`
  (exit 0, network available). Pruned to keep the file small: only failed
  controls/results remain, `frameworks`, `vulnerabilities` and
  `namespaceSummaries` were dropped, and the scan directory was rewritten to
  `/repo`. Offline (proxy blocked) kubescape fails with "framework from file
  not matching" and leaves an empty report file.

- `kics.json`: kics 2.2.0 (brew), 2026-10-13. Scanned copies of
  `terraform-bad/main.tf`, `k8s-bad/app.yaml` and `docker-bad/Dockerfile`
  (as `tf/`, `k8s/`, `docker/`) with the auditor's flags:
  `KICS_QUERIES_PATH=<brew prefix>/opt/kics/share/kics/assets/queries kics scan -p <dir> -o <out> --report-formats json --output-name results --no-progress --silent --no-color --disable-secrets --ignore-on-exit results`
  (exit 0; `file_name` is relative to the cwd; the scan directory was
  rewritten to `/repo`). The previously passed `--disable-full-descriptions`
  flag does not exist in 2.2.0 and made kics exit 126 ("unknown flag"); it was
  removed from the auditor.
