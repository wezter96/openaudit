# Provenance of codebase external-tool fixtures

Recorded from real tool runs:

- `scorecard.json`: OpenSSF Scorecard v5.6.0 (brew), 2026-10-13:
  `GITHUB_AUTH_TOKEN=<from env> scorecard --repo=github.com/ossf/scorecard --format json --show-details`
  (without `--show-details` every check's `details` is null).

Reconstructed from documentation (not recorded): see the notes appended below
for `cargo-audit.json` and `scancode.json`.

- `scancode.json`: ScanCode Toolkit 32.5.0 (`uv tool install scancode-toolkit`
  on Python 3.12, `brew install libmagic`), 2026-10-13. Scanned a synthetic
  tree (MIT `LICENSE`, `src/iproute.c` GPL-2.0+ header, `src/lgpl-helper.c`
  LGPL-2.1+ header, `src/server/agpl-app.js` AGPL-3.0+ header, plain
  `src/plain.ts`, `package.json`, `node_modules/` and `sub/node_modules/`):
  `scancode --license --copyright --strip-root --json out.json --quiet -n 4 --ignore node_modules --ignore .git <dir>`
  (exit 0). `--strip-root`, `--quiet` and `-n` are all accepted. The scan
  directory was rewritten to `/repo`. Findings from the run: `--ignore 'node_modules/*'`
  (the previous argument) does NOT exclude files under node_modules, while the
  bare `--ignore node_modules` does (directory entries are still listed, with
  `type: "directory"`).

Cross-checked against tool source, not recorded (the Rust toolchain is too big to install here):

- `cargo-audit.json`: shape checked against rustsec `rustsec/src/report.rs`
  (`database`, `lockfile`, `settings`, `vulnerabilities{found,count,list}`,
  `warnings` as a map keyed by `notice|unmaintained|unsound|yanked`),
  `warning.rs` (`kind`, `package`, nullable `advisory`/`affected`/`versions`;
  yanked warnings carry `advisory: null`), `advisory/metadata.rs` (incl.
  `source` and `expect-deleted`) and `advisory/versions.rs`, 2026-10-13. The
  earlier fixture filed an `informational: "unsound"` advisory under
  `unmaintained`; warnings are now filed under their own kind, and a yanked
  entry was added. Advisory contents are hand-written from the public RustSec
  entries, not captured output. `cvss` is a `cvss::Cvss` serialised as a vector
  string and may be CVSS v2, v3.x or v4.0; the severity helper only scores
  v3.x, so other versions fall back to `medium`.


- `guarddog-npm.json`, `guarddog-pypi.json`: GuardDog 3.2.0 (`uvx guarddog@3.2.0`,
  Python 3.14), 2026-10-14, run from an empty scratch dir holding copies of
  `supply/guarddog/package.json` and `supply/guarddog/requirements.txt`:
  `guarddog --log-level error npm verify <dir>/package.json --output-format json --include-dev-dependencies`
  and `guarddog --log-level error pypi verify <dir>/requirements.txt --output-format json`
  (both exit 0; `--exit-non-zero-on-finding` is not passed). The npm run got the
  manifest as-is, so it includes the `"lib": "workspace:*"` entry that the
  auditor's sanitised copy drops (it shows up as a `download-package` error).
  `electorn`, `lodahs` and `reqeusts` are not on the registry (only
  `0.0.1-security` matches for electorn, which `*` excludes) and are left out
  of the output. `crossenv` and `loadsh` trip the typosquatting metadata rule;
  core-js (postinstall hook), vite, wrangler (labelled `high_risk`) and
  beautifulsoup 3.2.2 trip source-code YARA rules. No known-malicious package
  was downloaded: the registries remove them, and the typosquats here are npm
  security placeholders or harmless.

- `gosec-load-error.json`: gosec 2.29.0 (`-fmt json -no-fail ./...`, no
  `-quiet`) in the openaudit full image (Go 1.27.1, `GOTOOLCHAIN=local`) on a
  module whose go.mod says `go 1.99`: no package loads, so `Stats.files` is 0
  and the reason is in `Golang errors`. With `-quiet` gosec prints nothing.
