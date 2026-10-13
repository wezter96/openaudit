# Provenance of web external-tool fixtures

Verified by inspection on 2026-10-13 (not re-recorded):

- `pa11y.json`: real pa11y output, not reconstructed. It carries fields only a
  live run produces: axe-core 4.13 `helpUrl`s, `typeCode`, `runnerExtras`
  with `needsFurtherReview`, 72 issues from both the `axe` and `htmlcs`
  runners, and truncated `context` strings (`<html><head>\n<meta ... </html>`).
- `testssl.json`: real `testssl.sh --jsonfile` output (flat list of
  `id/ip/port/severity/finding`) against `tls-v1-0.badssl.com:1010`, recorded
  on 2026-10-13 around 18:50 (the console log of that run says
  `Start 2026-10-13 18:50:48`) with testssl.sh 3.2.4 and Homebrew OpenSSL
  (`engine_problem` entry).
- `testssl-expired.json`: same recording method against `expired.badssl.com`.
- `zap-baseline.json`: not examined by this review.
