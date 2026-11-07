# Security policy

openaudit reads untrusted repositories, artifacts and websites, so we treat bugs that let a scanned target affect the machine running openaudit as security issues. That includes path traversal, command execution, credential leakage and SSRF in the hosted API, the quick website audit at https://openaudit.se/audit/ and the badge scanner.

## Report a vulnerability

Report vulnerabilities privately through GitHub Security Advisories: https://github.com/wezter96/openaudit/security/advisories/new (or "Report a vulnerability" on the repository's Security tab). Do not open a public issue.

Include what you ran, what the target contained and what happened, so we can reproduce it.

## What happens next

- We acknowledge the report within 3 working days.
- We confirm or rule out the issue, and tell you which, within 14 days.
- We aim to release a fix within 90 days, sooner for anything severe, and agree a disclosure date with you. We credit you in the advisory unless you ask us not to.

## Supported versions

Only the latest release of `@openaudit/cli` (https://www.npmjs.com/package/@openaudit/cli) and the `ghcr.io/wezter96/openaudit` image gets security fixes. Upgrade before you report.

Only audit systems you own or are authorised to test.
