import type { Playbook } from "../playbook";
import { compose, REPORTING, RESPONSIBLE_USE } from "./shared";

export const webappSecurity: Playbook = {
	id: "agent.webapp-security",
	title: "Web app security (authenticated flows)",
	summary:
		"Exercises a running app the user is authorised to test, with the provided test account(s): session handling, logout, CSRF, cookie flags, cross-account access, error leakage and login rate limiting.",
	categories: ["security"],
	targets: ["webapp", "url"],
	needs: ["browser", "network"],
	checklist: [
		"Confirmed the target and test account(s) are provided for testing; stayed within the target origin",
		"Mapped the authenticated surface: main pages, API calls observed in the network log, object ids in URLs/requests",
		"Checked session cookies in practice: HttpOnly, Secure, SameSite, Path/Domain scope, lifetime",
		"Checked session fixation: session identifier changes after login",
		"Checked logout invalidates the session server-side (old cookie/token rejected after logout)",
		"Checked CSRF protections on state-changing requests (token, SameSite, Origin/Referer checks, custom header for JSON APIs)",
		"With two provided test accounts (if available), checked whether account A can read/modify account B's resources by id",
		"Checked error handling for stack traces, framework debug pages, SQL errors or internal paths",
		"Checked login rate limiting / lockout with at most 5 failed attempts on the test account",
		"Checked security headers on authenticated responses (Cache-Control on sensitive pages, CSP, frame-ancestors)",
		"Checked password reset / change flows for obvious weaknesses without completing reset on accounts you do not own",
	],
	instructions: compose(
		`# Web app security (authenticated flows)

## Scope

A running web application the user owns or is authorised to test, using **only** the test account(s) the user provided (via openaudit settings, headers, a stored browser state or the instructions below). This is a light, manual, black-box review of behaviours static analysis cannot confirm — not a penetration test. Deterministic auditors already check response headers, TLS and cookie attributes on unauthenticated responses; focus on what requires a session and interaction.

If no test account is provided, limit yourself to unauthenticated checks (login/reset/sign-up behaviour, error leakage, CSRF on public forms) and say so in your coverage notes.

## Method

1. **Map the authenticated surface.** Sign in with the test account. Browse the main areas and note the requests the app makes (URLs, methods, object identifiers, auth mechanism: cookie vs bearer token). Collect a handful of object ids that belong to the test account (orders, projects, documents, profile id).
2. **Session cookies in practice.** Inspect the cookies set after login: \`HttpOnly\` on session cookies, \`Secure\`, \`SameSite\` (Lax/Strict unless cross-site use is needed), narrow \`Domain\`/\`Path\`, reasonable expiry. Check whether tokens are stored in \`localStorage\` (XSS-exposed) and whether tokens appear in URLs.
3. **Session fixation.** Note the session identifier before login (if any), log in, and confirm it changed.
4. **Logout invalidation.** Capture the session cookie or token, log out, then replay one authenticated GET request with the old credential. It must be rejected (401/403 or redirect to login). Also check whether changing the password invalidates other sessions if you can do so safely on the test account.
5. **CSRF.** For a harmless state-changing action on the test account (e.g. update a display name, toggle a preference), inspect the request: is there a CSRF token, a custom header requirement for JSON APIs, or \`SameSite=Lax/Strict\` cookies with correct \`Origin\` checks? Report missing protection only when the request is cookie-authenticated and would be sent cross-site.
6. **Access to other users' resources.** If the user provided **two** test accounts, sign in as account A and request account B's object ids (and vice versa) for read operations, then a harmless update. If only one account exists, try adjacent/sequential ids for **reads only**, stop at the first confirmation, and never modify data that is not the test account's. Record the request and the response status and redacted excerpt.
7. **Error leakage.** Trigger errors safely: malformed ids, unexpected types, a non-existent route, a missing parameter. Look for stack traces, framework debug pages, SQL/ORM error text, internal hostnames or file paths, and verbose GraphQL errors.
8. **Login rate limiting.** Using the test account's username (or a clearly fake one), submit **at most 5** wrong passwords and observe whether there is throttling, lockout, CAPTCHA or increasing delay. Do not continue beyond 5 attempts. Report the absence of any control as unverified-but-likely if nothing changed within 5 attempts (\`confidence: "medium"\`).
9. **Sensitive-page caching and framing.** Check authenticated pages with personal data send \`Cache-Control: no-store\` (or private), and that \`frame-ancestors\`/\`X-Frame-Options\` prevents clickjacking on pages with sensitive actions.
10. **Reset and change flows.** Observe password reset for account enumeration (different responses for existing vs non-existing emails), token in the URL being sent to third parties via \`Referer\`, and whether password/email change requires the current password. Only complete a reset on the test account.

## Severity rubric

- **critical** — authentication bypass, access to or modification of another user's data with a trivially changed id, session token usable after logout combined with exposure in URLs/logs.
- **high** — cross-account read/write (IDOR) confirmed with test accounts, logout that does not invalidate sessions, missing CSRF on sensitive cookie-authenticated actions, session fixation, stack traces exposing internals.
- **medium** — no login rate limiting observed within 5 attempts, session tokens in \`localStorage\`, account enumeration, sensitive pages cacheable, missing clickjacking protection on sensitive actions.
- **low** — long session lifetimes, minor information disclosure (framework version headers), missing \`SameSite\` where other CSRF defences exist.
- **info** — observations and areas you could not test.

## What NOT to report

- Findings that require attacking accounts you were not given, or anything you would need to exceed the request limits above to confirm.
- Missing headers already reported by deterministic web auditors (unless only authenticated responses lack them).
- Self-XSS, logout CSRF, missing rate limits on non-credential endpoints, or clickjacking on pages without sensitive actions.
- Theoretical issues you did not observe in this application.`,
		RESPONSIBLE_USE,
		REPORTING,
	),
};
