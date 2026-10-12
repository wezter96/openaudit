import type { Playbook } from "../playbook";
import { compose, REPORTING } from "./shared";

export const authz: Playbook = {
	id: "agent.authz",
	title: "Authentication & authorization review",
	summary:
		"Inventories every route and handler, then checks who can reach it and whose data it touches: missing auth, IDOR, tenant isolation, privilege escalation, sessions/JWT, password reset and rate limiting.",
	categories: ["security"],
	targets: ["codebase"],
	needs: ["code"],
	checklist: [
		"Built an inventory of entry points (HTTP routes, RPC procedures, GraphQL resolvers, server actions, webhooks, queue consumers, cron/admin scripts) with their auth requirement",
		"Identified how authentication is enforced (global middleware, per-route guard, decorator, framework config) and listed routes that bypass it",
		"Checked object-level authorization on every handler that loads a record by a client-supplied id (IDOR / BOLA)",
		"Checked tenant/organisation scoping on queries in multi-tenant code",
		"Checked function-level authorization: admin/staff-only actions, role checks done server-side, mass assignment of role/owner/tenant fields",
		"Reviewed session handling: cookie flags, rotation on login/privilege change, logout invalidation, expiry",
		"Reviewed JWT/token handling: signature verification, algorithm pinning, expiry/audience/issuer checks, secret strength and storage, refresh token rotation",
		"Reviewed password reset, email verification, magic links and invites: token entropy, expiry, single use, account enumeration",
		"Reviewed OAuth/OIDC/SSO flows: state/nonce, redirect URI validation, account linking",
		"Checked brute-force protection and rate limiting on login, reset, OTP/MFA and other credential endpoints",
		"Checked password storage (algorithm, cost) and MFA enforcement where present",
	],
	instructions: compose(
		`# Authentication & authorization review

## Scope

Server-side code that decides **who** a caller is and **what** they may do: route definitions, middleware, guards, policies, controllers/handlers, data-access helpers, session and token code, identity-provider integration. Client-side checks are in scope only to point out that they are the *only* check. Infrastructure IAM is out of scope (see \`agent.iac-architecture\`).

## Method

1. **Map the stack.** Identify the framework(s) and how they declare routes and middleware (e.g. Express/Fastify/Hono routers, Next.js route handlers / server actions / middleware.ts, tRPC/oRPC procedures, NestJS guards, Django/DRF permission classes, Rails before_action, Spring Security config, Laravel middleware, Go handlers). Find the auth library (Passport, NextAuth/Auth.js, Better Auth, Lucia, Clerk, Supabase, Firebase, Devise, Django auth, Spring Security, custom).
2. **Inventory entry points.** Enumerate every externally reachable handler. For each, record: method + path (or procedure name), the auth mechanism that applies, required role/permission, and which resource ids it takes from the request. Use grep for route declarations, decorators and exported handlers; do not stop at the first router file. Include webhooks (signature verification), file/upload endpoints, health/debug/admin routes, GraphQL resolvers and background-job triggers exposed over HTTP.
3. **Find unauthenticated paths.** Compare the inventory against how auth is enforced. Typical bugs: middleware matcher excludes a path prefix, router mounted before the auth middleware, \`public\`/\`skipAuth\` decorators applied too broadly, new handlers not registered under the protected router, Next.js middleware matcher that misses \`/api\`, server actions callable without a session check.
4. **Object-level authorization (IDOR/BOLA).** For every handler that reads or mutates a record by an id from params/body/query, verify the query is constrained by the current principal (owner id, tenant id, membership/ACL check) **before** returning or modifying data. \`findById(req.params.id)\` followed by no ownership check is the classic bug. Also check list/search endpoints for filter parameters that widen scope (\`?userId=\`, \`?orgId=\`), bulk endpoints and nested resources (\`/orgs/:org/projects/:project\` where only \`:org\` is checked).
5. **Tenant isolation.** In multi-tenant code, check that every query on tenant-owned tables includes the tenant from the session (not from the request), that row-level security policies exist where the code relies on them, that caches and object-storage keys are tenant-scoped, and that background jobs carry the tenant.
6. **Function-level authorization & privilege escalation.** Verify admin/staff actions check roles server-side; look for role/permission fields accepted from the client (mass assignment of \`role\`, \`isAdmin\`, \`ownerId\`, \`tenantId\`, \`emailVerified\`), invite flows that let users choose their own role, and endpoints that change another user's role without checking the caller's.
7. **Sessions.** Check cookie flags (\`HttpOnly\`, \`Secure\`, \`SameSite\`), session id regeneration on login and privilege change (fixation), server-side invalidation on logout and password change, idle/absolute expiry, and CSRF protection for cookie-authenticated state-changing requests.
8. **Tokens / JWT.** Check that tokens are verified (not just decoded), that the algorithm is pinned (no \`none\`, no RS/HS confusion), that \`exp\`, \`aud\` and \`iss\` are validated, that signing secrets are not hard-coded or weak, that refresh tokens rotate and are revocable, and that tokens are not put in URLs or logs.
9. **Account recovery & verification.** Reset / magic-link / invite / email-verification tokens must be unguessable (CSPRNG, ≥ 128 bits), short-lived, single-use, bound to the account, and compared in constant time. Responses should not reveal whether an account exists (or the product must accept enumeration explicitly). Changing email/password should require re-authentication.
10. **OAuth / OIDC / SSO.** Check \`state\` (and PKCE / \`nonce\`) handling, exact redirect-URI validation, account linking by verified email only, and that ID tokens are validated.
11. **Brute force & rate limiting.** Look for rate limiting or lockout on login, password reset, OTP/MFA verification, invite acceptance and API-key endpoints. Check where the limiter keys (IP vs account) and whether it is applied to every route that verifies a credential.
12. **Credential storage.** Passwords hashed with bcrypt/scrypt/argon2/PBKDF2 at a sane cost; no reversible encryption or fast hashes; MFA secrets and recovery codes stored safely.

## Severity rubric

- **critical** — unauthenticated access to sensitive data or actions across users/tenants, authentication bypass, forging any user's session/token, or account takeover without user interaction.
- **high** — authenticated user can read or modify other users'/tenants' data (IDOR, missing tenant scope), privilege escalation to admin, reset tokens that are guessable or reusable.
- **medium** — missing rate limiting on credential endpoints, session fixation, logout that does not invalidate sessions, JWT without expiry, account enumeration on login/reset, CSRF on a state-changing cookie-authenticated route.
- **low** — defence-in-depth gaps: missing \`Secure\`/\`SameSite\` where other controls mitigate, overly long session lifetime, weak but salted hashing cost.
- **info** — notable design observations worth a human look that are not vulnerabilities.

## What NOT to report

- Routes that are intentionally public (marketing pages, login, signup, health checks, public read-only content) — unless they leak data they should not.
- IDOR candidates where an ownership/tenant check exists anywhere on the path (middleware, policy, repository helper, database RLS). Read those layers before reporting.
- Generic advice ("consider adding MFA") without a concrete weakness in this code.
- Issues in test fixtures, seed scripts or example code that is not deployed.
- Framework defaults that are secure (e.g. a session library that already sets \`HttpOnly\`) — check the library default before reporting a missing flag.`,
		REPORTING,
	),
};
