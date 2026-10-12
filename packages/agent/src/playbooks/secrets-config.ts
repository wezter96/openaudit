import type { Playbook } from "../playbook";
import { compose, REPORTING } from "./shared";

export const secretsConfig: Playbook = {
	id: "agent.secrets-config",
	title: "Secrets & configuration review",
	summary:
		"Reviews how secrets and configuration actually flow — logs, debug modes, env handling, client bundles, CI pipelines, container images and IAM — beyond what regex secret scanners catch.",
	categories: ["security", "best-practices"],
	targets: ["codebase", "container", "iac"],
	needs: ["code"],
	checklist: [
		"Located configuration loading (env parsing, config files, secret managers) and the list of secrets the app uses",
		"Checked that secrets are not hard-coded, committed in config/fixtures, or given insecure fallback defaults",
		"Checked that secrets and credentials are not written to logs, error messages, analytics or API responses",
		"Checked which environment variables reach client bundles (NEXT_PUBLIC_, VITE_, REACT_APP_, PUBLIC_, EXPO_PUBLIC_) and that none are secret",
		"Checked debug/development modes, verbose error pages, stack traces, admin consoles and source maps in production config",
		"Checked CI workflows for secret exposure: pull_request_target, untrusted input in run steps, secrets echoed or passed to third-party actions, overly broad tokens",
		"Checked Dockerfiles/compose for secrets in ARG/ENV/COPY layers, and .dockerignore coverage",
		"Checked IaC for plaintext secrets, overly broad IAM, and secrets that should come from a manager",
		"Checked CORS, cookie and security-header configuration for permissive production settings",
		"Checked .env.example / sample configs for real values and .gitignore coverage of local env files",
	],
	instructions: compose(
		`# Secrets & configuration review

## Scope

How the project **handles** secrets and security-relevant configuration across application code, build tooling, CI/CD, containers and infrastructure-as-code. Regex scanners (openaudit \`code.secrets\`, gitleaks) already flag literal key patterns; focus on what needs reasoning: where secrets flow, what is exposed at runtime, and which settings are unsafe *in production*.

## Method

1. **Inventory configuration.** Find how config is loaded (\`process.env\`, dotenv, \`import.meta.env\`, pydantic settings, Viper, Spring profiles, Rails credentials, varlock/zod env schemas, Kubernetes ConfigMaps/Secrets, SSM/Secrets Manager/Vault/Doppler). List the secrets the app needs (DB URLs, API keys, signing keys, OAuth client secrets, webhook secrets).
2. **Hard-coded and defaulted secrets.** Look for secrets committed in source, config files, fixtures, notebooks, docker-compose files and IaC variables — and for code like \`process.env.JWT_SECRET ?? "dev-secret"\` where a missing env var silently falls back to a known value in production.
3. **Secrets in logs and responses.** Follow secrets and credential-bearing objects (request headers, config objects, DB connection strings, user records with password hashes/tokens) into loggers, error handlers, \`console.log\`, APM/analytics events, exception messages returned to clients and debug endpoints. Check request-logging middleware for \`Authorization\`/\`Cookie\` headers and body logging on auth routes.
4. **Client exposure.** Identify env vars and config bundled into client code (framework public prefixes, \`define\` in bundler config, values serialised into HTML/\`__NEXT_DATA__\`/initial state). Verify none is a server secret (service-role keys, secret API keys, private signing keys). Check whether production source maps are publicly served.
5. **Debug and unsafe production modes.** \`DEBUG=True\`, \`NODE_ENV\` not set to production, verbose error pages, GraphQL introspection/playground, Swagger UI, actuator/admin endpoints, profilers, test routes, feature flags that disable auth, permissive CORS (\`*\` with credentials, reflected origins), insecure cookie settings in production config, TLS verification disabled (\`rejectUnauthorized: false\`, \`verify=False\`).
6. **CI/CD.** In GitHub Actions/GitLab CI/etc.: \`pull_request_target\` or \`workflow_run\` that check out untrusted code with secrets available; \`\${{ github.event.* }}\` interpolated into \`run:\` (script injection); secrets echoed, written to artifacts or caches; secrets passed to unpinned third-party actions; \`permissions\` broader than needed (\`write-all\`, default token write); long-lived cloud keys instead of OIDC.
7. **Containers.** Secrets in \`ARG\`/\`ENV\`, \`COPY . .\` without a \`.dockerignore\` that excludes \`.env\`, keys, \`.git\`; secrets added then deleted in a later layer (still in history); build secrets not using BuildKit \`--mount=type=secret\`; compose files with real credentials.
8. **Infrastructure.** Plaintext secrets in Terraform variables/defaults/tfvars, Kubernetes manifests (Secret objects committed with real data, env values), Helm values; secrets that should come from a secret manager; IAM policies/roles attached to app workloads that are broader than the code needs (\`*:*\`, \`s3:*\` on \`*\`, cluster-admin bindings).

## Severity rubric

- **critical** — a live production secret is exposed publicly (client bundle, public repo history, public image layer) or authentication can be bypassed via a known default secret.
- **high** — secrets logged in production, CI workflow that exposes secrets to untrusted pull requests, debug mode / stack traces enabled in production config, wildcard IAM on a workload, TLS verification disabled for production traffic.
- **medium** — insecure defaults that only apply when misconfigured, secrets baked into private images, broad CI token permissions, permissive CORS without credentials, public source maps.
- **low** — hygiene: missing \`.dockerignore\` entries, example configs with realistic-looking placeholders, missing env validation.
- **info** — suggestions such as moving to OIDC or a secret manager where nothing is currently exposed.

## What NOT to report

- Literal key matches already reported by secret scanners unless you add new information (e.g. the key is shipped to clients or is a known-valid production key).
- Obvious placeholders (\`changeme\`, \`xxx\`, \`your-key-here\`) in \`.env.example\`, docs or tests.
- Local-development-only config (docker-compose for local DB with default password, \`.env.development\`) unless it is used in production.
- Public identifiers that are designed to be public (Stripe publishable keys, Firebase web config, Supabase anon key with RLS, OAuth client ids, Sentry DSNs).`,
		REPORTING,
	),
};
