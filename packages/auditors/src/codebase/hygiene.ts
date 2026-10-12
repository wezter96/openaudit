import {
	defineAuditor,
	type FindingInput,
	requireWorkspace,
} from "@openaudit/core";
import { Effect } from "effect";

/** Repository essentials: docs, licence, security policy, ignore rules, CI, lockfile. */
export const hygiene = defineAuditor({
	id: "code.hygiene",
	title: "Repository hygiene",
	description:
		"Checks for README, LICENSE, SECURITY.md, .gitignore coverage of secrets, lockfiles and CI configuration.",
	categories: ["best-practices", "maintainability", "security"],
	targets: ["codebase"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const ws = yield* requireWorkspace(ctx);
			const files = yield* ws.files;
			const has = (re: RegExp) => files.some((f) => re.test(f));
			const findings: FindingInput[] = [];

			if (!has(/^readme(\.\w+)?$/i))
				findings.push({
					ruleId: "code.hygiene/readme-missing",
					title: "README is missing",
					severity: "low",
					category: "maintainability",
					message: "The repository has no README at its root.",
					remediation: "Add a README.md describing purpose, setup and usage.",
				});

			if (!has(/^(licen[cs]e|copying)(\.\w+)?$/i))
				findings.push({
					ruleId: "code.hygiene/license-missing",
					title: "LICENSE is missing",
					severity: "low",
					category: "compliance",
					message:
						"No LICENSE file found; others cannot legally reuse the code.",
					remediation: "Add a LICENSE file (e.g. MIT, Apache-2.0).",
					references: ["https://choosealicense.com/"],
				});

			if (!has(/^(\.github\/)?security\.md$/i))
				findings.push({
					ruleId: "code.hygiene/security-policy-missing",
					title: "No security policy",
					severity: "info",
					category: "security",
					message:
						"No SECURITY.md telling researchers how to report vulnerabilities.",
					remediation: "Add SECURITY.md with a contact and disclosure process.",
					references: [
						"https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository",
					],
				});

			const gitignore = files.includes(".gitignore")
				? yield* ws.readText(".gitignore")
				: undefined;
			if (gitignore === undefined) {
				findings.push({
					ruleId: "code.hygiene/gitignore-missing",
					title: ".gitignore is missing",
					severity: "medium",
					category: "security",
					message:
						"Without a .gitignore, secrets and build output are easily committed.",
					remediation:
						"Add a .gitignore that excludes .env files, dependencies and build output.",
					location: { file: ".gitignore" },
				});
			} else if (
				!/^\s*\/?\.env/m.test(gitignore) &&
				!/^\s*\*\.env/m.test(gitignore)
			) {
				findings.push({
					ruleId: "code.hygiene/env-not-ignored",
					title: ".env files are not git-ignored",
					severity: "medium",
					category: "security",
					message:
						".gitignore does not exclude .env files, which commonly hold secrets.",
					remediation: "Add `.env` and `.env*.local` to .gitignore.",
					location: { file: ".gitignore" },
				});
			}

			if (
				files.includes("package.json") &&
				!has(/^(bun\.lockb?|package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/)
			)
				findings.push({
					ruleId: "code.hygiene/lockfile-missing",
					title: "No dependency lockfile",
					severity: "medium",
					category: "supply-chain",
					message:
						"package.json exists but no lockfile is committed, so installs are not reproducible.",
					remediation: "Commit the lockfile produced by your package manager.",
					location: { file: "package.json" },
				});

			if (
				!has(
					/^\.github\/workflows\/.+\.ya?ml$|^\.gitlab-ci\.yml$|^\.circleci\/|^azure-pipelines\.yml$|^Jenkinsfile$|^bitbucket-pipelines\.yml$/,
				)
			)
				findings.push({
					ruleId: "code.hygiene/ci-missing",
					title: "No CI configuration",
					severity: "info",
					category: "reliability",
					message: "No continuous-integration configuration was found.",
					remediation:
						"Run tests, linting and `openaudit --fail-on high` in CI.",
				});

			return findings;
		}),
});
