import { posix } from "node:path";
import {
	defineAuditor,
	type FindingInput,
	redact,
	skip,
	type Workspace,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	isMutableTag,
	isPlaceholderValue,
	parseImageRef,
	readOptional,
	SECRET_NAME_RE,
	targetFiles,
} from "./shared";

export const DOCKERFILE_RE =
	/(^|\/)(Dockerfile|Containerfile)(\.(?!dockerignore$)[\w.-]+)?$|\.dockerfile$/i;

const BEST_PRACTICES = "https://docs.docker.com/build/building/best-practices/";
const CIS_DOCKER = "https://www.cisecurity.org/benchmark/docker";

export interface Instruction {
	/** Upper-cased instruction keyword, e.g. `RUN`. */
	readonly keyword: string;
	/** Arguments with line continuations joined (and heredoc bodies appended). */
	readonly args: string;
	/** 1-based line where the instruction starts. */
	readonly line: number;
	/** First source line, trimmed, for evidence. */
	readonly source: string;
}

export interface Stage {
	readonly from: Instruction;
	readonly image: string;
	readonly alias: string | undefined;
	readonly instructions: ReadonlyArray<Instruction>;
}

/** Parses a Dockerfile into instructions, honouring `# escape=` and continuations. */
export const parseDockerfile = (text: string): Instruction[] => {
	const lines = text.split(/\r?\n/);
	const escapeMatch = /^#\s*escape\s*=\s*(\S)/i.exec(lines[0] ?? "");
	const escapeChar = escapeMatch?.[1] ?? "\\";
	const out: Instruction[] = [];
	let i = 0;
	while (i < lines.length) {
		const first = lines[i] ?? "";
		const trimmed = first.trim();
		const start = i;
		i++;
		if (trimmed === "" || trimmed.startsWith("#")) continue;
		let joined = "";
		let current = first;
		for (;;) {
			const end = current.trimEnd();
			if (!end.endsWith(escapeChar)) {
				joined += current;
				break;
			}
			joined += `${end.slice(0, -1)} `;
			// Comment and blank lines inside a continuation are dropped by Docker.
			while (i < lines.length && /^\s*(#.*)?$/.test(lines[i] ?? "")) i++;
			if (i >= lines.length) break;
			current = lines[i] ?? "";
			i++;
		}
		const m = /^\s*(\w+)\s*(.*)$/s.exec(joined);
		if (!m) continue;
		const keyword = (m[1] ?? "").toUpperCase();
		let args = (m[2] ?? "").trim();
		const heredoc = /<<-?\s*["']?(\w+)["']?/.exec(args);
		if (heredoc && (keyword === "RUN" || keyword === "COPY")) {
			const terminator = heredoc[1];
			const body: string[] = [];
			while (i < lines.length && (lines[i] ?? "").trim() !== terminator) {
				body.push(lines[i] ?? "");
				i++;
			}
			i++;
			args += `\n${body.join("\n")}`;
		}
		const source = trimmed.length > 160 ? `${trimmed.slice(0, 160)}…` : trimmed;
		out.push({ keyword, args, line: start + 1, source });
	}
	return out;
};

/** Groups instructions into build stages (instructions before FROM are dropped). */
export const toStages = (instructions: ReadonlyArray<Instruction>): Stage[] => {
	const stages: Stage[] = [];
	let current: { from: Instruction; list: Instruction[] } | undefined;
	const flush = () => {
		if (!current) return;
		const tokens = current.from.args
			.split(/\s+/)
			.filter((t) => t && !t.startsWith("--"));
		stages.push({
			from: current.from,
			image: tokens[0] ?? "",
			alias:
				tokens[1]?.toLowerCase() === "as"
					? tokens[2]?.toLowerCase()
					: undefined,
			instructions: current.list,
		});
	};
	for (const ins of instructions) {
		if (ins.keyword === "FROM") {
			flush();
			current = { from: ins, list: [] };
		} else current?.list.push(ins);
	}
	flush();
	return stages;
};

/** `KEY=value KEY2="v"` or legacy `KEY value` pairs of ENV/ARG/LABEL. */
const keyValues = (
	args: string,
): Array<{ key: string; value: string | undefined }> => {
	if (!/^[\w.-]+=/.test(args)) {
		const [key = "", ...rest] = args.split(/\s+/);
		return [{ key, value: rest.length ? rest.join(" ") : undefined }];
	}
	const out: Array<{ key: string; value: string | undefined }> = [];
	const re = /([\w.-]+)(?:=("(?:[^"\\]|\\.)*"|'[^']*'|\S*))?/g;
	for (const m of args.matchAll(re)) {
		out.push({ key: m[1] ?? "", value: m[2]?.replace(/^["']|["']$/g, "") });
	}
	return out;
};

const ARCHIVE_RE = /\.(tar|tar\.gz|tgz|tar\.bz2|tbz2?|tar\.xz|txz|tar\.zst)$/i;
const PIPE_TO_SHELL_RE =
	/\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+(-\S+\s+)*)?(ba|z|da|k|a)?sh\b/;
const BUILD_TOOLS_RE =
	/\b(apt-get|apt|apk|yum|dnf|microdnf)\b[^;&|]*\b(install|add)\b[^;&|]*\b(build-essential|build-base|gcc|g\+\+|clang|make|cmake|autoconf|golang|maven|gradle|rustc|cargo)\b/;
const BUILD_STEP_RE =
	/\b(go build|cargo build|mvn (-\S+\s+)*(package|install)|gradle(w)? (build|assemble)|(npm|yarn|pnpm|bun) (run )?build|dotnet publish|tsc\b)/;
const IGNORE_ENTRIES = [".git", ".env", "node_modules"] as const;

/** Dockerignore patterns (non-negated) that exclude `name` at the context root. */
const ignores = (dockerignore: string, name: string): boolean =>
	dockerignore
		.split(/\r?\n/)
		.map((l) => l.trim())
		.filter((l) => l && !l.startsWith("#") && !l.startsWith("!"))
		.map((l) => l.replace(/^\/+|\/+$/g, ""))
		.some((pattern) => {
			if (pattern === "*" || pattern === "**") return true;
			try {
				return (
					new Bun.Glob(pattern).match(name) ||
					new Bun.Glob(pattern).match(`${name}/x`)
				);
			} catch {
				return false;
			}
		});

const findDockerignore = (ws: Workspace, file: string) =>
	Effect.gen(function* () {
		const dir = posix.dirname(file);
		const candidates = [
			`${file}.dockerignore`,
			posix.join(dir, ".dockerignore"),
			".dockerignore",
		];
		for (const candidate of candidates) {
			if (yield* ws.exists(candidate)) {
				const text = yield* readOptional(ws, candidate);
				if (text !== undefined) return { path: candidate, text };
			}
		}
		return undefined;
	});

/** Audits one Dockerfile's text. Exported for tests. */
export const auditDockerfile = (
	file: string,
	text: string,
	context: {
		readonly dockerignore?: { readonly path: string; readonly text: string };
		readonly hasPackageJson?: boolean;
	} = {},
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const at = (ins: Instruction) => ({ file, line: ins.line });
	const stages = toStages(parseDockerfile(text));
	if (stages.length === 0) return findings;
	const aliases = new Set(stages.flatMap((s) => (s.alias ? [s.alias] : [])));

	for (const stage of stages) {
		const image = stage.image;
		if (
			image &&
			image.toLowerCase() !== "scratch" &&
			!aliases.has(image.toLowerCase()) &&
			!image.includes("$")
		) {
			const ref = parseImageRef(image);
			if (isMutableTag(ref))
				findings.push({
					ruleId: "container.dockerfile/from-latest",
					title: "Base image uses a mutable tag",
					severity: "medium",
					category: "supply-chain",
					message: `\`FROM ${image}\` ${ref.tag ? "uses `:latest`" : "has no tag (implicitly `:latest`)"}, so builds are not reproducible and can silently pick up breaking or compromised images.`,
					remediation:
						"Pin a specific version tag, ideally with a digest: `FROM node:22.11-alpine@sha256:…`.",
					location: at(stage.from),
					evidence: stage.from.source,
					references: [BEST_PRACTICES, CIS_DOCKER],
					tags: ["cis-docker-4.2", "cwe-1357"],
				});
			else if (!ref.digest)
				findings.push({
					ruleId: "container.dockerfile/from-unpinned-digest",
					title: "Base image not pinned by digest",
					severity: "low",
					category: "supply-chain",
					message: `\`FROM ${image}\` is pinned by tag only; tags can be re-pushed to point at different content.`,
					remediation:
						"Append the image digest (`@sha256:…`) and update it with Dependabot or Renovate.",
					location: at(stage.from),
					evidence: stage.from.source,
					references: [
						"https://docs.docker.com/reference/dockerfile/#from",
						BEST_PRACTICES,
					],
					tags: ["cwe-1357"],
				});
		}

		for (const ins of stage.instructions) {
			const args = ins.args;
			const base = { location: at(ins), evidence: ins.source };
			switch (ins.keyword) {
				case "ADD": {
					const tokens = args.split(/\s+/).filter((t) => !t.startsWith("--"));
					const sources = tokens.slice(0, -1);
					const hasChecksum = /--checksum=/.test(args);
					if (sources.some((s) => /^https?:\/\//i.test(s))) {
						if (!hasChecksum)
							findings.push({
								...base,
								ruleId: "container.dockerfile/add-remote-url",
								title: "ADD downloads a remote file without verification",
								severity: "medium",
								category: "supply-chain",
								message:
									"`ADD <url>` fetches content at build time without integrity verification.",
								remediation:
									"Use `ADD --checksum=sha256:… <url>`, or download with curl and verify a checksum in a RUN step.",
								references: [
									"https://docs.docker.com/reference/dockerfile/#add---checksum",
									BEST_PRACTICES,
								],
								tags: ["cis-docker-4.9", "cwe-494"],
							});
					} else if (
						sources.length > 0 &&
						!sources.some((s) => ARCHIVE_RE.test(s) || /^git@|\.git$/.test(s))
					) {
						findings.push({
							...base,
							ruleId: "container.dockerfile/add-instead-of-copy",
							title: "ADD used where COPY suffices",
							severity: "low",
							category: "best-practices",
							message:
								"`ADD` has implicit behaviour (archive extraction, URL fetching); `COPY` is explicit and safer for local files.",
							remediation: "Replace `ADD` with `COPY` for local files.",
							references: [BEST_PRACTICES],
							tags: ["cis-docker-4.9"],
						});
					}
					break;
				}
				case "RUN": {
					const cacheMount = /--mount=type=cache/.test(args);
					if (PIPE_TO_SHELL_RE.test(args))
						findings.push({
							...base,
							ruleId: "container.dockerfile/curl-pipe-shell",
							title: "Remote script piped into a shell",
							severity: "high",
							category: "security",
							message:
								"A script is downloaded and executed in one step without integrity verification; a compromised server or MITM yields code execution in the build.",
							remediation:
								"Download to a file, verify its checksum or signature, then execute it — or use a package manager.",
							references: [
								"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
							],
							tags: ["cwe-494", "owasp-a08"],
						});
					if (/\bapt-get\s+(?:-\S+\s+)*install\b/.test(args)) {
						if (!/--no-install-recommends/.test(args))
							findings.push({
								...base,
								ruleId: "container.dockerfile/apt-no-install-recommends",
								title: "apt-get install without --no-install-recommends",
								severity: "low",
								category: "performance",
								message:
									"Recommended packages are installed too, enlarging the image and its attack surface.",
								remediation:
									"Use `apt-get install -y --no-install-recommends …`.",
								references: [BEST_PRACTICES],
							});
						if (
							!cacheMount &&
							!/rm\s+-[rf]+\s+[^;&|]*\/var\/lib\/apt\/lists/.test(args)
						)
							findings.push({
								...base,
								ruleId: "container.dockerfile/apt-cache-not-cleaned",
								title: "apt cache not cleaned",
								severity: "low",
								category: "performance",
								message:
									"The apt package lists remain in the layer, adding tens of megabytes.",
								remediation:
									"End the same RUN with `&& rm -rf /var/lib/apt/lists/*` (or use a BuildKit cache mount).",
								references: [BEST_PRACTICES],
							});
					}
					if (
						/\bapk\s+(?:-\S+\s+)*add\b/.test(args) &&
						!/--no-cache/.test(args) &&
						!cacheMount
					)
						findings.push({
							...base,
							ruleId: "container.dockerfile/apk-no-cache",
							title: "apk add without --no-cache",
							severity: "low",
							category: "performance",
							message: "The apk index is left in the image layer.",
							remediation: "Use `apk add --no-cache …`.",
							references: [BEST_PRACTICES],
						});
					if (/(^|[\s;&|(])sudo\s/.test(args))
						findings.push({
							...base,
							ruleId: "container.dockerfile/sudo",
							title: "sudo used in RUN",
							severity: "medium",
							category: "security",
							message:
								"`sudo` in images has unpredictable TTY and signal behaviour and implies a privileged user setup.",
							remediation:
								"Run privileged steps before switching `USER`, or use `gosu` in entrypoints.",
							references: [BEST_PRACTICES],
							tags: ["cwe-250"],
						});
					break;
				}
				case "ENV":
				case "ARG": {
					for (const { key, value } of keyValues(args)) {
						if (!SECRET_NAME_RE.test(key)) continue;
						if (value !== undefined && !isPlaceholderValue(value)) {
							findings.push({
								location: at(ins),
								evidence: `${ins.keyword} ${key}=${redact(value)}`,
								ruleId: `container.dockerfile/secret-in-${ins.keyword.toLowerCase()}`,
								title: `Secret hardcoded in ${ins.keyword}`,
								severity: "high",
								category: "security",
								message: `\`${key}\` is set to a literal value; it is stored in the image metadata and visible to anyone who can pull the image.`,
								remediation:
									"Remove the value, rotate the credential, and pass secrets at runtime or with BuildKit `RUN --mount=type=secret`.",
								references: [
									"https://docs.docker.com/build/building/secrets/",
									CIS_DOCKER,
								],
								tags: ["cis-docker-4.10", "cwe-798"],
							});
						} else if (ins.keyword === "ARG" && value === undefined) {
							findings.push({
								...base,
								ruleId: "container.dockerfile/secret-build-arg",
								title: "Secret passed as build argument",
								severity: "medium",
								category: "security",
								message: `Build argument \`${key}\` looks like a credential; build-arg values are recorded in the image history.`,
								remediation:
									"Use BuildKit secret mounts (`RUN --mount=type=secret,id=…`) instead of ARG.",
								references: ["https://docs.docker.com/build/building/secrets/"],
								tags: ["cwe-532"],
							});
						}
					}
					break;
				}
				case "EXPOSE":
					if (args.split(/\s+/).some((p) => /^22(\/tcp)?$/.test(p)))
						findings.push({
							...base,
							ruleId: "container.dockerfile/expose-ssh",
							title: "SSH port exposed",
							severity: "medium",
							category: "security",
							message:
								"Port 22 is exposed; running an SSH daemon in a container widens the attack surface.",
							remediation:
								"Remove sshd from the image and use `docker exec` / `kubectl exec` for access.",
							references: [CIS_DOCKER],
							tags: ["cis-docker-5.6"],
						});
					break;
			}
		}
	}

	const final = stages[stages.length - 1];
	if (final) {
		const users = final.instructions.filter((i) => i.keyword === "USER");
		const lastUser = users[users.length - 1];
		const userName = lastUser?.args.split(/\s+/)[0] ?? "";
		const nonrootBase = /nonroot|distroless.*:nonroot|chainguard/i.test(
			final.image,
		);
		const isRoot = lastUser
			? /^(root|0)(:(root|0))?$/.test(userName)
			: !nonrootBase && final.image.toLowerCase() !== "scratch";
		if (isRoot)
			findings.push({
				ruleId: "container.dockerfile/runs-as-root",
				title: "Container runs as root",
				severity: "medium",
				category: "security",
				message: lastUser
					? "The final stage explicitly switches to the root user."
					: "The final stage never sets `USER`, so the container runs as root; a breakout or RCE gets root inside the container.",
				remediation:
					"Create an unprivileged user and add `USER app` (or a numeric UID) to the final stage.",
				location: at(lastUser ?? final.from),
				evidence: (lastUser ?? final.from).source,
				references: [
					"https://docs.docker.com/reference/dockerfile/#user",
					CIS_DOCKER,
				],
				tags: ["cis-docker-4.1", "cwe-250"],
			});

		if (
			!final.instructions.some((i) => i.keyword === "HEALTHCHECK") &&
			final.image.toLowerCase() !== "scratch"
		)
			findings.push({
				ruleId: "container.dockerfile/healthcheck-missing",
				title: "No HEALTHCHECK",
				severity: "low",
				category: "reliability",
				message:
					"The image defines no HEALTHCHECK, so Docker cannot detect a hung process (orchestrators with their own probes may not need it).",
				remediation:
					"Add `HEALTHCHECK CMD …` or configure liveness probes in your orchestrator.",
				location: at(final.from),
				evidence: final.from.source,
				confidence: "medium",
				references: [
					"https://docs.docker.com/reference/dockerfile/#healthcheck",
				],
				tags: ["cis-docker-4.6"],
			});
	}

	const copyAll = stages
		.flatMap((s) => s.instructions)
		.find(
			(i) =>
				(i.keyword === "COPY" || i.keyword === "ADD") &&
				!/--from=/.test(i.args) &&
				i.args
					.split(/\s+/)
					.filter((t) => !t.startsWith("--"))
					.slice(0, -1)
					.some((s) => s === "." || s === "./"),
		);
	if (copyAll) {
		const di = context.dockerignore;
		if (!di)
			findings.push({
				ruleId: "container.dockerfile/copy-context-no-dockerignore",
				title: "Whole build context copied without .dockerignore",
				severity: "medium",
				category: "security",
				message:
					"`COPY . …` copies the entire build context, and there is no .dockerignore — `.env` files, `.git` history and local credentials end up in the image.",
				remediation:
					"Add a .dockerignore excluding at least `.git`, `.env*`, `node_modules` and build output, or copy only what is needed.",
				location: at(copyAll),
				evidence: copyAll.source,
				references: [
					"https://docs.docker.com/build/concepts/context/#dockerignore-files",
				],
				tags: ["cwe-538"],
			});
		else {
			const missing = IGNORE_ENTRIES.filter(
				(name) =>
					(name !== "node_modules" || context.hasPackageJson) &&
					!ignores(di.text, name),
			);
			if (missing.length)
				findings.push({
					ruleId: "container.dockerfile/dockerignore-incomplete",
					title: ".dockerignore misses sensitive paths",
					severity: missing.some((m) => m !== "node_modules")
						? "medium"
						: "low",
					category: "security",
					message: `\`COPY . …\` is used but ${di.path} does not exclude ${missing.map((m) => `\`${m}\``).join(", ")}.`,
					remediation: `Add ${missing.map((m) => (m === ".env" ? "`.env*`" : `\`${m}\``)).join(", ")} to ${di.path}.`,
					location: { file: di.path, line: 1 },
					evidence: copyAll.source,
					references: [
						"https://docs.docker.com/build/concepts/context/#dockerignore-files",
					],
					tags: ["cwe-538"],
				});
		}
	}

	const only = stages.length === 1 ? stages[0] : undefined;
	const buildStep = only?.instructions.find(
		(i) =>
			i.keyword === "RUN" &&
			(BUILD_TOOLS_RE.test(i.args) || BUILD_STEP_RE.test(i.args)),
	);
	if (buildStep)
		findings.push({
			ruleId: "container.dockerfile/single-stage-build",
			title: "Build toolchain shipped in the runtime image",
			severity: "info",
			category: "best-practices",
			message:
				"This single-stage build installs compilers or runs a build, so toolchains and sources end up in the final image.",
			remediation:
				"Use a multi-stage build: compile in a `builder` stage and `COPY --from=builder` only the artefacts into a slim runtime image.",
			location: at(buildStep),
			evidence: buildStep.source,
			references: ["https://docs.docker.com/build/building/multi-stage/"],
		});

	return findings;
};

/** Static analysis of Dockerfiles / Containerfiles. */
export const dockerfile = defineAuditor({
	id: "container.dockerfile",
	title: "Dockerfile security & best practices",
	description:
		"Checks Dockerfiles for mutable base images, root users, secrets in ENV/ARG, remote ADD, curl-pipe-sh, package-cache hygiene, missing HEALTHCHECK and unsafe COPY of the build context.",
	categories: ["security", "supply-chain", "best-practices", "performance"],
	targets: ["container"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, files } = yield* targetFiles(ctx, DOCKERFILE_RE);
			if (files.length === 0) return yield* skip("No Dockerfiles found");
			const findings: FindingInput[] = [];
			for (const file of files) {
				const text = yield* readOptional(ws, file);
				if (text === undefined) continue;
				const dockerignore = yield* findDockerignore(ws, file);
				const hasPackageJson = yield* ws.exists(
					posix.join(posix.dirname(file), "package.json"),
				);
				findings.push(
					...auditDockerfile(file, text, { dockerignore, hasPackageJson }),
				);
			}
			return findings;
		}),
});
