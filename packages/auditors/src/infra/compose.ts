import {
	defineAuditor,
	type FindingInput,
	redact,
	skip,
} from "@openaudit/core";
import { Effect } from "effect";

import {
	asArray,
	asRecord,
	isMutableTag,
	isPlaceholderValue,
	parseImageRef,
	parseYaml,
	readOptional,
	SECRET_NAME_RE,
	targetFiles,
	type YamlDoc,
} from "./shared";

export const COMPOSE_RE = /(^|\/)(docker-)?compose(\.[\w-]+)?\.ya?ml$/;

const COMPOSE_SPEC = "https://docs.docker.com/reference/compose-file/services/";
const CIS_DOCKER = "https://www.cisecurity.org/benchmark/docker";
const OWASP_DOCKER =
	"https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html";

const DATABASE_PORTS: Record<number, string> = {
	5432: "PostgreSQL",
	3306: "MySQL/MariaDB",
	27017: "MongoDB",
	6379: "Redis",
	9200: "Elasticsearch",
	9300: "Elasticsearch",
	5984: "CouchDB",
	11211: "Memcached",
	1433: "SQL Server",
	9042: "Cassandra",
};
const LOOPBACK_RE = /^(127\.\d+\.\d+\.\d+|localhost|\[?::1\]?)$/;
const CRITICAL_CAPS = new Set(["ALL", "SYS_ADMIN"]);
const RISKY_CAPS = new Set([
	"SYS_PTRACE",
	"SYS_MODULE",
	"NET_ADMIN",
	"DAC_READ_SEARCH",
]);

interface PortBinding {
	readonly hostIp: string | undefined;
	readonly container: number | undefined;
}

/** Parses short (`127.0.0.1:5432:5432/tcp`) and long port syntax. */
export const parsePort = (entry: unknown): PortBinding => {
	const long = asRecord(entry);
	if (long)
		return {
			hostIp: long.host_ip === undefined ? undefined : String(long.host_ip),
			container: Number.parseInt(String(long.target ?? ""), 10) || undefined,
		};
	const spec = String(entry).replace(/\/(tcp|udp|sctp)$/, "");
	const ipv6 = /^\[([^\]]+)\]:(.*)$/.exec(spec);
	const parts = ipv6
		? [ipv6[1] ?? "", ...(ipv6[2] ?? "").split(":")]
		: spec.split(":");
	const containerPart = parts[parts.length - 1] ?? "";
	return {
		hostIp: parts.length === 3 ? parts[0] : undefined,
		container:
			Number.parseInt(containerPart.split("-")[0] ?? "", 10) || undefined,
	};
};

const envEntries = (
	env: unknown,
): Array<{
	key: string;
	value: string | undefined;
	index: string | number;
}> => {
	const map = asRecord(env);
	if (map)
		return Object.entries(map).map(([key, value]) => ({
			key,
			value: value === null || value === undefined ? undefined : String(value),
			index: key,
		}));
	return asArray(env).map((item, index) => {
		const s = String(item);
		const eq = s.indexOf("=");
		return eq === -1
			? { key: s, value: undefined, index }
			: { key: s.slice(0, eq), value: s.slice(eq + 1), index };
	});
};

const volumeSource = (v: unknown): string => {
	const long = asRecord(v);
	if (long) return String(long.source ?? "");
	return String(v).split(":")[0] ?? "";
};

const auditService = (
	file: string,
	doc: YamlDoc,
	name: string,
	svc: Record<string, unknown>,
): FindingInput[] => {
	const findings: FindingInput[] = [];
	const loc = (...path: Array<string | number>) => ({
		file,
		line: doc.lineOf(["services", name, ...path]),
	});
	const push = (
		f: Omit<FindingInput, "location"> & { path?: Array<string | number> },
	) => {
		const { path = [], ...rest } = f;
		findings.push({ location: loc(...path), ...rest });
	};

	if (svc.privileged === true)
		push({
			path: ["privileged"],
			ruleId: "container.compose/privileged",
			title: "Privileged container",
			severity: "high",
			category: "security",
			message: `Service \`${name}\` runs privileged, giving it full access to host devices and disabling most isolation.`,
			remediation:
				"Remove `privileged: true`; grant only the specific capabilities or devices needed.",
			evidence: "privileged: true",
			references: [COMPOSE_SPEC, CIS_DOCKER],
			tags: ["cis-docker-5.4", "cwe-250"],
		});

	for (const [key, rule, severity] of [
		["network_mode", "network-mode-host", "medium"],
		["pid", "pid-host", "high"],
		["ipc", "ipc-host", "medium"],
	] as const) {
		if (svc[key] === "host")
			push({
				path: [key],
				ruleId: `container.compose/${rule}`,
				title: `Host ${key === "network_mode" ? "network" : key.toUpperCase()} namespace shared`,
				severity,
				category: "security",
				message: `Service \`${name}\` uses \`${key}: host\`, removing ${key === "network_mode" ? "network" : key.toUpperCase()} isolation from the host.`,
				remediation: `Remove \`${key}: host\` and use the default isolated namespace${key === "network_mode" ? " with published ports" : ""}.`,
				evidence: `${key}: host`,
				references: [COMPOSE_SPEC, CIS_DOCKER],
				tags: [
					key === "pid"
						? "cis-docker-5.16"
						: key === "ipc"
							? "cis-docker-5.17"
							: "cis-docker-5.10",
				],
			});
	}

	asArray(svc.volumes).forEach((v, i) => {
		const source = volumeSource(v);
		if (/(^|\/)(var\/)?run\/docker\.sock$|docker\.sock$/.test(source))
			push({
				path: ["volumes", i],
				ruleId: "container.compose/docker-socket",
				title: "Docker socket mounted into container",
				severity: "high",
				category: "security",
				message: `Service \`${name}\` mounts the Docker socket, which is equivalent to root on the host.`,
				remediation:
					"Avoid mounting the socket; if unavoidable, use a filtering proxy (e.g. docker-socket-proxy) with read-only, minimal API access.",
				evidence: source,
				references: [OWASP_DOCKER, CIS_DOCKER],
				tags: ["cis-docker-5.31", "cwe-250"],
			});
	});

	asArray(svc.cap_add).forEach((c, i) => {
		const cap = String(c).toUpperCase().replace(/^CAP_/, "");
		if (CRITICAL_CAPS.has(cap) || RISKY_CAPS.has(cap))
			push({
				path: ["cap_add", i],
				ruleId: "container.compose/dangerous-capability",
				title: `Dangerous capability ${cap} added`,
				severity: CRITICAL_CAPS.has(cap) ? "high" : "medium",
				category: "security",
				message: `Service \`${name}\` adds \`${cap}\`, which enables container escape or host interference.`,
				remediation:
					"Drop the capability; add only narrowly scoped ones (and `cap_drop: [ALL]`).",
				evidence: `cap_add: ${cap}`,
				references: [CIS_DOCKER, OWASP_DOCKER],
				tags: ["cis-docker-5.3", "cwe-250"],
			});
	});

	asArray(svc.security_opt).forEach((o, i) => {
		const opt = String(o);
		const m = /^(seccomp|apparmor)[:=]unconfined$/i.exec(opt);
		if (m)
			push({
				path: ["security_opt", i],
				ruleId: `container.compose/${(m[1] ?? "").toLowerCase()}-unconfined`,
				title: `${m[1]} profile disabled`,
				severity: m[1]?.toLowerCase() === "seccomp" ? "high" : "medium",
				category: "security",
				message: `Service \`${name}\` disables the default ${m[1]} profile, exposing the full kernel syscall surface.`,
				remediation: `Remove \`${opt}\` or supply a custom profile allowing only the needed syscalls.`,
				evidence: opt,
				references: [
					"https://docs.docker.com/engine/security/seccomp/",
					CIS_DOCKER,
				],
				tags: ["cis-docker-5.21"],
			});
	});

	for (const { key, value, index } of envEntries(svc.environment)) {
		if (
			!SECRET_NAME_RE.test(key) ||
			value === undefined ||
			isPlaceholderValue(value)
		)
			continue;
		push({
			path: ["environment", index],
			ruleId: "container.compose/plaintext-secret",
			title: "Plaintext secret in environment",
			severity: "high",
			category: "security",
			message: `Service \`${name}\` sets \`${key}\` to a literal value in the compose file.`,
			remediation:
				"Interpolate it from an untracked `.env` file (`$VAR`) or use Compose `secrets:`; rotate the exposed value.",
			evidence: `${key}=${redact(value)}`,
			references: ["https://docs.docker.com/compose/how-tos/use-secrets/"],
			tags: ["cwe-798"],
		});
	}

	asArray(svc.ports).forEach((p, i) => {
		const { hostIp, container } = parsePort(p);
		const db = container === undefined ? undefined : DATABASE_PORTS[container];
		if (db && !(hostIp && LOOPBACK_RE.test(hostIp)))
			push({
				path: ["ports", i],
				ruleId: "container.compose/database-port-exposed",
				title: `${db} port published on all interfaces`,
				severity: "medium",
				category: "security",
				message: `Service \`${name}\` publishes ${db} port ${container} on ${hostIp ?? "all interfaces"}; Docker bypasses host firewalls such as ufw.`,
				remediation: `Bind to loopback (\`127.0.0.1:${container}:${container}\`) or drop the port mapping and use the internal network.`,
				evidence: typeof p === "object" ? JSON.stringify(p) : String(p),
				references: [
					"https://docs.docker.com/engine/network/packet-filtering-firewalls/",
					COMPOSE_SPEC,
				],
				tags: ["cwe-668"],
			});
	});

	if (
		typeof svc.image === "string" &&
		svc.build === undefined &&
		!svc.image.includes("$")
	) {
		if (isMutableTag(parseImageRef(svc.image)))
			push({
				path: ["image"],
				ruleId: "container.compose/image-latest",
				title: "Image uses a mutable tag",
				severity: "medium",
				category: "supply-chain",
				message: `Service \`${name}\` uses \`${svc.image}\`, which resolves to whatever \`latest\` points to at pull time.`,
				remediation: "Pin a version tag (and ideally a digest).",
				evidence: `image: ${svc.image}`,
				references: [COMPOSE_SPEC],
				tags: ["cwe-1357"],
			});
	}

	if (
		svc.restart === undefined &&
		asRecord(svc.deploy)?.restart_policy === undefined
	)
		push({
			ruleId: "container.compose/restart-missing",
			title: "No restart policy",
			severity: "low",
			category: "reliability",
			message: `Service \`${name}\` has no \`restart\` policy and will stay down after a crash or host reboot.`,
			remediation: "Add `restart: unless-stopped` (or `on-failure`).",
			references: [`${COMPOSE_SPEC}#restart`],
		});

	if (svc.healthcheck === undefined)
		push({
			ruleId: "container.compose/healthcheck-missing",
			title: "No healthcheck",
			severity: "low",
			category: "reliability",
			message: `Service \`${name}\` defines no healthcheck (the image may define one); \`depends_on\` cannot wait for it to become healthy.`,
			remediation: "Add a `healthcheck:` with a cheap readiness command.",
			confidence: "medium",
			references: [`${COMPOSE_SPEC}#healthcheck`],
		});

	return findings;
};

/** Audits one compose file's text. Exported for tests. */
export const auditCompose = (file: string, text: string): FindingInput[] => {
	const { docs } = parseYaml(text);
	const findings: FindingInput[] = [];
	for (const doc of docs) {
		const services = asRecord(asRecord(doc.value)?.services);
		if (!services) continue;
		for (const [name, svc] of Object.entries(services)) {
			const record = asRecord(svc);
			if (record) findings.push(...auditService(file, doc, name, record));
		}
	}
	return findings;
};

/** Static analysis of docker-compose files. */
export const compose = defineAuditor({
	id: "container.compose",
	title: "Docker Compose security",
	description:
		"Checks compose files for privileged services, host namespaces, Docker socket mounts, dangerous capabilities, plaintext secrets, exposed database ports, mutable image tags and missing restart/healthcheck.",
	categories: ["security", "supply-chain", "reliability"],
	targets: ["container"],
	engine: "builtin",
	run: (ctx) =>
		Effect.gen(function* () {
			const { ws, files } = yield* targetFiles(ctx, COMPOSE_RE);
			if (files.length === 0) return yield* skip("No compose files found");
			const findings: FindingInput[] = [];
			for (const file of files) {
				const text = yield* readOptional(ws, file);
				if (text !== undefined) findings.push(...auditCompose(file, text));
			}
			return findings;
		}),
});
