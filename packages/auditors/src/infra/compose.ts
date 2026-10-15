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

/** Repository-relative path of a compose file. */
type FilePath = string;
/** Raw compose file contents. */
type FileText = string;
/** Keys and indexes below a service, e.g. `["ports", 0]`. */
type ServicePath = Array<string | number>;

/** One service of a compose document, with what is needed to locate its keys. */
interface Service {
	readonly file: FilePath;
	readonly doc: YamlDoc;
	readonly name: string;
	readonly svc: Record<string, unknown>;
}

type ServiceRule = (service: Service) => FindingInput[];

/** A finding located at `path` below the service. */
const at = (
	{ file, doc, name }: Service,
	path: ServicePath,
	finding: Omit<FindingInput, "location">,
): FindingInput => ({
	location: { file, line: doc.lineOf(["services", name, ...path]) },
	...finding,
});

const privilegedFindings: ServiceRule = (service) =>
	service.svc.privileged === true
		? [
				at(service, ["privileged"], {
					ruleId: "container.compose/privileged",
					title: "Privileged container",
					severity: "high",
					category: "security",
					message: `Service \`${service.name}\` runs privileged, giving it full access to host devices and disabling most isolation.`,
					remediation:
						"Remove `privileged: true`; grant only the specific capabilities or devices needed.",
					evidence: "privileged: true",
					references: [COMPOSE_SPEC, CIS_DOCKER],
					tags: ["cis-docker-5.4", "cwe-250"],
				}),
			]
		: [];

/** Host namespaces a service can join, with how each is reported. */
const HOST_NAMESPACES = [
	{
		key: "network_mode",
		rule: "network-mode-host",
		severity: "medium",
		label: "network",
		remediationSuffix: " with published ports",
		tag: "cis-docker-5.10",
	},
	{
		key: "pid",
		rule: "pid-host",
		severity: "high",
		label: "PID",
		remediationSuffix: "",
		tag: "cis-docker-5.16",
	},
	{
		key: "ipc",
		rule: "ipc-host",
		severity: "medium",
		label: "IPC",
		remediationSuffix: "",
		tag: "cis-docker-5.17",
	},
] as const;

const hostNamespaceFindings: ServiceRule = (service) =>
	HOST_NAMESPACES.filter(({ key }) => service.svc[key] === "host").map(
		({ key, rule, severity, label, remediationSuffix, tag }) =>
			at(service, [key], {
				ruleId: `container.compose/${rule}`,
				title: `Host ${label} namespace shared`,
				severity,
				category: "security",
				message: `Service \`${service.name}\` uses \`${key}: host\`, removing ${label} isolation from the host.`,
				remediation: `Remove \`${key}: host\` and use the default isolated namespace${remediationSuffix}.`,
				evidence: `${key}: host`,
				references: [COMPOSE_SPEC, CIS_DOCKER],
				tags: [tag],
			}),
	);

const DOCKER_SOCKET_RE = /(^|\/)(var\/)?run\/docker\.sock$|docker\.sock$/;

const dockerSocketFindings: ServiceRule = (service) =>
	asArray(service.svc.volumes).flatMap((v, i) => {
		const source = volumeSource(v);
		if (!DOCKER_SOCKET_RE.test(source)) return [];
		return [
			at(service, ["volumes", i], {
				ruleId: "container.compose/docker-socket",
				title: "Docker socket mounted into container",
				severity: "high",
				category: "security",
				message: `Service \`${service.name}\` mounts the Docker socket, which is equivalent to root on the host.`,
				remediation:
					"Avoid mounting the socket; if unavoidable, use a filtering proxy (e.g. docker-socket-proxy) with read-only, minimal API access.",
				evidence: source,
				references: [OWASP_DOCKER, CIS_DOCKER],
				tags: ["cis-docker-5.31", "cwe-250"],
			}),
		];
	});

const isDangerousCapability = (cap: string) =>
	CRITICAL_CAPS.has(cap) || RISKY_CAPS.has(cap);

const capabilityFindings: ServiceRule = (service) =>
	asArray(service.svc.cap_add).flatMap((c, i) => {
		const cap = String(c).toUpperCase().replace(/^CAP_/, "");
		if (!isDangerousCapability(cap)) return [];
		return [
			at(service, ["cap_add", i], {
				ruleId: "container.compose/dangerous-capability",
				title: `Dangerous capability ${cap} added`,
				severity: CRITICAL_CAPS.has(cap) ? "high" : "medium",
				category: "security",
				message: `Service \`${service.name}\` adds \`${cap}\`, which enables container escape or host interference.`,
				remediation:
					"Drop the capability; add only narrowly scoped ones (and `cap_drop: [ALL]`).",
				evidence: `cap_add: ${cap}`,
				references: [CIS_DOCKER, OWASP_DOCKER],
				tags: ["cis-docker-5.3", "cwe-250"],
			}),
		];
	});

const unconfinedProfileFindings: ServiceRule = (service) =>
	asArray(service.svc.security_opt).flatMap((o, i) => {
		const opt = String(o);
		const m = /^(seccomp|apparmor)[:=]unconfined$/i.exec(opt);
		if (!m) return [];
		const profile = m[1];
		return [
			at(service, ["security_opt", i], {
				ruleId: `container.compose/${(profile ?? "").toLowerCase()}-unconfined`,
				title: `${profile} profile disabled`,
				severity: profile?.toLowerCase() === "seccomp" ? "high" : "medium",
				category: "security",
				message: `Service \`${service.name}\` disables the default ${profile} profile, exposing the full kernel syscall surface.`,
				remediation: `Remove \`${opt}\` or supply a custom profile allowing only the needed syscalls.`,
				evidence: opt,
				references: [
					"https://docs.docker.com/engine/security/seccomp/",
					CIS_DOCKER,
				],
				tags: ["cis-docker-5.21"],
			}),
		];
	});

type EnvEntry = ReturnType<typeof envEntries>[number];

/** A secret-named variable set to a literal (non-placeholder) value. */
const isLiteralSecret = (
	entry: EnvEntry,
): entry is EnvEntry & { value: string } =>
	SECRET_NAME_RE.test(entry.key) &&
	entry.value !== undefined &&
	!isPlaceholderValue(entry.value);

const plaintextSecretFindings: ServiceRule = (service) =>
	envEntries(service.svc.environment)
		.filter(isLiteralSecret)
		.map(({ key, value, index }) =>
			at(service, ["environment", index], {
				ruleId: "container.compose/plaintext-secret",
				title: "Plaintext secret in environment",
				severity: "high",
				category: "security",
				message: `Service \`${service.name}\` sets \`${key}\` to a literal value in the compose file.`,
				remediation:
					"Interpolate it from an untracked `.env` file (`$VAR`) or use Compose `secrets:`; rotate the exposed value.",
				evidence: `${key}=${redact(value)}`,
				references: ["https://docs.docker.com/compose/how-tos/use-secrets/"],
				tags: ["cwe-798"],
			}),
		);

const isLoopback = (hostIp: string | undefined) =>
	hostIp !== undefined && hostIp !== "" && LOOPBACK_RE.test(hostIp);

const databasePortFindings: ServiceRule = (service) =>
	asArray(service.svc.ports).flatMap((p, i) => {
		const { hostIp, container } = parsePort(p);
		const db = container === undefined ? undefined : DATABASE_PORTS[container];
		if (!db || isLoopback(hostIp)) return [];
		return [
			at(service, ["ports", i], {
				ruleId: "container.compose/database-port-exposed",
				title: `${db} port published on all interfaces`,
				severity: "medium",
				category: "security",
				message: `Service \`${service.name}\` publishes ${db} port ${container} on ${hostIp ?? "all interfaces"}; Docker bypasses host firewalls such as ufw.`,
				remediation: `Bind to loopback (\`127.0.0.1:${container}:${container}\`) or drop the port mapping and use the internal network.`,
				evidence: typeof p === "object" ? JSON.stringify(p) : String(p),
				references: [
					"https://docs.docker.com/engine/network/packet-filtering-firewalls/",
					COMPOSE_SPEC,
				],
				tags: ["cwe-668"],
			}),
		];
	});

/** The service's pulled image, unless it is built locally or interpolated. */
const pulledImage = (svc: Record<string, unknown>): string | undefined => {
	if (typeof svc.image !== "string") return undefined;
	if (svc.build !== undefined) return undefined;
	return svc.image.includes("$") ? undefined : svc.image;
};

const mutableImageFindings: ServiceRule = (service) => {
	const image = pulledImage(service.svc);
	if (image === undefined) return [];
	if (!isMutableTag(parseImageRef(image))) return [];
	return [
		at(service, ["image"], {
			ruleId: "container.compose/image-latest",
			title: "Image uses a mutable tag",
			severity: "medium",
			category: "supply-chain",
			message: `Service \`${service.name}\` uses \`${image}\`, which resolves to whatever \`latest\` points to at pull time.`,
			remediation: "Pin a version tag (and ideally a digest).",
			evidence: `image: ${image}`,
			references: [COMPOSE_SPEC],
			tags: ["cwe-1357"],
		}),
	];
};

const hasRestartPolicy = (svc: Record<string, unknown>) =>
	svc.restart !== undefined ||
	asRecord(svc.deploy)?.restart_policy !== undefined;

const restartFindings: ServiceRule = (service) =>
	hasRestartPolicy(service.svc)
		? []
		: [
				at(service, [], {
					ruleId: "container.compose/restart-missing",
					title: "No restart policy",
					severity: "low",
					category: "reliability",
					message: `Service \`${service.name}\` has no \`restart\` policy and will stay down after a crash or host reboot.`,
					remediation: "Add `restart: unless-stopped` (or `on-failure`).",
					references: [`${COMPOSE_SPEC}#restart`],
				}),
			];

const healthcheckFindings: ServiceRule = (service) =>
	service.svc.healthcheck === undefined
		? [
				at(service, [], {
					ruleId: "container.compose/healthcheck-missing",
					title: "No healthcheck",
					severity: "low",
					category: "reliability",
					message: `Service \`${service.name}\` defines no healthcheck (the image may define one); \`depends_on\` cannot wait for it to become healthy.`,
					remediation: "Add a `healthcheck:` with a cheap readiness command.",
					confidence: "medium",
					references: [`${COMPOSE_SPEC}#healthcheck`],
				}),
			]
		: [];

/** Service checks, in reporting order. */
const SERVICE_RULES: ReadonlyArray<ServiceRule> = [
	privilegedFindings,
	hostNamespaceFindings,
	dockerSocketFindings,
	capabilityFindings,
	unconfinedProfileFindings,
	plaintextSecretFindings,
	databasePortFindings,
	mutableImageFindings,
	restartFindings,
	healthcheckFindings,
];

const auditService = (service: Service): FindingInput[] =>
	SERVICE_RULES.flatMap((rule) => rule(service));

/** The document's services that are mappings. */
const servicesOf = (file: FilePath, doc: YamlDoc): Service[] => {
	const services = asRecord(asRecord(doc.value)?.services);
	if (!services) return [];
	return Object.entries(services).flatMap(([name, value]) => {
		const svc = asRecord(value);
		return svc ? [{ file, doc, name, svc }] : [];
	});
};

/** Audits one compose file's text. Exported for tests. */
export const auditCompose = (file: FilePath, text: FileText): FindingInput[] =>
	parseYaml(text)
		.docs.flatMap((doc) => servicesOf(file, doc))
		.flatMap(auditService);

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
