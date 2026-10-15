/**
 * The /badge/ sign-up: registers a repo through the badge JSON API, shows
 * the verification code and the one-time manage token, checks ownership on
 * request, then shows the embed snippets. Every value goes in as text.
 * Only the project id and its public code are remembered, never the token.
 */

interface Registration {
	readonly id: string;
	readonly site: string | null;
	readonly verification: {
		readonly code: string;
		readonly siteFile: string;
		readonly dnsName: string | null;
	};
	readonly manageToken?: string;
}

/** The project the visitor is working on. */
type Pending = Omit<Registration, "manageToken">;

/** A CSS selector inside <main>. */
type Selector = string;
/** Text shown to the visitor. */
type Message = string;
/** A path on this site's API. */
type ApiPath = string;
type ProjectId = string;
type ManageToken = string;
type Tone = "" | "ok" | "error";

const STORE = "openaudit-badge";

const root = document.querySelector<HTMLElement>("main");
const form = document.querySelector<HTMLFormElement>("[data-register]");

const find = <T extends HTMLElement = HTMLElement>(selector: Selector) =>
	root?.querySelector<T>(selector) ?? undefined;

const setText = (selector: Selector, text: Message) => {
	const el = find(selector);
	if (el) el.textContent = text;
};

const say = (selector: Selector, text: Message, tone: Tone = "") => {
	const el = find(selector);
	if (!el) return;
	el.textContent = text;
	el.dataset.tone = tone;
};

const show = (selector: Selector, visible: boolean) => {
	const el = find(selector);
	if (el) el.hidden = !visible;
};

const remember = (project: Pending) => {
	try {
		localStorage.setItem(STORE, JSON.stringify(project));
	} catch {}
};

const recall = (): Pending | undefined => {
	try {
		const saved = localStorage.getItem(STORE);
		return saved ? (JSON.parse(saved) as Pending) : undefined;
	} catch {
		return undefined;
	}
};

/** The API's error message, or a fallback for anything unexpected. */
const errorOf = async (res: Response) => {
	const body = (await res.json().catch(() => ({}))) as { message?: unknown };
	if (typeof body.message === "string") return body.message;
	return res.status === 429
		? "Too many tries. Wait a little and try again."
		: "That didn't work. Check the details and try again.";
};

const post = (path: ApiPath, body?: unknown) =>
	fetch(path, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: body === undefined ? null : JSON.stringify(body),
	});

const showSiteSteps = (project: Pending) => {
	const site = project.site;
	show("[data-site-steps]", site !== null);
	if (!site) return;
	setText(
		"[data-site-file]",
		new URL(project.verification.siteFile, site).href,
	);
	setText("[data-dns]", project.verification.dnsName ?? "");
};

const showVerify = (project: Pending, token?: ManageToken) => {
	setText("[data-code]", project.verification.code);
	showSiteSteps(project);
	show("[data-token-box]", token !== undefined);
	if (token) setText("[data-token]", token);
	show('[data-step="verify"]', true);
};

const showEmbed = (id: ProjectId) => {
	const origin = location.origin;
	const page = `${origin}/v/${id}`;
	const badge = `${origin}/badge/${id}.svg`;
	setText("[data-markdown]", `[![openaudit](${badge})](${page})`);
	setText(
		"[data-html]",
		`<a href="${page}"><img src="${badge}" alt="openaudit score"></a>`,
	);
	find<HTMLImageElement>("[data-preview]")?.setAttribute(
		"src",
		`/badge/${id}.svg`,
	);
	find<HTMLAnchorElement>("[data-page]")?.setAttribute("href", `/v/${id}`);
	show('[data-step="embed"]', true);
};

const register = async (event: SubmitEvent) => {
	event.preventDefault();
	if (!form) return;
	const data = new FormData(form);
	const repo = String(data.get("repo") ?? "").trim();
	const site = String(data.get("site") ?? "").trim();
	say("[data-status]", "Checking your repo on GitHub…");
	const res = await post("/api/badges", site ? { repo, site } : { repo });
	if (!res.ok) return say("[data-status]", await errorOf(res), "error");
	const { manageToken, ...project } = (await res.json()) as Registration;
	remember(project);
	say("[data-status]", "Signed up. Now prove it's yours.", "ok");
	showVerify(project, manageToken);
};

const verifyText = (result: { status: string; siteVerified: boolean }) => {
	if (result.status !== "active")
		return "We couldn't find the code in .openaudit-badge yet. Commit it to your default branch and try again in a minute.";
	return result.siteVerified
		? "Repo and site verified."
		: "Repo verified. The site isn't verified yet, so only the repo is scanned.";
};

const verify = async () => {
	const project = recall();
	if (!project) return;
	say("[data-verify-status]", "Checking…");
	const res = await post(
		`/api/badges/${encodeURIComponent(project.id)}/verify`,
	);
	if (!res.ok) return say("[data-verify-status]", await errorOf(res), "error");
	const result = (await res.json()) as {
		status: string;
		siteVerified: boolean;
	};
	const active = result.status === "active";
	say("[data-verify-status]", verifyText(result), active ? "ok" : "");
	if (active) showEmbed(project.id);
};

form?.addEventListener("submit", (event) => void register(event));
find("[data-verify]")?.addEventListener("click", () => void verify());

const saved = recall();
if (saved) showVerify(saved);

export {};
