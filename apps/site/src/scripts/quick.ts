/**
 * The /audit/ form: queues a quick audit through /api/quick, polls it, then
 * shows the score and the report link. The audit id stays in the URL hash,
 * so a reload or a shared link picks the result up again. Every value goes
 * in as text.
 */

interface Summary {
	readonly score: number;
	readonly grade: string;
	readonly severities: Readonly<Record<string, number>>;
}

interface QuickState {
	readonly id: string;
	readonly site: string;
	readonly status: "queued" | "running" | "ok" | "failed";
	readonly ahead: number;
	readonly summary: Summary | null;
	readonly error: string | null;
}

type Tone = "" | "error";

const POLL_MS = 4000;
/** Stop polling after this long; the scanner fails an audit at 15 minutes. */
const GIVE_UP_MS = 16 * 60_000;
const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const root = document.querySelector<HTMLElement>("main");
const form = document.querySelector<HTMLFormElement>("[data-quick]");

const find = <T extends HTMLElement = HTMLElement>(selector: string) =>
	root?.querySelector<T>(selector) ?? undefined;

const setText = (selector: string, text: string) => {
	const el = find(selector);
	if (el) el.textContent = text;
};

const say = (text: string, tone: Tone = "") => {
	const el = find("[data-status]");
	if (!el) return;
	el.textContent = text;
	el.dataset.tone = tone;
};

const busy = (on: boolean) => {
	const button = form?.querySelector<HTMLButtonElement>("button");
	if (button) button.disabled = on;
};

const errorOf = async (res: Response) => {
	const body = (await res.json().catch(() => ({}))) as { message?: unknown };
	if (typeof body.message === "string") return body.message;
	return "That didn't work. Try again in a minute.";
};

const COUNTS = ["critical", "high", "medium", "low"] as const;

const countsText = (s: Summary) => {
	const parts = COUNTS.filter((k) => (s.severities[k] ?? 0) > 0).map(
		(k) => `${s.severities[k]} ${k}`,
	);
	return parts.length > 0
		? `Findings: ${parts.join(", ")}.`
		: "No findings above info.";
};

const showResult = (state: QuickState) => {
	const s = state.summary;
	if (!s) return;
	setText("[data-site]", state.site);
	setText("[data-score]", `${s.score}/100`);
	setText("[data-grade]", `grade ${s.grade}`);
	setText("[data-counts]", countsText(s));
	const link = find<HTMLAnchorElement>("[data-report]");
	if (link) link.href = `/q/${state.id}`;
	const result = find("[data-result]");
	if (result) result.hidden = false;
	say("");
};

const progress = (state: QuickState) =>
	state.status === "queued"
		? state.ahead > 0
			? `Waiting in line: ${state.ahead} ahead of you.`
			: "Starting soon…"
		: `Auditing ${state.site}… this takes about a minute.`;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const poll = async (id: string) => {
	const until = Date.now() + GIVE_UP_MS;
	while (Date.now() < until) {
		const res = await fetch(`/api/quick/${id}`).catch(() => undefined);
		if (res?.status === 404)
			return say("This audit has expired or doesn't exist.", "error");
		if (res?.ok) {
			const state = (await res.json()) as QuickState;
			if (state.status === "ok") return showResult(state);
			if (state.status === "failed")
				return say(
					`The audit failed: ${state.error ?? "unknown error"}.`,
					"error",
				);
			say(progress(state));
		}
		await sleep(POLL_MS);
	}
	say("This is taking too long. Reload the page to check again.", "error");
};

const follow = async (id: string) => {
	busy(true);
	try {
		await poll(id);
	} finally {
		busy(false);
	}
};

form?.addEventListener("submit", async (event) => {
	event.preventDefault();
	const site = new FormData(form).get("site")?.toString().trim() ?? "";
	if (!site) return say("Enter a website address.", "error");
	const result = find("[data-result]");
	if (result) result.hidden = true;
	busy(true);
	say("Queueing the audit…");
	const res = await fetch("/api/quick", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ site }),
	}).catch(() => undefined);
	if (!res) {
		busy(false);
		return say("We couldn't reach the server. Check your connection.", "error");
	}
	if (!res.ok) {
		busy(false);
		return say(await errorOf(res), "error");
	}
	const { id } = (await res.json()) as { id: string };
	history.replaceState(null, "", `#${id}`);
	await follow(id);
});

const fromHash = location.hash.slice(1);
if (ID.test(fromHash)) void follow(fromHash);

export {};
