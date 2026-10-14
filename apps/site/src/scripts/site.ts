/**
 * Behaviour shared by every page. Each piece enhances markup that already
 * works without it: buttons that need script start `hidden`, and content the
 * motion reveals is visible unless the `js` class is set.
 */

const root = document.documentElement;
export const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ---- theme: follows the system until the reader picks one ---- */
const dark = matchMedia("(prefers-color-scheme: dark)");
const themeButton = document.querySelector<HTMLButtonElement>(
	"[data-theme-toggle]",
);
const effective = () => root.dataset.theme ?? (dark.matches ? "dark" : "light");
const labelTheme = () => {
	if (!themeButton) return;
	themeButton.setAttribute(
		"aria-label",
		effective() === "dark" ? "Switch to light theme" : "Switch to dark theme",
	);
};
if (themeButton) {
	labelTheme();
	themeButton.addEventListener("click", () => {
		const next = effective() === "dark" ? "light" : "dark";
		// A choice that matches the system is no choice: keep following it.
		const system = dark.matches ? "dark" : "light";
		if (next === system) delete root.dataset.theme;
		else root.dataset.theme = next;
		try {
			if (next === system) localStorage.removeItem("theme");
			else localStorage.setItem("theme", next);
		} catch {
			/* storage blocked: the choice lasts for this page only */
		}
		labelTheme();
	});
	dark.addEventListener("change", labelTheme);
}

/* ---- menu on narrow screens ---- */
const menu = document.querySelector<HTMLButtonElement>("[data-menu]");
const nav = document.getElementById("site-nav");
if (menu && nav) {
	const set = (open: boolean) => {
		menu.setAttribute("aria-expanded", String(open));
		nav.classList.toggle("open", open);
	};
	menu.addEventListener("click", () =>
		set(menu.getAttribute("aria-expanded") !== "true"),
	);
	document.addEventListener("keydown", (e) => {
		if (e.key === "Escape" && nav.classList.contains("open")) {
			set(false);
			menu.focus();
		}
	});
}

/* ---- copy buttons: commands and code blocks ---- */
const flash = (button: HTMLElement, label?: HTMLElement | null) => {
	button.classList.add("copied");
	const before = label?.textContent;
	if (label) label.textContent = button.dataset.copiedLabel ?? "Copied";
	window.setTimeout(() => {
		button.classList.remove("copied");
		if (label && before) label.textContent = before;
	}, 1600);
};
const copy = async (text: string): Promise<boolean> => {
	try {
		await navigator.clipboard.writeText(text);
		return true;
	} catch {
		return false;
	}
};
for (const b of document.querySelectorAll<HTMLButtonElement>(
	"[data-copy-text]",
)) {
	b.addEventListener("click", async () => {
		if (await copy(b.dataset.copyText ?? "")) {
			flash(b, b.querySelector<HTMLElement>(".copy-label"));
		}
	});
}
for (const b of document.querySelectorAll<HTMLButtonElement>("[data-copy]")) {
	b.setAttribute("aria-label", "Copy code");
	b.addEventListener("click", async () => {
		const code = b.parentElement?.querySelector("code")?.textContent ?? "";
		if (await copy(code)) flash(b, b);
	});
}

/* ---- header: a hairline once the page scrolls; the compact grade once
   the hero dial has gone ---- */
const head = document.querySelector<HTMLElement>("[data-head]");
if (head) {
	const sentinel = document.createElement("div");
	sentinel.className = "sentinel";
	sentinel.setAttribute("aria-hidden", "true");
	document.body.prepend(sentinel);
	new IntersectionObserver(([e]) =>
		head.classList.toggle("stuck", !e?.isIntersecting),
	).observe(sentinel);
	const heroDial = document.querySelector("[data-dial]");
	const mini = head.querySelector<HTMLElement>("[data-mini]");
	if (heroDial && mini) {
		new IntersectionObserver(
			([e]) => {
				const gone = !e?.isIntersecting;
				head.classList.toggle("stuck-dial", gone);
				if (gone) mini.removeAttribute("tabindex");
				else mini.setAttribute("tabindex", "-1");
			},
			{ rootMargin: "-60px 0px 0px 0px" },
		).observe(heroDial);
	}
}

/* ---- sheets settle once, as they arrive ---- */
const sheets = document.querySelectorAll<HTMLElement>(".sheet, [data-arrive]");
/** Numbers in [data-count-to] count up from zero when their sheet arrives. */
const countUp = (el: HTMLElement) => {
	const to = Number(el.dataset.countTo) || 0;
	const t0 = performance.now();
	const frame = (t: number) => {
		const k = Math.min(1, (t - t0) / 1100);
		el.textContent = String(Math.round(to * (1 - (1 - k) ** 4)));
		if (k < 1) requestAnimationFrame(frame);
	};
	requestAnimationFrame(frame);
};
const arrive = (el: Element) => {
	el.classList.add("in");
	if (!still) {
		for (const n of el.querySelectorAll<HTMLElement>("[data-count-to]"))
			countUp(n);
	}
};
if (still || !("IntersectionObserver" in window)) {
	for (const s of sheets) arrive(s);
} else {
	const io = new IntersectionObserver(
		(entries) => {
			for (const e of entries) {
				if (!e.isIntersecting) continue;
				arrive(e.target);
				io.unobserve(e.target);
			}
		},
		{ rootMargin: "0px 0px -18% 0px" },
	);
	for (const s of sheets) io.observe(s);
}

root.classList.add("ready");

/* ---- WebMCP: read-only tools for in-browser agents, where supported ---- */
if ("modelContext" in document || "modelContext" in navigator) {
	void import("./webmcp");
}
