/**
 * Filters the auditor list in place. The filters live in the URL hash, so a
 * link such as /auditors/#area=privacy opens the catalogue already filtered.
 */

const form = document.querySelector<HTMLFormElement>("[data-filters]");
const items = [...document.querySelectorAll<HTMLLIElement>("[data-list] > li")];
const count = document.querySelector<HTMLElement>("[data-count]");
const empty = document.querySelector<HTMLElement>("[data-empty]");
const resets = document.querySelectorAll<HTMLButtonElement>("[data-reset]");

/** The filter form's controls. */
interface Filters {
	readonly q: HTMLInputElement;
	readonly target: HTMLSelectElement;
	readonly area: HTMLSelectElement;
	readonly engine: HTMLSelectElement;
	readonly byDefault: HTMLInputElement;
}

const pick = (select: HTMLSelectElement, value: string | null) => {
	if (value && [...select.options].some((o) => o.value === value)) {
		select.value = value;
	}
};

/** An unset filter allows everything; otherwise `list` must name `value`. */
const listed = (value: string, list: string | undefined) =>
	!value || (list ?? "").split(" ").includes(value);

const matches = (f: Filters, words: ReadonlyArray<string>, d: DOMStringMap) =>
	listed(f.target.value, d.targets) &&
	listed(f.area.value, d.areas) &&
	(!f.engine.value || d.engine === f.engine.value) &&
	(!f.byDefault.checked || d.optin === "0") &&
	words.every((w) => (d.text ?? "").includes(w));

/** The set filters as a query string, empty when none is set. */
const filterQuery = (f: Filters) => {
	const next = new URLSearchParams();
	const values: ReadonlyArray<readonly [string, string]> = [
		["q", f.q.value],
		["target", f.target.value],
		["area", f.area.value],
		["engine", f.engine.value],
		["default", f.byDefault.checked ? "1" : ""],
	];
	for (const [key, value] of values) if (value) next.set(key, value);
	return next.toString();
};

const showCount = (shown: number) => {
	if (!count) return;
	const num = document.createElement("b");
	num.className = "num";
	num.textContent = String(shown);
	count.replaceChildren(num, ` of ${items.length} auditors`);
};

const apply = (f: Filters) => {
	const words = f.q.value.toLowerCase().split(/\s+/).filter(Boolean);
	let shown = 0;
	for (const li of items) {
		const ok = matches(f, words, li.dataset);
		li.classList.toggle("out", !ok);
		if (ok) shown++;
	}
	showCount(shown);
	if (empty) empty.hidden = shown > 0;
	const query = filterQuery(f);
	resets[0]?.toggleAttribute("hidden", !query);
	history.replaceState(null, "", query ? `#${query}` : location.pathname);
};

const setUp = (form: HTMLFormElement) => {
	const f: Filters = {
		q: form.elements.namedItem("q") as HTMLInputElement,
		target: form.elements.namedItem("target") as HTMLSelectElement,
		area: form.elements.namedItem("area") as HTMLSelectElement,
		engine: form.elements.namedItem("engine") as HTMLSelectElement,
		byDefault: form.elements.namedItem("default") as HTMLInputElement,
	};

	// Filters live in the hash, so filtered views are not separate pages to
	// crawlers; ?area= links from elsewhere still work.
	const params = new URLSearchParams(location.hash.slice(1) || location.search);
	f.q.value = params.get("q") ?? "";
	pick(f.target, params.get("target"));
	pick(f.area, params.get("area"));
	pick(f.engine, params.get("engine"));
	f.byDefault.checked = params.get("default") === "1";

	form.addEventListener("input", () => apply(f));
	form.addEventListener("submit", (e) => e.preventDefault());
	for (const r of resets) {
		r.addEventListener("click", () => {
			form.reset();
			apply(f);
			f.q.focus();
		});
	}
	apply(f);
};

if (form) setUp(form);
