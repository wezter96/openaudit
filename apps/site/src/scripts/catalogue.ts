/**
 * Filters the auditor list in place. The filters live in the URL hash, so a
 * link such as /auditors/#area=privacy opens the catalogue already filtered.
 */

const form = document.querySelector<HTMLFormElement>("[data-filters]");
const items = [...document.querySelectorAll<HTMLLIElement>("[data-list] > li")];
const count = document.querySelector<HTMLElement>("[data-count]");
const empty = document.querySelector<HTMLElement>("[data-empty]");
const resets = document.querySelectorAll<HTMLButtonElement>("[data-reset]");

if (form) {
	const q = form.elements.namedItem("q") as HTMLInputElement;
	const target = form.elements.namedItem("target") as HTMLSelectElement;
	const area = form.elements.namedItem("area") as HTMLSelectElement;
	const engine = form.elements.namedItem("engine") as HTMLSelectElement;
	const byDefault = form.elements.namedItem("default") as HTMLInputElement;

	// Filters live in the hash, so filtered views are not separate pages to
	// crawlers; ?area= links from elsewhere still work.
	const params = new URLSearchParams(location.hash.slice(1) || location.search);
	const pick = (select: HTMLSelectElement, value: string | null) => {
		if (value && [...select.options].some((o) => o.value === value)) {
			select.value = value;
		}
	};
	q.value = params.get("q") ?? "";
	pick(target, params.get("target"));
	pick(area, params.get("area"));
	pick(engine, params.get("engine"));
	byDefault.checked = params.get("default") === "1";

	const apply = () => {
		const words = q.value.toLowerCase().split(/\s+/).filter(Boolean);
		let shown = 0;
		for (const li of items) {
			const d = li.dataset;
			const ok =
				(!target.value ||
					(d.targets ?? "").split(" ").includes(target.value)) &&
				(!area.value || (d.areas ?? "").split(" ").includes(area.value)) &&
				(!engine.value || d.engine === engine.value) &&
				(!byDefault.checked || d.optin === "0") &&
				words.every((w) => (d.text ?? "").includes(w));
			li.classList.toggle("out", !ok);
			if (ok) shown++;
		}
		if (count) {
			const num = document.createElement("b");
			num.className = "num";
			num.textContent = String(shown);
			count.replaceChildren(num, ` of ${items.length} auditors`);
		}
		if (empty) empty.hidden = shown > 0;
		const active =
			!!q.value ||
			!!target.value ||
			!!area.value ||
			!!engine.value ||
			byDefault.checked;
		resets[0]?.toggleAttribute("hidden", !active);
		const next = new URLSearchParams();
		if (q.value) next.set("q", q.value);
		if (target.value) next.set("target", target.value);
		if (area.value) next.set("area", area.value);
		if (engine.value) next.set("engine", engine.value);
		if (byDefault.checked) next.set("default", "1");
		const query = next.toString();
		history.replaceState(null, "", query ? `#${query}` : location.pathname);
	};

	form.addEventListener("input", apply);
	form.addEventListener("submit", (e) => e.preventDefault());
	for (const r of resets) {
		r.addEventListener("click", () => {
			form.reset();
			apply();
			q.focus();
		});
	}
	apply();
}
