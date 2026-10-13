export {};

/**
 * Tabs with an ink bar that springs to the selected tab, as in the report's
 * rail. Arrow keys, Home and End move between tabs (automatic activation).
 * When the new panel is taller or shorter, the panels' box eases to its new
 * height instead of jumping, and the panel's parts settle in (CSS, on
 * .entering).
 */

const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
const soft =
	getComputedStyle(document.documentElement)
		.getPropertyValue("--soft")
		.trim() || "ease-out";

for (const root of document.querySelectorAll<HTMLElement>("[data-tabs]")) {
	const list = root.querySelector<HTMLElement>("[role=tablist]");
	const ink = root.querySelector<HTMLElement>(".tab-ink");
	if (!list) continue;
	const tabs = [...list.querySelectorAll<HTMLButtonElement>("[role=tab]")];
	const panels = tabs.map((t) =>
		document.getElementById(t.getAttribute("aria-controls") ?? ""),
	);

	const moveInk = () => {
		const tab = tabs.find((t) => t.getAttribute("aria-selected") === "true");
		if (!tab || !ink) return;
		const vertical = getComputedStyle(list).flexDirection === "column";
		ink.style.transform = vertical
			? `translateY(${tab.offsetTop}px) scaleY(${tab.offsetHeight})`
			: `translateX(${tab.offsetLeft}px) scaleX(${tab.offsetWidth})`;
	};

	const box = panels[0]?.parentElement ?? null;
	const select = (index: number, focus: boolean, animate = true) => {
		const before = box?.offsetHeight ?? 0;
		tabs.forEach((t, i) => {
			const on = i === index;
			t.setAttribute("aria-selected", String(on));
			t.tabIndex = on ? 0 : -1;
			const panel = panels[i];
			if (!panel) return;
			panel.hidden = !on;
			panel.classList.remove("entering");
			if (on && animate) {
				void panel.offsetWidth;
				panel.classList.add("entering");
			}
		});
		const after = box?.offsetHeight ?? 0;
		if (box && animate && !still && before && after !== before) {
			box.style.overflow = "clip";
			box
				.animate([{ height: `${before}px` }, { height: `${after}px` }], {
					duration: 450,
					easing: soft,
				})
				.finished.then(() => box.style.removeProperty("overflow"))
				.catch(() => box.style.removeProperty("overflow"));
		}
		const tab = tabs[index];
		if (focus) tab?.focus({ preventScroll: true });
		// On narrow screens the tabs scroll sideways; keep the chosen one in view.
		if (tab && list.scrollWidth > list.clientWidth) {
			list.scrollTo({ left: tab.offsetLeft - 16, behavior: "smooth" });
		}
		moveInk();
	};

	select(
		Math.max(
			0,
			tabs.findIndex((t) => t.getAttribute("aria-selected") === "true"),
		),
		false,
		false,
	);
	// Place the ink before turning its transition on.
	requestAnimationFrame(() => root.classList.add("ink-ready"));

	list.addEventListener("click", (e) => {
		const tab = (e.target as Element).closest<HTMLButtonElement>("[role=tab]");
		if (tab) select(tabs.indexOf(tab), false);
	});
	list.addEventListener("keydown", (e) => {
		const i = tabs.indexOf(e.target as HTMLButtonElement);
		if (i < 0) return;
		const n = tabs.length;
		const to =
			e.key === "ArrowDown" || e.key === "ArrowRight"
				? (i + 1) % n
				: e.key === "ArrowUp" || e.key === "ArrowLeft"
					? (i - 1 + n) % n
					: e.key === "Home"
						? 0
						: e.key === "End"
							? n - 1
							: -1;
		if (to < 0) return;
		e.preventDefault();
		select(to, true);
	});
	new ResizeObserver(moveInk).observe(list);
}
