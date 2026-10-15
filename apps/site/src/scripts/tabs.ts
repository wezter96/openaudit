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

/** One [data-tabs] widget's parts. */
interface TabSet {
	readonly list: HTMLElement;
	readonly ink: HTMLElement | null;
	readonly tabs: ReadonlyArray<HTMLButtonElement>;
	readonly panels: ReadonlyArray<HTMLElement | null>;
	/** The panels' parent, whose height eases between panels. */
	readonly box: HTMLElement | null;
}

/** How a selection shows: whether it moves focus and whether it animates. */
interface Motion {
	readonly focus: boolean;
	readonly animate: boolean;
}

/** A tab's position in its set. */
type TabIndex = number;
/** How many tabs a set has. */
type TabCount = number;
/** A height in CSS pixels. */
type Pixels = number;
/** Whether a tab is the selected one. */
type Selected = boolean;

const isSelected = (t: HTMLButtonElement) =>
	t.getAttribute("aria-selected") === "true";

const moveInk = ({ list, ink, tabs }: TabSet) => {
	const tab = tabs.find(isSelected);
	if (!tab || !ink) return;
	const vertical = getComputedStyle(list).flexDirection === "column";
	ink.style.transform = vertical
		? `translateY(${tab.offsetTop}px) scaleY(${tab.offsetHeight})`
		: `translateX(${tab.offsetLeft}px) scaleX(${tab.offsetWidth})`;
};

const markTab = (tab: HTMLButtonElement, on: Selected) => {
	tab.setAttribute("aria-selected", String(on));
	tab.tabIndex = on ? 0 : -1;
};

const showPanel = (
	panel: HTMLElement | null | undefined,
	on: Selected,
	{ animate }: Motion,
) => {
	if (!panel) return;
	panel.hidden = !on;
	panel.classList.remove("entering");
	if (on && animate) {
		void panel.offsetWidth;
		panel.classList.add("entering");
	}
};

/** Eases the panels' box from its old height to its new one. */
const easeHeight = (box: HTMLElement, before: Pixels, after: Pixels) => {
	if (!before || after === before) return;
	box.style.overflow = "clip";
	box
		.animate([{ height: `${before}px` }, { height: `${after}px` }], {
			duration: 450,
			easing: soft,
		})
		.finished.then(() => box.style.removeProperty("overflow"))
		.catch(() => box.style.removeProperty("overflow"));
};

const revealTab = (
	{ list, tabs }: TabSet,
	index: TabIndex,
	{ focus }: Motion,
) => {
	const tab = tabs[index];
	if (focus) tab?.focus({ preventScroll: true });
	// On narrow screens the tabs scroll sideways; keep the chosen one in view.
	if (tab && list.scrollWidth > list.clientWidth) {
		list.scrollTo({ left: tab.offsetLeft - 16, behavior: "smooth" });
	}
};

const select = (set: TabSet, index: TabIndex, motion: Motion) => {
	const before = set.box?.offsetHeight ?? 0;
	set.tabs.forEach((t, i) => {
		markTab(t, i === index);
		showPanel(set.panels[i], i === index, motion);
	});
	const after = set.box?.offsetHeight ?? 0;
	const ease = motion.animate && !still;
	if (set.box && ease) easeHeight(set.box, before, after);
	revealTab(set, index, motion);
	moveInk(set);
};

/** Where each key moves from tab `i` of `n` (automatic activation). */
const next = (i: TabIndex, n: TabCount) => (i + 1) % n;
const previous = (i: TabIndex, n: TabCount) => (i - 1 + n) % n;
const KEY_MOVES = new Map<string, (i: TabIndex, n: TabCount) => TabIndex>([
	["ArrowDown", next],
	["ArrowRight", next],
	["ArrowUp", previous],
	["ArrowLeft", previous],
	["Home", () => 0],
	["End", (_, n) => n - 1],
]);

const onKey = (set: TabSet, e: KeyboardEvent) => {
	const i = set.tabs.indexOf(e.target as HTMLButtonElement);
	const move = KEY_MOVES.get(e.key);
	if (i < 0 || !move) return;
	e.preventDefault();
	select(set, move(i, set.tabs.length), { focus: true, animate: true });
};

const onClick = (set: TabSet, e: MouseEvent) => {
	const tab = (e.target as Element).closest<HTMLButtonElement>("[role=tab]");
	if (tab) select(set, set.tabs.indexOf(tab), { focus: false, animate: true });
};

const setUp = (root: HTMLElement) => {
	const list = root.querySelector<HTMLElement>("[role=tablist]");
	if (!list) return;
	const tabs = [...list.querySelectorAll<HTMLButtonElement>("[role=tab]")];
	const panels = tabs.map((t) =>
		document.getElementById(t.getAttribute("aria-controls") ?? ""),
	);
	const set: TabSet = {
		list,
		ink: root.querySelector<HTMLElement>(".tab-ink"),
		tabs,
		panels,
		box: panels[0]?.parentElement ?? null,
	};
	select(set, Math.max(0, tabs.findIndex(isSelected)), {
		focus: false,
		animate: false,
	});
	// Place the ink before turning its transition on.
	requestAnimationFrame(() => root.classList.add("ink-ready"));
	list.addEventListener("click", (e) => onClick(set, e));
	list.addEventListener("keydown", (e) => onKey(set, e));
	new ResizeObserver(() => moveInk(set)).observe(list);
};

for (const root of document.querySelectorAll<HTMLElement>("[data-tabs]"))
	setUp(root);
