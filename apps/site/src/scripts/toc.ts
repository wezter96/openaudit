/** Docs: mark the section being read in "On this page", and keep the
 * current page visible in the sideways nav on narrow screens. */

const links = [...document.querySelectorAll<HTMLAnchorElement>(".toc a")];
const targets = links
	.map((a) => document.getElementById(decodeURIComponent(a.hash.slice(1))))
	.filter((el): el is HTMLElement => el !== null);

if (targets.length) {
	const visible = new Set<Element>();
	const mark = () => {
		const first = targets.find((t) => visible.has(t));
		if (!first) return;
		for (const a of links) {
			a.classList.toggle("active", a.hash === `#${first.id}`);
		}
	};
	const io = new IntersectionObserver(
		(entries) => {
			for (const e of entries) {
				if (e.isIntersecting) visible.add(e.target);
				else visible.delete(e.target);
			}
			mark();
		},
		{ rootMargin: "-80px 0px -55% 0px" },
	);
	for (const t of targets) io.observe(t);
}

const current = document.querySelector<HTMLElement>(
	".docs-nav a[aria-current=page]",
);
const list = current?.closest("ol");
if (current && list && list.scrollWidth > list.clientWidth) {
	list.scrollLeft = current.offsetLeft - 16;
}
