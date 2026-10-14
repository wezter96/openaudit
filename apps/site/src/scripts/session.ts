/**
 * The example agent session plays line by line in a short window and scrolls
 * like a terminal, then starts over. It runs only while on screen; without
 * JavaScript or with reduced motion the whole session stands still.
 */
const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

const session = document.querySelector<HTMLElement>("[data-session]");
const pane = session?.querySelector<HTMLElement>(".screen");
const log = session?.querySelector<HTMLElement>(".log");

if (session && pane && log && !still) {
	const lines = [...log.children] as HTMLElement[];
	let shown = 0;
	let timer = 0;
	let playing = false;

	/** Keep the newest line at the bottom of the window. */
	const follow = () => {
		const last = lines[shown - 1];
		const shift = last
			? Math.max(0, last.offsetTop + last.offsetHeight - pane.clientHeight)
			: 0;
		log.style.transform = shift ? `translateY(${-shift}px)` : "";
		pane.classList.toggle("scrolled", shift > 0);
	};

	const step = () => {
		const line = lines[shown];
		if (line) {
			line.classList.add("on");
			shown++;
			follow();
			timer = window.setTimeout(
				step,
				line.classList.contains("out") ? 1500 : 1000,
			);
			return;
		}
		// hold the result, then clear the window and play it again
		timer = window.setTimeout(() => {
			for (const l of lines) l.classList.remove("on");
			shown = 0;
			timer = window.setTimeout(() => {
				follow();
				timer = window.setTimeout(step, 600);
			}, 450);
		}, 3500);
	};

	session.classList.add("play");
	new IntersectionObserver(([entry]) => {
		if (entry?.isIntersecting && !playing) {
			playing = true;
			timer = window.setTimeout(step, 300);
		} else if (!entry?.isIntersecting && playing) {
			playing = false;
			window.clearTimeout(timer);
		}
	}).observe(session);
	new ResizeObserver(follow).observe(pane);
}
