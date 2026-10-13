export {};

/**
 * The one choreographed load, after the report's: while the headline settles
 * (CSS), the dial draws itself: scale, then each area's arc in turn, the
 * ring, the bead, the grade, and the score counting up. Every animation
 * fills backwards from the final state already in the markup, so reduced
 * motion and no-JS simply show that state.
 */

const still =
	matchMedia("(prefers-reduced-motion: reduce)").matches ||
	!("animate" in Element.prototype);

const css = getComputedStyle(document.documentElement);
const SETTLE = css.getPropertyValue("--settle").trim() || "ease-out";
const SOFT = css.getPropertyValue("--soft").trim() || "ease-out";

const anim = (
	el: Element | null,
	frames: Keyframe[],
	options: KeyframeAnimationOptions,
) => el?.animate(frames, { fill: "backwards", ...options });

const dial = document.querySelector<HTMLElement>("[data-dial]");

if (!still && dial) {
	anim(
		dial.querySelector(".dial-plate"),
		[
			{ opacity: 0, transform: "scale(.9)" },
			{ opacity: 1, transform: "none" },
		],
		{ duration: 900, delay: 60, easing: SOFT },
	);
	anim(
		dial.querySelector(".scale"),
		[
			{ opacity: 0, transform: "rotate(-24deg)" },
			{ opacity: 1, transform: "none" },
		],
		{ duration: 1300, delay: 120, easing: SETTLE },
	);
	const draw = (el: Element, delay: number, ms: number) => {
		const v = Number(el.getAttribute("data-v")) || 0;
		anim(el, [{ strokeDashoffset: v }, { strokeDashoffset: 0 }], {
			duration: ms,
			delay,
			easing: SETTLE,
		});
	};
	dial.querySelectorAll(".seg").forEach((s, i) => {
		draw(s, 320 + i * 85, 950);
	});
	for (const [i, s] of [...dial.querySelectorAll(".seg-track")].entries()) {
		anim(s, [{ opacity: 0 }, { opacity: 1 }], {
			duration: 500,
			delay: 240 + i * 85,
			easing: SOFT,
		});
	}
	for (const [i, s] of [...dial.querySelectorAll(".seg-label")].entries()) {
		anim(s, [{ opacity: 0 }, { opacity: 1 }], {
			duration: 600,
			delay: 420 + i * 85,
			easing: SOFT,
		});
	}
	const ring = dial.querySelector(".ring");
	if (ring) draw(ring, 520, 1500);
	anim(
		dial.querySelector(".cap"),
		[
			{ opacity: 0, transform: "scale(0)" },
			{ opacity: 1, transform: "none" },
		],
		{ duration: 700, delay: 1750, easing: SETTLE },
	);
	anim(
		dial.querySelector(".dial-grade"),
		[
			{ opacity: 0, transform: "translateY(18%) scale(.6)" },
			{ opacity: 1, transform: "none" },
		],
		{ duration: 1100, delay: 1150, easing: SETTLE },
	);
	const count = dial.querySelector<HTMLElement>("[data-count]");
	if (count) {
		const to = Number(count.dataset.count) || 0;
		const ms = 1500;
		const delay = 520;
		let t0: number | null = null;
		count.textContent = "0";
		const frame = (t: number) => {
			if (t0 === null) t0 = t + delay;
			const k = Math.max(0, Math.min(1, (t - t0) / ms));
			count.textContent = String(Math.round(to * (1 - (1 - k) ** 4)));
			if (k < 1) requestAnimationFrame(frame);
		};
		requestAnimationFrame(frame);
	}
}

if (!still) {
	for (const [i, el] of [
		...document.querySelectorAll(".hero .late"),
	].entries()) {
		anim(
			el,
			[
				{ opacity: 0, transform: "translateY(10px)" },
				{ opacity: 1, transform: "none" },
			],
			{ duration: 800, delay: 380 + i * 90, easing: SOFT },
		);
	}
}
