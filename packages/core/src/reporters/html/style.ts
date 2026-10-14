/*
 * Stylesheet of the HTML report, inlined and allowed by its hash. Nothing
 * external: system fonts, and the only images are data: URIs.
 *
 * Design language: "Calibration sheet". The report reads as a measurement
 * document rather than an app.
 * - Paper: cool fog with a millimetre dot grid and faint grain on the hero.
 *   Hairline rules separate things; boxes are the exception (open findings,
 *   inputs), never the default.
 * - Type: one system sans, set large and tight for grades and headlines; a
 *   precise monospace data layer for every score, count, id, path and time.
 * - Colour: ink and graphite on fog, one ultramarine accent for anything you
 *   can act on, and a heat ramp for severity (oxblood, vermilion, amber,
 *   straw, slate). Each severity also has its own glyph shape (diamond,
 *   triangle, disc, ring, dash), so colour is never the only signal.
 * - The dial is the one loud element. Everything around it is quiet.
 * - Motion: springs, not eases. One choreographed load (the dial draws, the
 *   score counts, the rest settles in order); after that, motion only answers
 *   the reader (rail ink slides, panels cross-fade, disclosures grow, counts
 *   roll). Reduced motion shows every final state at once.
 */

/** A damped spring sampled into a CSS `linear()` easing (mass 1). */
const spring = (stiffness: number, damping: number, ms: number): string => {
	const steps = 48;
	const dt = 1 / 600;
	const points: string[] = [];
	let x = 0;
	let v = 0;
	let t = 0;
	for (let i = 0; i <= steps; i++) {
		const until = (i / steps) * (ms / 1000);
		while (t < until) {
			v += (-stiffness * (x - 1) - damping * v) * dt;
			x += v * dt;
			t += dt;
		}
		points.push(i === steps ? "1" : x.toFixed(3));
	}
	return `linear(${points.join(",")})`;
};

/** Settles with a small overshoot: the dial, letters, the rail ink. */
const SETTLE = spring(170, 19, 900);
/** No overshoot: panels, rows and disclosure. */
const SOFT = spring(210, 29, 600);

const NOISE =
	"url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='180'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='3' stitchTiles='stitch'/%3E%3CfeColorMatrix values='0 0 0 0 .5 0 0 0 0 .5 0 0 0 0 .5 0 0 0 .5 0'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E\")";

/**
 * The dark palette. It applies when the system is dark and the reader hasn't
 * picked light, or when a host page sets data-theme="dark" (openaudit.se's
 * theme switch does).
 */
const DARK = `--paper:#0b111b;--paper-2:#111a27;--paper-3:#172233;--ink:#e7ecf3;--graphite:#9aa7b9;--hair:#2a374c;--hair-soft:#1b2636;--dot:rgba(154,167,185,.08);
--accent:#8fa2ff;--accent-soft:#1a2246;--focus:#8fa2ff;
--c-critical:#ff4f75;--c-high:#ff7442;--c-medium:#ffb13d;--c-low:#e9d38a;--c-info:#6f7b8e;--c-none:#243145;
--t-critical:#ff8aa3;--t-high:#ff9f7a;--t-medium:#ffc46e;--t-low:#e9d38a;--t-info:#a6b1c1;
--g-A:#4fd49b;--g-B:#a6d96c;--g-C:#ffc46e;--g-D:#ff9f7a;--g-F:#ff8aa3;
--a-A:#3cc98c;--a-B:#98cf55;--a-C:#ffb13d;--a-D:#ff7442;--a-F:#ff4f75;
--ok:#4fd49b;--s-failed:#d9788a;--s-error:#ffb13d;
--lift:0 1px 2px rgba(0,0,0,.4),0 14px 30px -14px rgba(0,0,0,.7);
--grain-blend:screen;--grain:.16`;

export const STYLE = `
:root{color-scheme:light dark;
--paper:#eef1f4;--paper-2:#f8fafb;--paper-3:#e4e8ed;--ink:#0d1522;--graphite:#4a5668;--hair:#c9d1db;--hair-soft:#dce2e9;--dot:rgba(13,21,34,.085);
--accent:#2340e8;--accent-soft:#e2e7ff;--focus:#2340e8;
--c-critical:#a1123a;--c-high:#e04a1f;--c-medium:#f0a22b;--c-low:#dfbc4f;--c-info:#a3adba;--c-none:#d5dbe3;
--t-critical:#a1123a;--t-high:#b4380f;--t-medium:#8c5600;--t-low:#6b570a;--t-info:#556070;
--g-A:#0b7a4e;--g-B:#4f7a12;--g-C:#8c5600;--g-D:#b4380f;--g-F:#a1123a;
--a-A:#19a86a;--a-B:#7fb236;--a-C:#f0a22b;--a-D:#e04a1f;--a-F:#a1123a;
--ok:#0b7a4e;--s-failed:#b9566a;--s-error:#f0a22b;
--lift:0 1px 2px rgba(13,21,34,.06),0 10px 28px -14px rgba(13,21,34,.22);
--grain-blend:multiply;--grain:.3;
--sans:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI Variable Text","Segoe UI",Inter,Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,"SF Mono",SFMono-Regular,"JetBrains Mono","Cascadia Mono","Segoe UI Mono",Menlo,Consolas,monospace;
--settle:cubic-bezier(.22,1.25,.36,1);--soft:cubic-bezier(.2,.8,.2,1);--rail:15.5rem}
@supports (transition-timing-function:linear(0,1)){:root{--settle:${SETTLE};--soft:${SOFT}}}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){${DARK}}}
:root[data-theme=dark]{${DARK}}
:root[data-theme=light]{color-scheme:light}
:root[data-theme=dark]{color-scheme:dark}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;scroll-padding-top:4.5rem}
body{margin:0;background-color:var(--paper);background-image:radial-gradient(circle at 1px 1px,var(--dot) 1px,transparent 0);background-size:20px 20px;color:var(--ink);font:400 .9375rem/1.55 var(--sans);-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
a{color:var(--accent);text-decoration-thickness:1px;text-underline-offset:.2em}
a:hover{text-decoration-thickness:2px}
:focus-visible{outline:2px solid var(--focus);outline-offset:3px;border-radius:4px}
code,pre,.mono{font-family:var(--mono);font-size:.82em;font-variant-ligatures:none}
pre{margin:0;background:var(--paper-3);border-radius:6px;padding:.8rem .95rem;overflow:auto;white-space:pre-wrap;word-break:break-word;max-height:24rem;line-height:1.55}
h1,h2,h3,h4{margin:0;font-weight:650;letter-spacing:-.012em}
p,dl,dd,figure{margin:0}
ul,ol{margin:0;padding:0;list-style:none}
[hidden]{display:none!important}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.skip{position:absolute;left:1rem;top:-4rem;z-index:60;background:var(--paper-2);color:var(--accent);padding:.6rem 1rem;border-radius:6px;box-shadow:var(--lift)}
.skip:focus{top:1rem}
.wrap{max-width:84rem;margin:0 auto;padding:0 2.25rem}
.muted{color:var(--graphite)}
.small{font-size:.8125rem}
.num{font-family:var(--mono);font-variant-numeric:tabular-nums}

/* severity: heat ramp plus a glyph per level */
.sev{--s:var(--c-info);display:inline-flex;align-items:center;gap:.45rem;font-size:.8125rem;font-weight:600;white-space:nowrap;color:var(--t-info)}
.sev::before,.glyph{content:"";display:inline-block;width:.62rem;height:.62rem;flex:none;background:var(--s)}
.sev-critical,.g-critical{--s:var(--c-critical);color:var(--t-critical)}
.sev-high,.g-high{--s:var(--c-high);color:var(--t-high)}
.sev-medium,.g-medium{--s:var(--c-medium);color:var(--t-medium)}
.sev-low,.g-low{--s:var(--c-low);color:var(--t-low)}
.sev-info,.g-info{--s:var(--c-info);color:var(--t-info)}
.sev-critical::before,.glyph.g-critical{transform:rotate(45deg) scale(.86);border-radius:1px}
.sev-high::before,.glyph.g-high{clip-path:polygon(50% 4%,100% 96%,0 96%)}
.sev-medium::before,.glyph.g-medium{border-radius:50%}
.sev-low::before,.glyph.g-low{border-radius:50%;background:transparent;box-shadow:inset 0 0 0 2px var(--s)}
.sev-info::before,.glyph.g-info{height:2px;border-radius:1px}

/* masthead: the briefing's slug line and title */
.mast{padding:1.4rem 0 1.75rem}
.slug{display:flex;align-items:center;gap:1rem;justify-content:space-between;flex-wrap:wrap;padding-bottom:1.1rem;border-bottom:1px solid var(--hair)}
.brand{display:flex;align-items:center;gap:.55rem;font-size:.875rem;font-weight:650}
.brand svg{width:1.15rem;height:1.15rem}
.brand .ver{font-family:var(--mono);font-size:.75rem;color:var(--graphite);font-weight:400}
.logo-a{fill:var(--ink)}.logo-b{fill:none;stroke:var(--paper);stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
.mast h1{margin-top:1.5rem;font-size:clamp(1.75rem,1.2rem + 2.2vw,2.75rem);font-weight:750;line-height:1.05;letter-spacing:-.035em;text-wrap:balance;max-width:60rem}
.h1-pre{display:block;font-size:.875rem;font-weight:500;letter-spacing:0;color:var(--graphite);margin-bottom:.45rem}
.h1-target{overflow-wrap:anywhere}
.meta{display:flex;flex-wrap:wrap;gap:.4rem 2.25rem;margin-top:1.1rem;font-size:.8125rem}
.meta div{display:flex;flex-direction:column;gap:.1rem;min-width:0}
.meta dt{color:var(--graphite);font-size:.75rem}
.meta dd{font-family:var(--mono);font-size:.78rem;overflow-wrap:anywhere}
.actions{display:flex;gap:.4rem;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:.45rem;font:inherit;font-size:.8125rem;font-weight:600;color:var(--ink);background:transparent;border:1px solid var(--hair);border-radius:7px;padding:.42rem .8rem;min-height:2.2rem;cursor:pointer;transition:border-color .2s,background-color .2s,transform .35s var(--settle)}
.btn:hover{border-color:var(--ink);background:var(--paper-2)}
.btn:active{transform:scale(.97)}
.btn svg{width:1rem;height:1rem;fill:none;stroke:currentColor;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
.btn.quiet{border-color:transparent;color:var(--graphite)}
.btn.quiet:hover{color:var(--ink);border-color:var(--hair)}

/* download menu */
.dl{position:relative}
.dl .btn .chev{width:.8rem;height:.8rem;transform:rotate(90deg);margin-left:-.1rem}
.dl .btn[aria-expanded=true]{border-color:var(--ink);background:var(--paper-2)}
.dl .btn[aria-expanded=true] .chev{transform:rotate(-90deg)}
.dl-menu{position:absolute;right:0;top:calc(100% + .45rem);z-index:50;width:min(24rem,calc(100vw - 2.5rem));padding:.35rem;background:var(--paper-2);border:1px solid var(--hair);border-radius:8px;box-shadow:var(--lift);transform-origin:top right}
.dl-menu li+li{border-top:1px solid var(--hair-soft)}
.dl-menu button{all:unset;box-sizing:border-box;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.1rem 1rem;width:100%;padding:.6rem .7rem;border-radius:5px;cursor:pointer;transition:background-color .15s}
.dl-menu button:hover,.dl-menu button:focus-visible{background:var(--accent-soft);outline:none}
.dl-menu button:focus-visible{box-shadow:inset 0 0 0 2px var(--focus)}
.dl-l{font-weight:650;font-size:.875rem}
.dl-h{grid-column:1;font-size:.75rem;color:var(--graphite)}
.dl-f{grid-column:2;grid-row:1/3;align-self:center;font-family:var(--mono);font-size:.7rem;color:var(--graphite)}

/* frame: rail + content once the script runs; stacked sections without it */
.frame{max-width:84rem;margin:0 auto;padding:0 2.25rem}
.js .frame{display:grid;grid-template-columns:var(--rail) minmax(0,1fr);gap:0 3rem;align-items:start}
.toc{padding:0 0 1rem}
.toc ul{display:flex;flex-wrap:wrap;gap:.3rem 1.25rem}
.toc a{font-size:.875rem;font-weight:550}

/* rail navigation */
.rail{position:sticky;top:0;max-height:100vh;overflow:auto;padding:1.5rem 0 2rem;scrollbar-width:none}
.rail::-webkit-scrollbar{display:none}
.mini{display:flex;align-items:center;gap:.55rem;font-size:.8125rem;color:var(--graphite);height:0;opacity:0;overflow:hidden;transform:translateY(-6px);transition:opacity .25s,transform .5s var(--settle),height .4s var(--soft),margin .4s var(--soft)}
.stuck .mini{height:2.6rem;opacity:1;transform:none;margin-bottom:.9rem}
.mini svg{width:1.7rem;height:1.7rem;transform:rotate(-90deg);flex:none}
.mini .ring,.mini .ring-track{stroke-width:4}
.mini b{font-size:1.15rem;font-weight:800;letter-spacing:-.03em}
.mini .num{color:var(--ink);font-size:.8rem}
.tablist{position:relative;display:flex;flex-direction:column;gap:1px}
.tab{position:relative;display:grid;grid-template-columns:1.6rem minmax(0,1fr) auto;grid-template-rows:auto auto;column-gap:.6rem;align-items:center;text-align:left;font:inherit;color:var(--graphite);background:none;border:0;border-radius:6px;padding:.5rem .6rem .5rem .85rem;cursor:pointer;transition:color .2s,background-color .25s}
.tab:hover{color:var(--ink);background:color-mix(in srgb,var(--paper-3) 60%,transparent)}
.tab[aria-selected=true]{color:var(--ink);background:var(--paper-2);box-shadow:0 1px 0 var(--hair-soft)}
.tab.sep{margin-top:1.1rem}
.tab.sep::before{content:"";position:absolute;left:.85rem;right:.6rem;top:-.6rem;border-top:1px solid var(--hair)}
.tg{grid-row:1/3;font-size:1.15rem;font-weight:800;letter-spacing:-.04em;line-height:1;text-align:center}
.tg svg{width:1.05rem;height:1.05rem;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;vertical-align:-.15rem;color:var(--graphite)}
.tl{font-size:.875rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ts{font-family:var(--mono);font-size:.75rem;color:var(--graphite);font-variant-numeric:tabular-nums}
.tbar{grid-column:2/4;display:block;width:100%;height:2px;margin-top:.35rem;overflow:hidden;border-radius:2px}
.tbar .tr{fill:var(--c-none)}
.tab-ink{position:absolute;left:0;top:0;width:2px;height:1px;border-radius:2px;background:var(--accent);transform-origin:0 0;pointer-events:none;transition:transform .6s var(--settle)}
.rail:not(.ready) .tab-ink{transition:none}

/* panels */
main{display:block;min-width:0;padding-bottom:4rem;overflow-x:clip}
main:focus{outline:0}
.panel{padding-top:1.75rem}
.panel:focus-visible{outline:none}
.panel+.panel{margin-top:3rem;border-top:1px solid var(--hair)}
.js .panel+.panel{margin-top:0;border-top:0}
.panel-head{display:flex;gap:1.5rem 2.5rem;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;padding-bottom:1.5rem;border-bottom:1px solid var(--hair)}
.panel-head>div:first-child{flex:1 1 24rem;min-width:0}
.panel-head h2{font-size:clamp(1.9rem,1.3rem + 1.8vw,2.75rem);font-weight:750;letter-spacing:-.035em;line-height:1.02}
.lede{color:var(--graphite);margin-top:.6rem;max-width:38rem;font-size:1rem;text-wrap:pretty}
.section{margin-top:2.75rem}
.sh{display:flex;align-items:baseline;justify-content:space-between;gap:1rem;flex-wrap:wrap;padding-bottom:.6rem;border-bottom:1px solid var(--ink)}
.sh h3{font-size:1rem;font-weight:700}
.sh p{color:var(--graphite);font-size:.8125rem}

/* hero: the dial on the paper, a spec sheet beside it */
.hero{position:relative;display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,1fr);gap:2.5rem;align-items:center;padding:1rem 0 2.25rem;isolation:isolate}
.hero::before{content:"";position:absolute;inset:-1rem -2rem 0;background-image:${NOISE};opacity:var(--grain);mix-blend-mode:var(--grain-blend);pointer-events:none;z-index:-1;-webkit-mask-image:radial-gradient(60% 80% at 25% 50%,#000,transparent);mask-image:radial-gradient(60% 80% at 25% 50%,#000,transparent)}
.dial{position:relative;width:calc(100% - 3rem);margin:1.5rem;aspect-ratio:1}
.dial svg{display:block;width:100%;height:100%;overflow:visible}
.dial-plate{fill:var(--paper-2);stroke:var(--hair-soft)}
.seg-track{fill:none;stroke:var(--c-none);stroke-width:6}
.seg{fill:none;stroke-width:6;transition:stroke-width .35s var(--settle),opacity .2s}
.dial:hover .seg{opacity:.5}
.dial .seg:hover{opacity:1;stroke-width:10}
.seg-label{font-family:var(--sans);font-size:7.2px;font-weight:550;fill:var(--graphite);letter-spacing:.01em}
.ticks{stroke:var(--graphite);stroke-width:.8;opacity:.5}
.ticks-major{stroke:var(--ink);stroke-width:1.3;opacity:.6}
.ring-track{fill:none;stroke:var(--c-none);stroke-width:15}
.ring{fill:none;stroke-width:15;stroke-linecap:round}
.cap{fill:var(--paper-2);stroke-width:3}
.a-A{stroke:var(--a-A)}.a-B{stroke:var(--a-B)}.a-C{stroke:var(--a-C)}.a-D{stroke:var(--a-D)}.a-F{stroke:var(--a-F)}
.af-A{fill:var(--a-A)}.af-B{fill:var(--a-B)}.af-C{fill:var(--a-C)}.af-D{fill:var(--a-D)}.af-F{fill:var(--a-F)}
.dial-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;pointer-events:none}
.dial-grade{font-size:clamp(5.5rem,3rem + 6vw,8.5rem);font-weight:800;line-height:.8;letter-spacing:-.08em;margin-left:-.08em}
.dial-score{margin-top:.7rem;font-family:var(--mono);font-size:1rem;font-weight:600;font-variant-numeric:tabular-nums;color:var(--ink)}
.dial-score small{font-size:.75rem;font-weight:400;color:var(--graphite);margin-left:.1rem}
.gm-A{color:var(--g-A)}.gm-B{color:var(--g-B)}.gm-C{color:var(--g-C)}.gm-D{color:var(--g-D)}.gm-F{color:var(--g-F)}
.readout{min-width:0}
.verdict{font-size:clamp(1.6rem,1.1rem + 1.6vw,2.4rem);font-weight:750;letter-spacing:-.035em;line-height:1.06;text-wrap:balance;max-width:22ch}
.verdict-sub{color:var(--graphite);margin-top:.75rem;max-width:40rem;text-wrap:pretty}
.spec{margin-top:1.75rem;border-top:1px solid var(--ink)}
.spec>div{display:flex;flex-direction:column;gap:.65rem;padding:1rem 0 1.1rem;border-bottom:1px solid var(--hair)}
.spec dt{display:flex;justify-content:space-between;gap:1rem;font-size:.8125rem;font-weight:600}
.spec dt span{font-family:var(--mono);font-size:.72rem;font-weight:400;color:var(--graphite)}
.spectrum{display:block;width:100%;height:10px;overflow:hidden;border-radius:2px}
.spectrum rect{transform-box:fill-box;transform-origin:left center}
.legend{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:.5rem .75rem;margin-top:.75rem}
.legend .sev{white-space:nowrap;gap:.35rem}
.legend li{display:flex;flex-direction:column;gap:.15rem}
.legend .n{font-family:var(--mono);font-size:1.6rem;font-weight:500;letter-spacing:-.04em;line-height:1;font-variant-numeric:tabular-nums;color:var(--ink)}
.legend .zero .n{color:var(--graphite);opacity:.6}
.legend .sev{font-size:.75rem}
.f-critical{fill:var(--c-critical)}.f-high{fill:var(--c-high)}.f-medium{fill:var(--c-medium)}.f-low{fill:var(--c-low)}.f-info{fill:var(--c-info)}.f-none{fill:var(--c-none)}
.f-passed{fill:var(--a-A)}.f-failed{fill:var(--s-failed)}.f-error{fill:var(--s-error)}.f-skipped{fill:var(--c-none)}
.strip{display:block;width:100%;height:12px;overflow:hidden;border-radius:2px}
.strip rect{transition:opacity .2s}
.strip:hover rect{opacity:.55}
.strip rect:hover{opacity:1}
.strip-key{display:flex;flex-wrap:wrap;gap:.3rem 1.2rem;margin-top:.6rem;font-size:.8125rem;color:var(--graphite)}
.strip-key span{display:inline-flex;align-items:center;gap:.4rem}
.strip-key b{font-family:var(--mono);color:var(--ink);font-weight:500;font-size:.8rem}
.key{width:.55rem;height:.55rem;border-radius:1px;background:var(--c-none)}
.k-passed{background:var(--a-A)}.k-failed{background:var(--s-failed)}.k-error{background:var(--s-error)}
.diffnote{display:inline-flex;align-items:center;gap:.5rem;margin-top:1rem;font-size:.8125rem;color:var(--ink);border:1px solid var(--accent);border-radius:999px;padding:.25rem .8rem .25rem .6rem}
.diffnote svg{width:1rem;height:1rem;fill:none;stroke:var(--accent);stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

/* category rack: one ruled line per category */
.rack-head,.ch{display:grid;grid-template-columns:3rem minmax(9rem,1.1fr) minmax(8rem,1fr) minmax(10rem,1.2fr) 4.5rem;gap:1.5rem;align-items:center}
.rack-head{padding:.7rem 0 .5rem;font-size:.72rem;color:var(--graphite);border-bottom:1px solid var(--hair)}
.rack li{border-bottom:1px solid var(--hair-soft)}
.ch{padding:.95rem .25rem;color:inherit;text-decoration:none;position:relative;transition:background-color .2s}
.ch::after{content:"";position:absolute;left:0;top:-1px;bottom:-1px;width:2px;background:var(--accent);transform:scaleY(0);transition:transform .45s var(--settle)}
.ch:hover{background:color-mix(in srgb,var(--paper-2) 70%,transparent)}
.ch:hover::after,.ch:focus-visible::after{transform:none}
.ch:hover .ch-name{color:var(--accent)}
.ch:focus-visible{outline-offset:-2px}
.ch-grade{font-size:2.25rem;font-weight:800;letter-spacing:-.07em;line-height:.9;text-align:center}
.ch-name{font-weight:650;font-size:1.0625rem;letter-spacing:-.01em;transition:color .2s}
.ch-meter{display:flex;align-items:center;gap:.8rem}
.ch-meter svg{flex:1;height:4px;min-width:0;border-radius:2px;overflow:hidden}
.ch-meter .num{font-size:.95rem;font-weight:600;min-width:2.2rem;text-align:right}
.ch-sev{display:flex;flex-wrap:wrap;gap:.25rem .9rem;font-family:var(--mono);font-size:.8rem;color:var(--ink);font-variant-numeric:tabular-nums}
.ch-sev span{display:inline-flex;align-items:center;gap:.35rem}
.ch-clean{display:inline-flex;align-items:center;gap:.4rem;font-family:var(--sans);font-size:.8125rem;color:var(--ok);font-weight:600}
.ch-clean svg{width:.9rem;height:.9rem;fill:none;stroke:currentColor;stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
.dots{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:3px}
.dots i{width:5px;height:5px;border-radius:50%;background:var(--c-none)}
.dots .d-passed{background:var(--a-A)}.dots .d-failed{background:var(--s-failed)}.dots .d-error{background:var(--s-error)}

/* ruled finding lists (top findings, compliance) */
.flist li{border-bottom:1px solid var(--hair-soft)}
.frow{display:grid;grid-template-columns:6rem minmax(0,1fr) auto;gap:1.25rem;align-items:baseline;padding:.85rem .25rem;color:inherit;text-decoration:none;transition:background-color .2s}
.frow:hover{background:color-mix(in srgb,var(--paper-2) 70%,transparent)}
.frow:hover .t{color:var(--accent)}
.frow:focus-visible{outline-offset:-2px}
.frow .t{font-weight:600;overflow-wrap:anywhere;transition:color .2s}
.frow .sub{display:block;font-family:var(--mono);font-size:.74rem;color:var(--graphite);font-weight:400;overflow-wrap:anywhere;margin-top:.2rem}
.frow .cat{font-size:.8125rem;color:var(--graphite)}

/* AI note, coverage */
.ai{position:relative;padding:1.4rem 0 .2rem 1.5rem;border-left:2px solid var(--accent)}
.ai-head{display:flex;align-items:center;gap:.55rem;margin-bottom:.7rem}
.ai-head svg{width:1.05rem;height:1.05rem;fill:var(--accent)}
.ai-head h3{font-size:1rem}
.ai-sum{font-size:1.125rem;line-height:1.5;max-width:44rem;letter-spacing:-.005em}
.ai ol{counter-reset:p;display:grid;grid-template-columns:repeat(auto-fit,minmax(16rem,1fr));gap:1.5rem;margin-top:1.4rem}
.ai ol li{counter-increment:p;border-top:1px solid var(--hair);padding-top:.8rem}
.ai ol li strong{display:block;font-size:.9375rem}
.ai ol li strong::before{content:counter(p,decimal-leading-zero) "  ";font-family:var(--mono);color:var(--accent);font-weight:500;font-size:.8rem}
.ai ol li p{color:var(--graphite);font-size:.875rem;margin-top:.3rem}
.ai ol li p b{color:var(--ink);font-weight:600}
.ai .model{margin-top:1.2rem;font-size:.75rem;color:var(--graphite)}
.cov{display:flex;flex-direction:column;font-size:.875rem}
.cov li{display:flex;gap:.7rem;align-items:flex-start;padding:.75rem 0;border-bottom:1px solid var(--hair-soft)}
.cov svg{width:1.05rem;height:1.05rem;flex:none;margin-top:.15rem;fill:none;stroke:var(--graphite);stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.cov .ok svg{stroke:var(--ok)}.cov .gap svg{stroke:var(--t-medium)}
.callout{display:flex;gap:.8rem;align-items:flex-start;padding:.9rem 0;border-bottom:1px solid var(--hair-soft);font-size:.875rem}
.callout svg{width:1.1rem;height:1.1rem;flex:none;margin-top:.1rem;fill:none;stroke:var(--graphite);stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.callout.warn{border:0;border-left:2px solid var(--c-medium);padding:.85rem 1rem;background:color-mix(in srgb,var(--c-medium) 9%,transparent);border-radius:0 6px 6px 0;margin-top:.75rem}
.callout.warn svg{stroke:var(--t-medium)}
.callout ul{margin:.4rem 0 0;padding-left:1.1rem}

/* category panel */
.cat-score{display:flex;align-items:center;gap:1.1rem}
.cat-score .dial{width:5.75rem;margin:0}
.cat-score .dial-grade{font-size:2.6rem;letter-spacing:-.07em}
.cat-score .ring,.cat-score .ring-track{stroke-width:9}
.cat-score p{font-size:.8125rem;color:var(--graphite);line-height:1.45}
.cat-score p b{display:block;font-family:var(--mono);font-size:1.6rem;font-weight:500;letter-spacing:-.04em;color:var(--ink);line-height:1.1}
.cat-score p b small{font-size:.75rem;color:var(--graphite);letter-spacing:0}
.contrib{display:flex;flex-wrap:wrap;gap:.3rem 1rem;margin-top:1rem;font-size:.75rem;color:var(--graphite)}
.contrib li{display:inline-flex;align-items:center;gap:.4rem}
.contrib li code{font-size:.75rem}
.contrib li.off code{color:var(--graphite);text-decoration:line-through;text-decoration-color:var(--hair)}
.dot{width:.42rem;height:.42rem;border-radius:50%;flex:none;background:var(--c-info)}
.dot-passed{background:var(--a-A)}.dot-failed{background:var(--s-failed)}.dot-error{background:var(--s-error)}.dot-skipped{background:transparent;box-shadow:inset 0 0 0 1.5px var(--graphite)}

/* filters: a toolbar, not a card */
.filters{display:flex;flex-wrap:wrap;gap:.9rem 1.5rem;align-items:flex-end;padding:1.1rem 0 1rem;border-bottom:1px solid var(--hair)}
.filters fieldset{border:0;margin:0;padding:0;min-width:0}
.filters legend,.field label{display:block;font-size:.75rem;color:var(--graphite);padding:0;margin-bottom:.4rem}
.checks{display:flex;flex-wrap:wrap;gap:.3rem}
.check{position:relative;display:inline-flex}
.check input{position:absolute;opacity:0;inset:0;margin:0;cursor:pointer}
.check span{display:inline-flex;align-items:center;gap:.45rem;border-radius:6px;padding:.35rem .65rem;font-size:.8125rem;font-weight:600;color:var(--graphite);border:1px solid var(--hair);cursor:pointer;user-select:none;transition:background-color .2s,color .2s,border-color .2s}
.check span b{font-family:var(--mono);font-weight:500;font-size:.75rem}
.check span::before{transition:opacity .2s,transform .4s var(--settle);opacity:.3;transform:scale(.8)}
.check input:checked+span{color:var(--ink);border-color:var(--ink);background:var(--paper-2)}
.check input:checked+span::before{opacity:1;transform:none}
.check.sev-critical input:checked+span::before{transform:rotate(45deg) scale(.86)}
.check.sev-critical span::before{transform:rotate(45deg) scale(.7)}
.check:hover span{color:var(--ink)}
.check input:focus-visible+span{outline:2px solid var(--focus);outline-offset:2px}
.check::before{content:none}
.check span::before{content:"";width:.62rem;height:.62rem;background:var(--s)}
.check.sev-critical span::before{border-radius:1px}
.check.sev-high span::before{clip-path:polygon(50% 4%,100% 96%,0 96%)}
.check.sev-medium span::before{border-radius:50%}
.check.sev-low span::before{border-radius:50%;background:transparent;box-shadow:inset 0 0 0 2px var(--s)}
.check.sev-info span::before{height:2px}
.field{display:flex;flex-direction:column;min-width:9.5rem}
.field.grow{flex:1 1 14rem}
input[type=search],select{font:inherit;font-size:.875rem;color:var(--ink);background:var(--paper-2);border:1px solid var(--hair);border-radius:6px;padding:.42rem .6rem;min-height:2.25rem;width:100%;transition:border-color .2s}
input[type=search]:hover,select:hover{border-color:var(--graphite)}
input[type=search]:focus,select:focus{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px var(--accent-soft)}
.toolbar{display:flex;gap:.5rem 1rem;align-items:center;flex-wrap:wrap;padding:.8rem 0;border-bottom:1px solid var(--ink)}
.live{margin-right:auto;color:var(--graphite);font-size:.8125rem}
.live b{font-family:var(--mono);color:var(--ink);font-weight:600;font-variant-numeric:tabular-nums}

/* findings: ruled rows; a rule with several findings is a group */
.rules>li{border-bottom:1px solid var(--hair-soft)}
.rule>summary,.finding>summary,.ctrl>summary{list-style:none;cursor:pointer}
.rule>summary::-webkit-details-marker,.finding>summary::-webkit-details-marker,.ctrl>summary::-webkit-details-marker{display:none}
.row{display:grid;grid-template-columns:6rem minmax(0,1fr) auto;gap:.2rem 1.25rem;align-items:baseline;padding:.85rem .25rem;transition:background-color .2s}
summary.row:hover{background:color-mix(in srgb,var(--paper-2) 70%,transparent)}
summary.row:focus-visible{outline-offset:-2px}
.row .main{min-width:0}
.ft{font-weight:600;overflow-wrap:anywhere}
.loc{display:block;font-family:var(--mono);font-size:.74rem;color:var(--graphite);overflow-wrap:anywhere;margin-top:.2rem}
.side{display:flex;align-items:center;gap:.75rem;font-size:.75rem;color:var(--graphite);white-space:nowrap}
.side .mono{font-size:.72rem}
.chev{width:.95rem;height:.95rem;fill:none;stroke:var(--graphite);stroke-width:2;stroke-linecap:round;stroke-linejoin:round;transition:transform .5s var(--settle);flex:none}
details[open]>summary .chev{transform:rotate(90deg)}
.confirm{display:inline-flex;align-items:center;gap:.3rem;font-size:.75rem;font-weight:600;color:var(--ok);margin-top:.25rem}
.confirm svg{width:.85rem;height:.85rem;fill:none;stroke:currentColor;stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
.count{font-family:var(--mono);font-size:.75rem;color:var(--ink);border:1px solid var(--hair);border-radius:4px;padding:0 .35rem;font-variant-numeric:tabular-nums}
.rule-body{margin:0 0 .9rem 7.25rem;border-left:1px solid var(--hair)}
.rule-body .findings>li+li{border-top:1px solid var(--hair-soft)}
.rule-body .row{grid-template-columns:1rem minmax(0,1fr) auto;padding:.6rem .25rem .6rem 1rem}
.sev.bare{gap:0}
.rule-body .loc{margin-top:0;font-size:.78rem;color:var(--ink)}
.finding{position:relative}
.finding[open]{background:var(--paper-2);box-shadow:var(--lift);border-radius:6px;z-index:1}
.finding[open]>summary{border-bottom:1px solid var(--hair-soft)}
.finding::before{content:"";position:absolute;left:-1px;top:0;bottom:0;width:2px;background:var(--s,var(--c-info));transform:scaleY(0);transform-origin:top;transition:transform .5s var(--settle)}
.finding[open]::before{transform:none}
.fs-critical{--s:var(--c-critical)}.fs-high{--s:var(--c-high)}.fs-medium{--s:var(--c-medium)}.fs-low{--s:var(--c-low)}.fs-info{--s:var(--c-info)}
.fbody{padding:1rem 1.25rem 1.25rem 7.25rem;display:grid;grid-template-columns:minmax(0,1fr) minmax(12rem,17rem);gap:1.75rem}
.rule-body .fbody{padding-left:1rem}
.fmain{display:flex;flex-direction:column;gap:1.1rem;min-width:0}
.fmain h3{font-size:.75rem;font-weight:600;color:var(--graphite);margin-bottom:.35rem;letter-spacing:0}
.fmain ul{padding-left:1rem;list-style:square}
.fmain li{overflow-wrap:anywhere}
.msg-text{white-space:pre-line;overflow-wrap:anywhere;max-width:46rem}
dl.facts{display:flex;flex-direction:column;font-size:.8125rem;min-width:0}
dl.facts dt{font-size:.72rem;color:var(--graphite);margin-top:.8rem}
dl.facts dt:first-child{margin-top:0}
dl.facts dd{margin-top:.1rem;overflow-wrap:anywhere}
dl.facts dd code{font-size:.78rem}
.tags{display:flex;flex-wrap:wrap;gap:.25rem .6rem}
.tags li{font-family:var(--mono);font-size:.74rem}

/* empty states */
.empty{display:flex;flex-direction:column;align-items:center;text-align:center;gap:.35rem;padding:3.5rem 1.5rem 3rem;border-bottom:1px solid var(--hair)}
.empty svg{width:4rem;height:4rem;margin-bottom:.9rem}
.empty .er{fill:none;stroke:var(--a-A);stroke-width:1.2;opacity:.45}
.empty .er2{fill:none;stroke:var(--a-A);stroke-width:1.2;opacity:.2}
.empty .ec{fill:none;stroke:var(--g-A);stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round}
.empty .eq{fill:none;stroke:var(--graphite);stroke-width:1.6;stroke-linecap:round}
.empty strong{font-size:1.25rem;font-weight:700;letter-spacing:-.02em}
.empty p{color:var(--graphite);max-width:32rem}

/* tables */
.table-wrap{overflow-x:auto;border-top:1px solid var(--ink)}
table{border-collapse:collapse;width:100%;font-size:.875rem}
th,td{text-align:left;padding:.75rem .6rem;border-bottom:1px solid var(--hair-soft);vertical-align:top}
th:first-child,td:first-child{padding-left:.25rem}
thead th{font-size:.75rem;font-weight:500;color:var(--graphite);white-space:nowrap;border-bottom-color:var(--hair)}
tbody tr{transition:background-color .2s}
tbody tr:hover{background:color-mix(in srgb,var(--paper-2) 70%,transparent)}
tbody th{font-weight:600}
tbody th code{font-size:.8rem}
tbody th .rid,td .rid{display:block;font-family:var(--sans);font-size:.8125rem;font-weight:400;color:var(--graphite)}
td.n,th.n{text-align:right;font-family:var(--mono);font-size:.8rem;font-variant-numeric:tabular-nums}
th button{all:unset;cursor:pointer;display:inline-flex;align-items:center;gap:.35rem;border-radius:3px}
th button:hover{color:var(--ink)}
th button:focus-visible{outline:2px solid var(--focus);outline-offset:3px}
th button::after{content:"";width:.38rem;height:.38rem;border-right:1.5px solid currentColor;border-bottom:1.5px solid currentColor;transform:rotate(45deg) translate(-1px,-1px);opacity:.35;transition:transform .4s var(--settle),opacity .2s}
th[aria-sort] button{color:var(--ink)}
th[aria-sort=ascending] button::after{transform:rotate(-135deg) translate(-1px,-1px);opacity:1}
th[aria-sort=descending] button::after{opacity:1}
.status{display:inline-flex;align-items:center;gap:.45rem}
.msg{white-space:pre-line;overflow-wrap:anywhere;color:var(--graphite);max-width:34rem}
.cats{font-size:.8125rem;color:var(--graphite)}
.runtime{padding:1.1rem 0 1.25rem}
.runtime h3{display:flex;justify-content:space-between;gap:1rem;font-size:.875rem;margin-bottom:.6rem}
.runtime h3 span{font-weight:400;color:var(--graphite);font-size:.8125rem}

/* standards */
.controls{border-top:1px solid var(--ink)}
.controls>li{border-bottom:1px solid var(--hair-soft)}
.ctrl>summary,.ctrl-row{display:grid;grid-template-columns:3.4rem minmax(0,1fr) auto;gap:1rem;align-items:center;padding:.7rem .25rem}
.ctrl>summary{transition:background-color .2s}
.ctrl>summary:hover{background:color-mix(in srgb,var(--paper-2) 70%,transparent)}
.ctrl>summary:focus-visible{outline-offset:-2px}
.cid{font-family:var(--mono);font-weight:500;font-size:.8rem;color:var(--accent)}
.ctitle{font-weight:600;overflow-wrap:anywhere}
.ctitle small{display:block;font-weight:400;color:var(--graphite);font-size:.72rem;font-family:var(--mono)}
.cside{display:flex;align-items:center;gap:.75rem;font-size:.8125rem;color:var(--graphite);white-space:nowrap}
.cside .mono{font-size:.75rem;color:var(--ink)}
.nf{display:inline-flex;align-items:center;gap:.4rem;color:var(--graphite);font-size:.78rem}
.nf::before{content:"";width:.7rem;height:1px;background:var(--graphite)}
.ctrl-row .ctitle{color:var(--graphite);font-weight:500}
.ctrl-row .cid{color:var(--graphite)}
.ctrl-body{padding:0 0 .8rem 4.65rem}
.ctrl-body .flist{border-left:1px solid var(--hair)}
.ctrl-body .frow{padding:.55rem .25rem .55rem 1rem;grid-template-columns:5.5rem minmax(0,1fr)}
.ctrl-body .frow .cat{display:none}
.two{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:2.5rem;align-items:start}

footer{padding:2rem 0 3rem;color:var(--graphite);font-size:.8125rem}
footer .wrap{display:flex;flex-wrap:wrap;gap:.4rem 2rem;border-top:1px solid var(--hair);padding-top:1.5rem;font-family:var(--mono);font-size:.74rem}

@media (max-width:78rem){
.hero{grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:1.75rem}
.two{grid-template-columns:1fr}
.rack-head,.ch{grid-template-columns:2.6rem minmax(8rem,1fr) minmax(7rem,.9fr) minmax(9rem,1.2fr)}
.rack-head span:last-child,.ch-dots{display:none}
}
@media (max-width:64rem){
:root{--rail:0}
.wrap,.frame{padding:0 1.25rem}
.js .frame{display:block}
.rail{position:sticky;top:0;z-index:30;max-height:none;overflow:visible;padding:0;margin:0 -1.25rem;background:color-mix(in srgb,var(--paper) 86%,transparent);-webkit-backdrop-filter:saturate(1.4) blur(14px);backdrop-filter:saturate(1.4) blur(14px);border-bottom:1px solid var(--hair);display:flex;align-items:center}
.mini{order:2;height:auto;margin:0 1.25rem 0 0;transform:translateX(6px);width:0;transition:opacity .25s,transform .5s var(--settle),width .4s var(--soft)}
.stuck .mini{height:auto;width:4.6rem;margin:0 1.25rem 0 .5rem;margin-bottom:0}
.tablist{flex-direction:row;gap:.15rem;overflow-x:auto;scrollbar-width:none;flex:1;min-width:0;padding:.5rem 1.25rem;-webkit-mask-image:linear-gradient(90deg,transparent 0,#000 1.25rem,#000 calc(100% - 2rem),transparent);mask-image:linear-gradient(90deg,transparent 0,#000 1.25rem,#000 calc(100% - 2rem),transparent)}
.tablist.at-start{-webkit-mask-image:linear-gradient(90deg,#000 calc(100% - 2rem),transparent);mask-image:linear-gradient(90deg,#000 calc(100% - 2rem),transparent)}
.tablist.at-end{-webkit-mask-image:linear-gradient(90deg,transparent 0,#000 1.25rem);mask-image:linear-gradient(90deg,transparent 0,#000 1.25rem)}
.tablist.at-start.at-end{-webkit-mask-image:none;mask-image:none}
.tablist::-webkit-scrollbar{display:none}
.tab{flex:none;display:inline-flex;gap:.4rem;align-items:baseline;padding:.45rem .65rem}
.tab[aria-selected=true]{background:none;box-shadow:none}
.tab.sep{margin-top:0;margin-left:.6rem}
.tab.sep::before{left:-.4rem;right:auto;top:.55rem;bottom:.55rem;border-top:0;border-left:1px solid var(--hair)}
.tg{font-size:.9rem}
.tg svg{width:.9rem;height:.9rem}
.ts,.tbar{display:none}
.tab-ink{top:auto;bottom:0;height:2px;width:1px}
.hero{grid-template-columns:1fr;gap:1rem;padding-top:.5rem}
.dial{max-width:21rem;justify-self:center}
}
@media (max-width:40rem){
.dl-menu{right:auto;left:0;transform-origin:top left}
.dl-f{display:none}
.mast h1{margin-top:1.1rem}
.meta{gap:.6rem 1.5rem}
.seg-labels{display:none}
.dial{max-width:16rem}
.legend{grid-template-columns:repeat(3,minmax(0,1fr));row-gap:.9rem}
.rack-head{display:none}
.ch{grid-template-columns:2.4rem minmax(0,1fr) auto;gap:.3rem .9rem}
.ch-grade{grid-row:1/3;font-size:1.9rem}
.ch-meter{grid-column:3;grid-row:1}
.ch-meter svg{display:none}
.ch-sev{grid-column:2/4;grid-row:2}
.frow,.row{grid-template-columns:minmax(0,1fr) auto;gap:.3rem .75rem}
.frow .sev,.row>.sev{grid-column:1;grid-row:1}
.frow .t,.row .main{grid-column:1/-1;grid-row:2}
.frow .cat,.row .side{grid-column:2;grid-row:1;justify-self:end}
.rule-body{margin-left:.4rem}
.rule-body .row{grid-template-columns:1rem minmax(0,1fr) auto;padding-left:.8rem}
.rule-body .row>.sev{grid-column:1;grid-row:1}
.rule-body .row .main{grid-column:2;grid-row:1}
.rule-body .row .side{grid-column:3;grid-row:1}
.fbody,.rule-body .fbody{grid-template-columns:1fr;padding:1rem;gap:1rem}
dl.facts{border-top:1px solid var(--hair);padding-top:.9rem}
.ctrl>summary,.ctrl-row{grid-template-columns:2.8rem minmax(0,1fr)}
.cside{grid-column:2}
.ctrl-body{padding-left:.4rem}
.field{flex:1 1 100%}
.cat-score{width:100%}
.table-wrap table,.table-wrap tbody,.table-wrap td,.table-wrap tbody th{display:block}
.table-wrap thead tr{display:flex;flex-wrap:wrap;gap:.4rem 1.1rem;padding:.8rem 0 .6rem;border-bottom:1px solid var(--hair)}
.table-wrap thead th{padding:0;border:0}
.table-wrap thead th.plain{display:none}
.table-wrap tbody tr{display:flex;flex-wrap:wrap;gap:.25rem 1rem;padding:.85rem .25rem;border-bottom:1px solid var(--hair-soft)}
.table-wrap tbody th,.table-wrap td{padding:0;border:0}
.table-wrap tbody th,.table-wrap td.cats,.table-wrap td.note{flex:1 1 100%}
.table-wrap td.eng,.table-wrap td.note:empty{display:none}
.table-wrap td.n{text-align:left}
.table-wrap td[data-label]::before{content:attr(data-label) " ";color:var(--graphite);font-family:var(--sans)}
.table-wrap td.n .rid{display:inline;margin-left:.3rem}
}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{transition-duration:0s!important;animation-duration:0s!important;scroll-behavior:auto!important}}
@media print{
:root{--paper:#fff;--paper-2:#fff;--paper-3:#f3f3f3}
body{background:#fff;font-size:10.5pt}
.rail,.toc,.actions,.filters,.toolbar,.skip{display:none!important}
.js .frame{display:block}
.panel[hidden]{display:block!important}
.panel+.panel,.js .panel+.panel{border-top:1px solid #999;margin-top:1.5rem;break-before:page}
.hero::before{display:none}
.finding[open]{box-shadow:none}
.finding,.row,.ch,.frow{break-inside:avoid}
details::details-content{content-visibility:visible;display:contents}
a{color:inherit}
pre{max-height:none}
}
`;
