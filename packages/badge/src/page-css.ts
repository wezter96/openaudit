/** The verification page's stylesheet, in the openaudit.se palette. */
export const PAGE_CSS = `
:root{color-scheme:light dark;--paper:#eef1f4;--paper-2:#f8fafb;--ink:#0d1522;--graphite:#4a5668;--hair:#c9d1db;--accent:#2340e8;--warn:#a1123a;--g-A:#0b7a4e;--g-B:#4f7a12;--g-C:#8c5600;--g-D:#b4380f;--g-F:#a1123a;--sans:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,"Helvetica Neue",Arial,sans-serif;--mono:ui-monospace,"SF Mono",SFMono-Regular,"JetBrains Mono",Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root{--paper:#0b111b;--paper-2:#111a27;--ink:#e7ecf3;--graphite:#9aa7b9;--hair:#2a374c;--accent:#8fa2ff;--warn:#ff8aa3;--g-A:#4fd49b;--g-B:#a6d96c;--g-C:#ffc46e;--g-D:#ff9f7a;--g-F:#ff8aa3}}
*{box-sizing:border-box}
html{background:var(--paper)}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 var(--sans)}
header,main,footer{max-width:52rem;margin:0 auto;padding:1rem}
header{display:flex;justify-content:space-between;border-bottom:1px solid var(--hair)}
.brand{font-weight:700;color:var(--ink);text-decoration:none}
a{color:var(--accent)}
h1{font-size:clamp(1.6rem,4vw,2.4rem);line-height:1.15;margin:.2rem 0 .6rem;overflow-wrap:anywhere}
h1 a{color:var(--ink);text-decoration:none}
h2{margin-top:2.4rem;padding-top:1rem;border-top:1px solid var(--hair);font-size:1.25rem}
h3{font-size:1.05rem}
.kicker{margin:1.5rem 0 0;color:var(--graphite);font:600 .8rem/1 var(--mono);text-transform:uppercase;letter-spacing:.08em}
.status{display:inline-block;padding:.2rem .6rem;border:1px solid var(--hair);border-radius:99px;font-size:.9rem}
.s-ok{border-color:var(--g-A);color:var(--g-A)}.s-failed{border-color:var(--warn);color:var(--warn)}
.warn{color:var(--warn);overflow-wrap:anywhere}
.preview img{max-width:100%;height:auto;vertical-align:middle;margin:.25rem 0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}
dt{color:var(--graphite)}dd{margin:0}
code,pre,.score,.cats b,td{font-family:var(--mono)}
.target{margin-top:1.5rem;padding:1rem;background:var(--paper-2);border:1px solid var(--hair);border-radius:.5rem}
.target h3{margin-top:0}
.cats{list-style:none;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(12rem,1fr));gap:.2rem 1rem}
.hidden{margin:.3rem 0 0;padding-left:1.1rem;overflow-wrap:anywhere}
.cats li{display:flex;justify-content:space-between;border-bottom:1px solid var(--hair)}
.g-A{color:var(--g-A)}.g-B{color:var(--g-B)}.g-C{color:var(--g-C)}.g-D{color:var(--g-D)}.g-F{color:var(--g-F)}
table{width:100%;border-collapse:collapse;font-size:.9rem;display:block;overflow-x:auto}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--hair)}
pre{background:var(--paper-2);border:1px solid var(--hair);border-radius:.4rem;padding:.75rem;overflow-x:auto;font-size:.85rem}
footer{color:var(--graphite);font-size:.9rem;border-top:1px solid var(--hair);margin-top:3rem}
`;
