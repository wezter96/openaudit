/* openaudit HTML report: tabs, filters, downloads and motion (see script.ts) */
// biome-ignore format: compact on purpose, every report inlines this
(()=>{
// biome-ignore lint/suspicious/noRedundantUseStrict: the report inlines this as a classic script
"use strict";
const d=document;const root=d.documentElement;const w=window;
/* the page as served, before any of this runs, for the HTML download */
const pristine=root.cloneNode(true);
root.classList.add("js");
const still=calm();
const css=getComputedStyle(root);
const SETTLE=ease("--settle");const SOFT=ease("--soft");
function calm(){if(!w.matchMedia)return true;return w.matchMedia("(prefers-reduced-motion: reduce)").matches||!root.animate;}
function ease(name){return css.getPropertyValue(name).trim()||"ease-out";}
function anim(el,frames,o){if(still||!el)return null;try{return el.animate(frames,o);}catch{return null;}}
function closest(el,sel){return el&&el.nodeType===1?el.closest(sel):null;}
function each(list,fn){Array.prototype.forEach.call(list,fn);}

const tablist=d.querySelector("[role=tablist]");
const tabs=tablist?[].slice.call(tablist.querySelectorAll("[role=tab]")):[];
const panels=tabs.map((t)=>d.getElementById(t.getAttribute("aria-controls")));
const bar=d.getElementById("tabbar");const ink=d.querySelector(".tab-ink");
let current=-1;const seen={};
const wide=w.matchMedia?w.matchMedia("(min-width: 64.01rem)"):{matches:true};
const frame=d.querySelector(".frame");
/* arrow keys step through the tabs and the download menu; Home and End jump */
const TAB_KEYS=new Map([["ArrowRight",1],["ArrowDown",1],["ArrowLeft",-1],["ArrowUp",-1],["Home","first"],["End","last"]]);
const MENU_KEYS=new Map([["ArrowDown",1],["ArrowUp",-1],["Home","first"],["End","last"]]);
/* load sequence delays (ms) for the first panel shown, and for panels opened later */
const FIRST={ring:120,seg:260,cap:1100,grade:520,ec:600,bars:420,strip:560,legend:480,rise:700};
const LATER={ring:40,seg:60,cap:600,grade:180,ec:220,bars:120,strip:160,legend:140,rise:200};
const running=new WeakMap();
const cache=new WeakMap();
const MODIFIERS=["metaKey","ctrlKey","shiftKey","altKey"];
const ACTIONS=new Map([
["expand",(b)=>{toggleAll(closest(b,".panel"),true);}],
["collapse",(b)=>{toggleAll(closest(b,".panel"),false);}],
["menu",()=>{toggleMenu(menuOpen()?0:1);}],
["download",(b)=>{download(b);toggleMenu(0,true);}],
["copy-ai",copyAi],
["print",()=>{w.print();}],
["sort",sortTable]
]);
const menuBtn=d.getElementById("dl-button");const menu=d.getElementById("dl-menu");
let reopened=[];

showTabs();
each(d.querySelectorAll("[data-js]"),(el)=>{el.hidden=false;});
listenTabs();
w.addEventListener("popstate",route);
w.addEventListener("hashchange",route);
watchMast();
d.addEventListener("click",onSummary);
d.addEventListener("click",onClick);
d.addEventListener("input",onFilter);
d.addEventListener("change",onFilter);
d.addEventListener("submit",onSubmit);
d.addEventListener("reset",onReset);
listenMenu();
w.addEventListener("beforeprint",openAll);
w.addEventListener("afterprint",closeAgain);
each(d.querySelectorAll("form.filters"),(f)=>{apply(f,false);});
route();
if(bar)requestAnimationFrame(()=>{moveInk();bar.classList.add("ready");});

/* ---- tabs ---- */
function showTabs(){
if(!tabs.length)return;
bar.hidden=false;
const toc=d.getElementById("toc");if(toc)toc.hidden=true;
panels.forEach((p,i)=>{p.setAttribute("role","tabpanel");p.setAttribute("aria-labelledby",tabs[i].id);p.tabIndex=0;});
}
function listenTabs(){
if(!tablist)return;
tablist.addEventListener("click",onTabClick);
tablist.addEventListener("keydown",onTabKey);
w.addEventListener("resize",moveInk);
tablist.addEventListener("scroll",fades,{passive:true});
}
function setHash(id,push){try{history[push?"pushState":"replaceState"](null,"",`#${id}`);}catch{}}
function vertical(){return wide.matches;}
function moveInk(){
const t=tabs[current];if(!ink||!t)return;
tablist.setAttribute("aria-orientation",vertical()?"vertical":"horizontal");
ink.style.transform=vertical()?`translateY(${t.offsetTop}px) scaleY(${t.offsetHeight})`:`translateX(${t.offsetLeft}px) scaleX(${t.offsetWidth})`;
fades();
}
function fades(){if(!tablist)return;const max=tablist.scrollWidth-tablist.clientWidth;tablist.classList.toggle("at-start",tablist.scrollLeft<=2);tablist.classList.toggle("at-end",tablist.scrollLeft>=max-2);}
/* a host page may pin its own bar above the report; it sets scroll-margin-top on .frame */
function above(){return frame?Number.parseFloat(w.getComputedStyle(frame).scrollMarginTop)||0:0;}
function topOfTabs(){const y=frame.getBoundingClientRect().top+w.pageYOffset-above();if(w.pageYOffset>y)w.scrollTo(0,y);}
function select(i,focus){
if(i<0||i>=tabs.length)return;
const prev=current;
tabs.forEach((_t,j)=>{mark(j,j===i);});
if(focus)tabs[i].focus();
if(i!==prev)arrive(i,prev);
}
function mark(j,on){const t=tabs[j];t.setAttribute("aria-selected",on?"true":"false");t.tabIndex=on?0:-1;panels[j].hidden=!on;}
function arrive(i,prev){
current=i;topOfTabs();moveInk();
centre(tabs[i]);
if(prev>=0)slide(panels[i],i>prev?1:-1);
enter(panels[i],prev<0);
}
/* a tab scrolled out of a horizontal bar comes back to its middle */
function centre(t){
if(vertical()||tablist.scrollWidth<=tablist.clientWidth)return;
const l=t.offsetLeft-tablist.clientWidth/2+t.offsetWidth/2;tablist.scrollTo({left:l,behavior:still?"auto":"smooth"});
}
function slide(panel,dir){const shift=vertical()?`translateY(${dir*14}px)`:`translateX(${dir*18}px)`;anim(panel,[{opacity:0,transform:shift},{opacity:1,transform:"none"}],{duration:460,easing:SOFT});}
function reveal(el){
const panel=closest(el,".panel");
if(panel&&tabs.length)select(panels.indexOf(panel));
if(filteredOut(el))unfilter(panel);
openAround(el);
el.scrollIntoView({block:"start"});
const sum=el.querySelector("summary");(sum||el).focus({preventScroll:true});
anim(el,[{boxShadow:"0 0 0 3px var(--signal)"},{boxShadow:"0 0 0 3px transparent"}],{duration:1400,easing:"ease-out"});
}
function filteredOut(el){return el.hidden||closest(el.parentNode,"[hidden]");}
function unfilter(panel){const form=panel?.querySelector("form.filters");if(form){form.reset();apply(form);}}
function openAround(el){
for(let p=closest(el,"details");p;p=closest(p.parentNode,"details"))p.open=true;
const own=el.querySelector("details");if(own)own.open=true;
}
function hashId(){try{return decodeURIComponent(location.hash.slice(1));}catch{return "";}}
function panelIndex(id){return panels.map((p)=>p.id).lastIndexOf(id);}
function route(){
const id=hashId();const target=id&&d.getElementById(id);
if(!tabs.length){routeStacked(target);return;}
const i=panelIndex(id);
if(i>=0){select(i);return;}
if(inTab(target)){reveal(target);return;}
select(current<0?0:current);
}
function routeStacked(target){if(target&&target.tagName!=="SECTION")reveal(target);}
function inTab(el){if(!el||!tabs.length)return false;return closest(el,".panel")!==null;}
function onTabClick(ev){const t=closest(ev.target,"[role=tab]");if(!t)return;const i=tabs.indexOf(t);select(i);setHash(panels[i].id,true);}
function onTabKey(ev){
const i=tabs.indexOf(ev.target);if(i<0)return;
const to=stepTo(TAB_KEYS.get(ev.key),i,tabs.length);
if(to<0)return;ev.preventDefault();select(to,true);setHash(panels[to].id,false);
}
/* move: 1 next, -1 previous (both wrap), "first", "last", or none (-1) */
function stepTo(move,i,n){
if(move==="first")return 0;
if(move==="last")return n-1;
return move?(i+move+n)%n:-1;
}

/* the compact grade in the sticky bar appears once the masthead is gone */
function watchMast(){
const mast=d.querySelector(".mast");
if(!mast||!bar)return;
if(!w.IntersectionObserver)return;
new IntersectionObserver((es)=>{bar.classList.toggle("stuck",!es[0].isIntersecting);},{threshold:0,rootMargin:`${-above()}px 0px 0px 0px`}).observe(mast);
}

/* ---- load sequence: the dial settles, the readout and rack follow ---- */
/* calls step with the eased progress (0 to 1) on every frame for ms */
function play(ms,power,step){
let t0=null;
function f(t){if(t0===null)t0=t;const k=Math.min(1,(t-t0)/ms);step(1-(1-k)**power);if(k<1)requestAnimationFrame(f);}
requestAnimationFrame(f);
}
function count(el,ms){
if(still||!el)return;
const to=Number(el.textContent)||0;
el.textContent="0";play(ms,4,(e)=>{el.textContent=String(Math.round(to*e));});
}
function draw(el,delay,ms){const v=Number(el.getAttribute("data-v"))||0;anim(el,[{strokeDashoffset:v},{strokeDashoffset:0}],{duration:ms,delay:delay,easing:SETTLE,fill:"backwards"});}
function enter(panel,first){
if(still||seen[panel.id])return;seen[panel.id]=true;
const at=first?FIRST:LATER;
const dialEl=panel.querySelector("[data-dial]");
if(dialEl)settle(dialEl,at);
each(panel.querySelectorAll(".empty .ec"),(c)=>{anim(c,[{strokeDashoffset:1},{strokeDashoffset:0}],{duration:700,delay:at.ec,easing:SOFT,fill:"backwards"});});
if(first||dialEl)rise(panel,at);
}
function settle(dial,at){
const ring=dial.querySelector(".ring");if(ring)draw(ring,at.ring,1200);
each(dial.querySelectorAll(".seg"),(s,i)=>{draw(s,at.seg+i*70,900);});
anim(dial.querySelector(".cap"),[{opacity:0},{opacity:1}],{duration:300,delay:at.cap,easing:"ease-out",fill:"backwards"});
anim(dial.querySelector(".dial-grade"),[{opacity:0,transform:"scale(.7)"},{opacity:1,transform:"none"}],{duration:900,delay:at.grade,easing:SETTLE,fill:"backwards"});
count(dial.querySelector("[data-count]"),1200);
}
function rise(panel,at){
grow(panel.querySelectorAll(".readout .spectrum rect"),at.bars);
each(panel.querySelectorAll(".strip"),(s)=>{anim(s,[{clipPath:"inset(0 100% 0 0)"},{clipPath:"inset(0 0 0 0)"}],{duration:1100,delay:at.strip,easing:SOFT,fill:"backwards"});});
each(panel.querySelectorAll(".legend li"),(li,i)=>{anim(li,[{opacity:0,transform:"translateY(6px)"},{opacity:1,transform:"none"}],{duration:600,delay:at.legend+i*50,easing:SOFT,fill:"backwards"});});
each(panel.querySelectorAll("[data-rise]"),(r,i)=>{if(i>14)return;const t=at.rise+i*45;anim(r,[{opacity:0,transform:"translateY(10px)"},{opacity:1,transform:"none"}],{duration:700,delay:t,easing:SOFT,fill:"backwards"});grow(r.querySelectorAll(".spectrum rect"),t+160);});
}
function grow(rects,delay){each(rects,(r,i)=>{anim(r,[{transform:"scaleX(0)"},{transform:"none"}],{duration:700,delay:delay+i*60,easing:SOFT,fill:"backwards"});});}

/* ---- disclosure with height animation (the report's own, not a host page's) ---- */
function onSummary(ev){
const sum=closest(ev.target,"summary");if(!sum||still)return;
const det=sum.parentNode;if(!ownDisclosure(det,ev))return;
ev.preventDefault();
toggleDetails(det,sum);
}
function ownDisclosure(det,ev){
if(det?.tagName!=="DETAILS")return false;
if(ev.defaultPrevented)return false;
return closest(det,".frame")!==null&&!closest(ev.target,"a");
}
function toggleDetails(det,sum){
const prev=running.get(det);if(prev)prev.cancel();
const opening=!det.open;
const a=resize(det,sum,opening);
running.set(det,a);
const body=sum.nextElementSibling;
if(opening&&body)anim(body,[{opacity:0,transform:"translateY(-4px)"},{opacity:1,transform:"none"}],{duration:380,delay:60,easing:SOFT,fill:"backwards"});
a.onfinish=()=>{if(!opening)det.open=false;det.style.overflow="";running.delete(det);};
a.oncancel=()=>{det.style.overflow="";};
}
function resize(det,sum,opening){
const from=det.offsetHeight;
if(opening)det.open=true;
const to=opening?det.scrollHeight:sum.offsetHeight;
det.style.overflow="hidden";
return det.animate([{height:`${from}px`},{height:`${to}px`}],{duration:opening?520:340,easing:opening?SETTLE:SOFT});
}

/* ---- in-page links and actions ---- */
function onClick(ev){
if(!plainClick(ev))return;
const a=closest(ev.target,"a[href^='#']");
if(a){follow(a,ev);return;}
const b=closest(ev.target,"[data-action]");
if(b)act(b);
}
function plainClick(ev){return ev.button===0&&!MODIFIERS.some((k)=>ev[k]);}
function follow(a,ev){
const id=a.getAttribute("href").slice(1);const t=id&&d.getElementById(id);
if(!inTab(t))return;
ev.preventDefault();setHash(id,true);route();
}
function act(b){const run=ACTIONS.get(b.getAttribute("data-action"));if(run)run(b);}

/* ---- filters ---- */
function state(panel){
let s=cache.get(panel);
if(!s){s={items:[].slice.call(panel.querySelectorAll("li[data-sev]")),groups:[].slice.call(panel.querySelectorAll("li.rule-item")),text:null,shown:-1};cache.set(panel,s);}
return s;
}
function tween(el,from,to){
if(!el)return;
if(instant(from,to)){el.textContent=String(to);return;}
play(380,3,(e)=>{el.textContent=String(Math.round(from+(to-from)*e));});
}
function instant(from,to){return still||from<0||from===to;}
function say(panel,text){const live=panel.querySelector("[data-live]");if(!live)return;clearTimeout(live._t);live._t=setTimeout(()=>{live.textContent=text;},350);}
function apply(form,user){
const panel=closest(form,".panel");if(!panel)return;
if(form.getAttribute("data-kind")==="auditors")return applyAuditors(form,panel,user);
const s=state(panel);const tally={shown:0,rules:0,appeared:[]};
filterItems(s,criteria(form,s),tally);
countRules(s,tally);
tween(panel.querySelector("[data-n]"),s.shown,tally.shown);
showRules(panel,tally.rules);
s.shown=tally.shown;
if(user)announce(panel,s.items.length,tally);
const empty=panel.querySelector("[data-empty]");if(empty)empty.hidden=tally.shown!==0;
}
function criteria(form,s){
const q=form.elements.q.value.trim().toLowerCase();const sev={};
each(form.querySelectorAll("input[name=severity]"),(i)=>{sev[i.value]=i.checked;});
if(q&&!s.text)s.text=s.items.map((li)=>li.textContent.toLowerCase());
return {q,sev,aud:form.elements.auditor.value,conf:form.elements.confidence.value,text:s.text};
}
function matches(li,i,f){
if(!f.sev[li.getAttribute("data-sev")])return false;
if(f.aud&&li.getAttribute("data-auditors").indexOf(` ${f.aud} `)===-1)return false;
if(!confident(li.getAttribute("data-conf"),f.conf))return false;
return !f.q||f.text[i].indexOf(f.q)!==-1;
}
function confident(c,conf){if(!conf)return true;return conf==="high"?c==="high":c!=="low";}
function filterItems(s,f,tally){
s.items.forEach((li,i)=>{
const ok=matches(li,i,f);
if(ok&&li.hidden)tally.appeared.push(li);
li.hidden=!ok;if(ok)tally.shown++;
});
}
/* a finding listed straight in .rules is a rule of its own; the rest count by group */
function countRules(s,tally){
s.items.forEach((li)=>{if(loose(li))tally.rules++;});
s.groups.forEach((g)=>{if(showGroup(g,tally))tally.rules++;});
}
function loose(li){return !li.hidden&&li.parentNode.classList.contains("rules");}
function showGroup(g,tally){
const all=g.querySelectorAll("li[data-sev]");const n=visible(all);
if(n&&g.hidden)tally.appeared.push(g);
g.hidden=n===0;
const c=g.querySelector("[data-shown]");if(c)c.textContent=shownLabel(n,all.length);
return n>0;
}
function visible(list){return [].filter.call(list,(x)=>!x.hidden).length;}
function shownLabel(n,total){return (n===total?String(n):`${n} of ${total}`)+(total===1?" finding":" findings");}
function showRules(panel,rules){const r=panel.querySelector("[data-r]");if(!r)return;r.textContent=String(rules);r.nextSibling.textContent=rules===1?" rule":" rules";}
function announce(panel,total,tally){
say(panel,`Showing ${tally.shown} of ${total} findings in ${tally.rules}${tally.rules===1?" rule":" rules"}`);
tally.appeared.slice(0,40).forEach((el,i)=>{anim(el,[{opacity:0,transform:"translateY(6px)"},{opacity:1,transform:"none"}],{duration:420,delay:i*18,easing:SOFT,fill:"backwards"});});
}
function applyAuditors(form,panel,user){
const st=form.elements.status.value;const q=form.elements.q.value.trim().toLowerCase();
const rows=panel.querySelectorAll("tbody tr");const s=state(panel);let shown=0;
each(rows,(r)=>{const ok=rowMatches(r,st,q);r.hidden=!ok;if(ok)shown++;});
tween(panel.querySelector("[data-n]"),s.shown,shown);s.shown=shown;
if(user)say(panel,`Showing ${shown} of ${rows.length} auditors`);
}
function rowMatches(r,st,q){
if(st&&r.getAttribute("data-status")!==st)return false;
return !q||r.textContent.toLowerCase().indexOf(q)!==-1;
}
function onFilter(ev){const f=closest(ev.target,"form.filters");if(f)apply(f,true);}
function onSubmit(ev){if(closest(ev.target,"form.filters"))ev.preventDefault();}
function onReset(ev){const f=ev.target;if(f.matches?.("form.filters"))setTimeout(()=>{apply(f,true);},0);}
function toggleAll(panel,open){
if(!panel)return;
each(panel.querySelectorAll("details.rule,details.finding"),(x)=>{if(!closest(x,"[hidden]"))x.open=open;});
}

/* ---- auditors table sorting ---- */
function sortTable(btn){
const th=closest(btn,"th");const table=closest(th,"table");const body=table.tBodies[0];
const dir=th.getAttribute("aria-sort")==="ascending"?"descending":"ascending";
each(table.querySelectorAll("thead th[aria-sort]"),(h)=>{h.removeAttribute("aria-sort");});
th.setAttribute("aria-sort",dir);
const rows=[].slice.call(body.rows);const before=tops(rows);
rows.sort(byColumn(btn.getAttribute("data-key"),btn.hasAttribute("data-num"),dir==="ascending"?1:-1));
const frag=d.createDocumentFragment();rows.forEach((r)=>{frag.appendChild(r);});body.appendChild(frag);
glide(rows,before);
}
function tops(rows){const at=new Map();if(!still)rows.forEach((r)=>{at.set(r,r.getBoundingClientRect().top);});return at;}
function byColumn(key,num,sign){
return (a,b)=>{const x=a.getAttribute(`data-${key}`);const y=b.getAttribute(`data-${key}`);
return sign*(num?Number(x)-Number(y):x.localeCompare(y))||Number(a.getAttribute("data-i"))-Number(b.getAttribute("data-i"));};
}
/* rows slide from where they were to where the sort put them */
function glide(rows,before){
if(still)return;
rows.forEach((r)=>{const dy=before.get(r)-r.getBoundingClientRect().top;if(dy)anim(r,[{transform:`translateY(${dy}px)`},{transform:"none"}],{duration:520,easing:SOFT});});
}

/* ---- downloads: every format is rendered at report time and embedded ---- */
/* what a host page added (a site's bar, its meta tags) stays with the host */
function savedPage(){
const page=pristine.cloneNode(true);
each(page.querySelectorAll("[data-host]"),(n)=>{n.parentNode.removeChild(n);});
page.removeAttribute("data-theme");
return `<!doctype html>\n${page.outerHTML}\n`;
}
function download(btn){
const page=btn.getAttribute("data-page");
if(page)return save(savedPage(),"text/html",page);
const src=d.getElementById(btn.getAttribute("data-src"));if(!src)return;
const data=JSON.parse(src.textContent);
const text=src.getAttribute("data-format")==="json"?`${JSON.stringify(data,null,2)}\n`:String(data);
save(text,src.getAttribute("data-type"),src.getAttribute("data-file"));
}
function save(text,type,file){
const url=URL.createObjectURL(new Blob([text],{type:`${type};charset=utf-8`}));
const a=d.createElement("a");a.href=url;a.download=file||"openaudit-report";a.hidden=true;
d.body.appendChild(a);a.click();a.remove();
setTimeout(()=>{URL.revokeObjectURL(url);},4000);
}
/* ---- copy for AI: the report with a plain-language prompt ---- */
function copyAi(btn){
const src=d.getElementById("data-ai");
const c={btn,label:btn.querySelector(".bl"),status:d.getElementById("copy-status")};
if(!src)return;
c.text=JSON.parse(src.textContent);
if(navigator.clipboard&&w.isSecureContext)navigator.clipboard.writeText(c.text).then(()=>{copied(c,true);},()=>{copyByHand(c);});
else copyByHand(c);
}
function copied(c,ok){
if(c.status)c.status.textContent=ok?"Report copied. Paste it into an AI chat.":"Couldn't copy. Use Download, Markdown instead.";
if(!c.label)return;
c.label.textContent=ok?"Copied":"Couldn't copy";
clearTimeout(c.btn._t);c.btn._t=setTimeout(()=>{c.label.textContent="Copy for AI";if(c.status)c.status.textContent="";},2500);
}
function copyByHand(c){
const area=d.createElement("textarea");area.value=c.text;area.setAttribute("readonly","");
area.style.position="fixed";area.style.opacity="0";d.body.appendChild(area);area.select();
let ok=false;try{ok=d.execCommand("copy");}catch{}
area.remove();c.btn.focus();copied(c,ok);
}

/* ---- download menu ---- */
function listenMenu(){
if(!menu)return;
menuBtn.addEventListener("keydown",onMenuButtonKey);
menu.addEventListener("keydown",onMenuKey);
d.addEventListener("click",onOutsideMenu);
}
function items(){return menu?[].slice.call(menu.querySelectorAll("[role=menuitem]")):[];}
function menuOpen(){return menu&&!menu.hidden;}
/* how: 0 close, 1 open at first item, -1 open at last item */
function toggleMenu(how,refocus){
if(!menu)return;
if(how)openMenu(how);else closeMenu(refocus);
}
function closeMenu(refocus){if(menu.hidden)return;menu.hidden=true;menuBtn.setAttribute("aria-expanded","false");if(refocus)menuBtn.focus();}
function openMenu(how){
menu.hidden=false;menuBtn.setAttribute("aria-expanded","true");
keepOnScreen();
const list=items();(how<0?list[list.length-1]:list[0]).focus();
anim(menu,[{opacity:0,transform:"translateY(-6px) scale(.98)"},{opacity:1,transform:"none"}],{duration:420,easing:SETTLE});
each(list,(it,i)=>{anim(it,[{opacity:0,transform:"translateY(-4px)"},{opacity:1,transform:"none"}],{duration:380,delay:40+i*35,easing:SOFT,fill:"backwards"});});
}
/* keep the menu on screen wherever the button wrapped to */
function keepOnScreen(){
menu.style.translate="";const mr=menu.getBoundingClientRect();const edge=12;let dx=0;
if(mr.right>w.innerWidth-edge)dx=w.innerWidth-edge-mr.right;
if(mr.left+dx<edge)dx=edge-mr.left;
if(dx)menu.style.translate=`${Math.round(dx)}px 0`;
}
function onMenuButtonKey(ev){
if(ev.key==="ArrowDown"){ev.preventDefault();toggleMenu(1);}
else if(ev.key==="ArrowUp"){ev.preventDefault();toggleMenu(-1);}
}
function onMenuKey(ev){
const k=ev.key;
if(k==="Escape"){ev.preventDefault();toggleMenu(0,true);return;}
if(k==="Tab"){toggleMenu(0);return;}
const list=items();const to=stepTo(MENU_KEYS.get(k),list.indexOf(d.activeElement),list.length);
if(to<0)return;ev.preventDefault();list[to].focus();
}
function onOutsideMenu(ev){if(menuOpen()&&!closest(ev.target,".dl"))toggleMenu(0);}

/* ---- print everything: all panels (CSS) and all details ---- */
function openAll(){reopened=[].filter.call(d.querySelectorAll("details:not([open])"),(x)=>{x.open=true;return true;});}
function closeAgain(){reopened.forEach((x)=>{x.open=false;});reopened=[];}
})();
