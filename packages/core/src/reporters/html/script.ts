/*
 * Progressive enhancement for the HTML report. Without it every panel shows
 * stacked and complete; with it the panels become WAI-ARIA tabs (selected tab
 * in the URL hash), the findings get filters, and the page gets its motion:
 * one load sequence on the overview, and motion that answers the reader
 * (tab ink, panel slide, disclosure height, filter counts). Every listener is
 * delegated, so the page stays fast with thousands of findings. Reduced
 * motion shows final states immediately. Inlined and allowed by hash.
 */
export const SCRIPT = `
(function(){
"use strict";
var d=document,root=d.documentElement,w=window;
/* the page as served, before any of this runs, for the HTML download */
var pristine=root.cloneNode(true);
root.classList.add("js");
var still=!w.matchMedia||w.matchMedia("(prefers-reduced-motion: reduce)").matches||!root.animate;
var css=getComputedStyle(root);
var SETTLE=css.getPropertyValue("--settle").trim()||"ease-out",SOFT=css.getPropertyValue("--soft").trim()||"ease-out";
function anim(el,frames,o){if(still||!el)return null;try{return el.animate(frames,o);}catch(e){return null;}}
function closest(el,sel){while(el&&el.nodeType===1){if(el.matches(sel))return el;el=el.parentNode;}return null;}
function each(list,fn){Array.prototype.forEach.call(list,fn);}

var tablist=d.querySelector("[role=tablist]");
var tabs=tablist?[].slice.call(tablist.querySelectorAll("[role=tab]")):[];
var panels=tabs.map(function(t){return d.getElementById(t.getAttribute("aria-controls"));});
var bar=d.getElementById("tabbar"),ink=d.querySelector(".tab-ink");
var current=-1,seen={};

if(tabs.length){
bar.hidden=false;
var toc=d.getElementById("toc");if(toc)toc.hidden=true;
panels.forEach(function(p,i){p.setAttribute("role","tabpanel");p.setAttribute("aria-labelledby",tabs[i].id);p.tabIndex=0;});
}
each(d.querySelectorAll("[data-js]"),function(el){el.hidden=false;});

/* ---- tabs ---- */
function setHash(id,push){try{history[push?"pushState":"replaceState"](null,"","#"+id);}catch(e){}}
var wide=w.matchMedia?w.matchMedia("(min-width: 64.01rem)"):{matches:true};
function vertical(){return wide.matches;}
function moveInk(){
var t=tabs[current];if(!ink||!t)return;
tablist.setAttribute("aria-orientation",vertical()?"vertical":"horizontal");
ink.style.transform=vertical()?"translateY("+t.offsetTop+"px) scaleY("+t.offsetHeight+")":"translateX("+t.offsetLeft+"px) scaleX("+t.offsetWidth+")";
fades();
}
function fades(){if(!tablist)return;var max=tablist.scrollWidth-tablist.clientWidth;tablist.classList.toggle("at-start",tablist.scrollLeft<=2);tablist.classList.toggle("at-end",tablist.scrollLeft>=max-2);}
var frame=d.querySelector(".frame");
/* a host page may pin its own bar above the report; it sets scroll-margin-top on .frame */
function above(){return frame?parseFloat(w.getComputedStyle(frame).scrollMarginTop)||0:0;}
function topOfTabs(){var y=frame.getBoundingClientRect().top+w.pageYOffset-above();if(w.pageYOffset>y)w.scrollTo(0,y);}
function select(i,focus){
if(i<0||i>=tabs.length)return;
var prev=current;
tabs.forEach(function(t,j){var on=j===i;t.setAttribute("aria-selected",on?"true":"false");t.tabIndex=on?0:-1;panels[j].hidden=!on;});
if(focus)tabs[i].focus();
if(i!==prev){
current=i;topOfTabs();moveInk();
var t=tabs[i];if(!vertical()&&tablist.scrollWidth>tablist.clientWidth){var l=t.offsetLeft-tablist.clientWidth/2+t.offsetWidth/2;tablist.scrollTo({left:l,behavior:still?"auto":"smooth"});}
if(prev>=0){var dir=i>prev?1:-1,shift=vertical()?"translateY("+(dir*14)+"px)":"translateX("+(dir*18)+"px)";anim(panels[i],[{opacity:0,transform:shift},{opacity:1,transform:"none"}],{duration:460,easing:SOFT});}
enter(panels[i],prev<0);
}
}
function reveal(el){
var panel=closest(el,".panel");
if(panel&&tabs.length)select(panels.indexOf(panel));
if(el.hidden||closest(el.parentNode,"[hidden]")){var form=panel&&panel.querySelector("form.filters");if(form){form.reset();apply(form);}}
for(var p=el;p;p=p.parentNode){if(p.tagName==="DETAILS")p.open=true;}
var own=el.querySelector("details");if(own)own.open=true;
el.scrollIntoView({block:"start"});
var sum=el.querySelector("summary");(sum||el).focus({preventScroll:true});
anim(el,[{boxShadow:"0 0 0 3px var(--signal)"},{boxShadow:"0 0 0 3px transparent"}],{duration:1400,easing:"ease-out"});
}
function route(){
var id="";try{id=decodeURIComponent(location.hash.slice(1));}catch(e){}
var target=id&&d.getElementById(id);
if(!tabs.length){if(target&&target.tagName!=="SECTION")reveal(target);return;}
var i=-1;for(var j=0;j<panels.length;j++)if(panels[j].id===id)i=j;
if(i>=0){select(i);return;}
if(target&&closest(target,".panel")){reveal(target);return;}
select(current<0?0:current);
}
if(tablist){
tablist.addEventListener("click",function(ev){var t=closest(ev.target,"[role=tab]");if(!t)return;var i=tabs.indexOf(t);select(i);setHash(panels[i].id,true);});
tablist.addEventListener("keydown",function(ev){
var i=tabs.indexOf(ev.target);if(i<0)return;var n=tabs.length,k=ev.key,to=-1;
if(k==="ArrowRight"||k==="ArrowDown")to=(i+1)%n;else if(k==="ArrowLeft"||k==="ArrowUp")to=(i-1+n)%n;else if(k==="Home")to=0;else if(k==="End")to=n-1;
if(to<0)return;ev.preventDefault();select(to,true);setHash(panels[to].id,false);
});
w.addEventListener("resize",moveInk);
tablist.addEventListener("scroll",fades,{passive:true});
}
w.addEventListener("popstate",route);
w.addEventListener("hashchange",route);

/* the compact grade in the sticky bar appears once the masthead is gone */
var mast=d.querySelector(".mast");
if(mast&&bar&&w.IntersectionObserver){new IntersectionObserver(function(es){bar.classList.toggle("stuck",!es[0].isIntersecting);},{threshold:0,rootMargin:(-above())+"px 0px 0px 0px"}).observe(mast);}

/* ---- load sequence: the dial settles, the readout and rack follow ---- */
function count(el,to,ms){
if(still||!el)return;var t0=null;
function f(t){if(t0===null)t0=t;var k=Math.min(1,(t-t0)/ms),e=1-Math.pow(1-k,4);el.textContent=String(Math.round(to*e));if(k<1)requestAnimationFrame(f);}
el.textContent="0";requestAnimationFrame(f);
}
function draw(el,delay,ms){var v=Number(el.getAttribute("data-v"))||0;anim(el,[{strokeDashoffset:v},{strokeDashoffset:0}],{duration:ms,delay:delay,easing:SETTLE,fill:"backwards"});}
function enter(panel,first){
if(still||seen[panel.id])return;seen[panel.id]=true;
var dialEl=panel.querySelector("[data-dial]");
if(dialEl){
var ring=dialEl.querySelector(".ring");if(ring)draw(ring,first?120:40,1200);
each(dialEl.querySelectorAll(".seg"),function(s,i){draw(s,(first?260:60)+i*70,900);});
anim(dialEl.querySelector(".cap"),[{opacity:0},{opacity:1}],{duration:300,delay:first?1100:600,easing:"ease-out",fill:"backwards"});
var g=dialEl.querySelector(".dial-grade");anim(g,[{opacity:0,transform:"scale(.7)"},{opacity:1,transform:"none"}],{duration:900,delay:first?520:180,easing:SETTLE,fill:"backwards"});
count(dialEl.querySelector("[data-count]"),Number((dialEl.querySelector("[data-count]")||{}).textContent)||0,1200);
}
each(panel.querySelectorAll(".empty .ec"),function(c){anim(c,[{strokeDashoffset:1},{strokeDashoffset:0}],{duration:700,delay:first?600:220,easing:SOFT,fill:"backwards"});});
if(!first&&!dialEl)return;
function grow(rects,delay){each(rects,function(r,i){anim(r,[{transform:"scaleX(0)"},{transform:"none"}],{duration:700,delay:delay+i*60,easing:SOFT,fill:"backwards"});});}
grow(panel.querySelectorAll(".readout .spectrum rect"),first?420:120);
each(panel.querySelectorAll(".strip"),function(s){anim(s,[{clipPath:"inset(0 100% 0 0)"},{clipPath:"inset(0 0 0 0)"}],{duration:1100,delay:first?560:160,easing:SOFT,fill:"backwards"});});
each(panel.querySelectorAll(".legend li"),function(li,i){anim(li,[{opacity:0,transform:"translateY(6px)"},{opacity:1,transform:"none"}],{duration:600,delay:(first?480:140)+i*50,easing:SOFT,fill:"backwards"});});
each(panel.querySelectorAll("[data-rise]"),function(r,i){if(i>14)return;var at=(first?700:200)+i*45;anim(r,[{opacity:0,transform:"translateY(10px)"},{opacity:1,transform:"none"}],{duration:700,delay:at,easing:SOFT,fill:"backwards"});grow(r.querySelectorAll(".spectrum rect"),at+160);});
}

/* ---- disclosure with height animation (the report's own, not a host page's) ---- */
var running=new WeakMap();
d.addEventListener("click",function(ev){
var sum=closest(ev.target,"summary");if(!sum||still)return;
var det=sum.parentNode;if(!det||det.tagName!=="DETAILS"||ev.defaultPrevented||!closest(det,".frame"))return;
if(closest(ev.target,"a"))return;
ev.preventDefault();
var prev=running.get(det);if(prev){prev.cancel();}
var from=det.offsetHeight,opening=!det.open;
if(opening)det.open=true;
var to=opening?det.scrollHeight:sum.offsetHeight;
det.style.overflow="hidden";
var a=det.animate([{height:from+"px"},{height:to+"px"}],{duration:opening?520:340,easing:opening?SETTLE:SOFT});
running.set(det,a);
var body=sum.nextElementSibling;
if(opening&&body)anim(body,[{opacity:0,transform:"translateY(-4px)"},{opacity:1,transform:"none"}],{duration:380,delay:60,easing:SOFT,fill:"backwards"});
a.onfinish=function(){if(!opening)det.open=false;det.style.overflow="";running.delete(det);};
a.oncancel=function(){det.style.overflow="";};
});

/* ---- in-page links and actions ---- */
d.addEventListener("click",function(ev){
if(ev.button!==0||ev.metaKey||ev.ctrlKey||ev.shiftKey||ev.altKey)return;
var a=closest(ev.target,"a[href^='#']");
if(a){var id=a.getAttribute("href").slice(1),t=id&&d.getElementById(id);if(t&&tabs.length&&closest(t,".panel")){ev.preventDefault();setHash(id,true);route();}return;}
var b=closest(ev.target,"[data-action]");if(!b)return;
var act=b.getAttribute("data-action"),panel=closest(b,".panel");
if(act==="expand"||act==="collapse")toggleAll(panel,act==="expand");
else if(act==="menu")toggleMenu(menuOpen()?0:1);
else if(act==="download"){download(b);toggleMenu(0,true);}
else if(act==="copy-ai")copyAi(b);
else if(act==="print")w.print();
else if(act==="sort")sortTable(b);
});

/* ---- filters ---- */
var cache=new WeakMap();
function state(panel){
var s=cache.get(panel);
if(!s){s={items:[].slice.call(panel.querySelectorAll("li[data-sev]")),groups:[].slice.call(panel.querySelectorAll("li.rule-item")),text:null,shown:-1};cache.set(panel,s);}
return s;
}
function tween(el,from,to){
if(!el)return;if(still||from<0||from===to){el.textContent=String(to);return;}
var t0=null;function f(t){if(t0===null)t0=t;var k=Math.min(1,(t-t0)/380),e=1-Math.pow(1-k,3);el.textContent=String(Math.round(from+(to-from)*e));if(k<1)requestAnimationFrame(f);}
requestAnimationFrame(f);
}
function say(panel,text){var live=panel.querySelector("[data-live]");if(!live)return;clearTimeout(live._t);live._t=setTimeout(function(){live.textContent=text;},350);}
function apply(form,user){
var panel=closest(form,".panel");if(!panel)return;
if(form.getAttribute("data-kind")==="auditors")return applyAuditors(form,panel,user);
var s=state(panel),sev={},q=form.elements.q.value.trim().toLowerCase();
each(form.querySelectorAll("input[name=severity]"),function(i){sev[i.value]=i.checked;});
var aud=form.elements.auditor.value,conf=form.elements.confidence.value;
if(q&&!s.text)s.text=s.items.map(function(li){return li.textContent.toLowerCase();});
var shown=0,appeared=[];
s.items.forEach(function(li,i){
var c=li.getAttribute("data-conf");
var ok=sev[li.getAttribute("data-sev")]&&(!aud||li.getAttribute("data-auditors").indexOf(" "+aud+" ")!==-1)&&(!conf||(conf==="high"?c==="high":c!=="low"))&&(!q||s.text[i].indexOf(q)!==-1);
if(ok&&li.hidden)appeared.push(li);
li.hidden=!ok;if(ok)shown++;
});
var rules=0;
s.items.forEach(function(li){if(!li.hidden&&li.parentNode.classList.contains("rules"))rules++;});
s.groups.forEach(function(g){
var all=g.querySelectorAll("li[data-sev]"),n=0;for(var i=0;i<all.length;i++)if(!all[i].hidden)n++;
if(n&&g.hidden)appeared.push(g);
g.hidden=n===0;if(n)rules++;
var c=g.querySelector("[data-shown]");if(c)c.textContent=(n===all.length?String(n):n+" of "+all.length)+(all.length===1?" finding":" findings");
});
tween(panel.querySelector("[data-n]"),s.shown,shown);
var r=panel.querySelector("[data-r]");if(r){r.textContent=String(rules);r.nextSibling.textContent=rules===1?" rule":" rules";}
s.shown=shown;
if(user){say(panel,"Showing "+shown+" of "+s.items.length+" findings in "+rules+(rules===1?" rule":" rules"));
appeared.slice(0,40).forEach(function(el,i){anim(el,[{opacity:0,transform:"translateY(6px)"},{opacity:1,transform:"none"}],{duration:420,delay:i*18,easing:SOFT,fill:"backwards"});});}
var empty=panel.querySelector("[data-empty]");if(empty)empty.hidden=shown!==0;
}
function applyAuditors(form,panel,user){
var st=form.elements.status.value,q=form.elements.q.value.trim().toLowerCase();
var rows=panel.querySelectorAll("tbody tr"),shown=0,s=state(panel);
for(var i=0;i<rows.length;i++){var r=rows[i];var ok=(!st||r.getAttribute("data-status")===st)&&(!q||r.textContent.toLowerCase().indexOf(q)!==-1);r.hidden=!ok;if(ok)shown++;}
tween(panel.querySelector("[data-n]"),s.shown,shown);s.shown=shown;
if(user)say(panel,"Showing "+shown+" of "+rows.length+" auditors");
}
function onFilter(ev){var f=closest(ev.target,"form.filters");if(f)apply(f,true);}
d.addEventListener("input",onFilter);
d.addEventListener("change",onFilter);
d.addEventListener("submit",function(ev){if(closest(ev.target,"form.filters"))ev.preventDefault();});
d.addEventListener("reset",function(ev){var f=ev.target;if(f.matches&&f.matches("form.filters"))setTimeout(function(){apply(f,true);},0);});
function toggleAll(panel,open){
if(!panel)return;var ds=panel.querySelectorAll("details.rule,details.finding");
for(var i=0;i<ds.length;i++){if(!closest(ds[i],"[hidden]"))ds[i].open=open;}
}

/* ---- auditors table sorting ---- */
function sortTable(btn){
var th=closest(btn,"th"),table=closest(th,"table"),body=table.tBodies[0];
var key=btn.getAttribute("data-key"),num=btn.hasAttribute("data-num");
var dir=th.getAttribute("aria-sort")==="ascending"?"descending":"ascending";
each(table.querySelectorAll("thead th[aria-sort]"),function(h){h.removeAttribute("aria-sort");});
th.setAttribute("aria-sort",dir);
var rows=[].slice.call(body.rows),sign=dir==="ascending"?1:-1;
var before=new Map();if(!still)rows.forEach(function(r){before.set(r,r.getBoundingClientRect().top);});
rows.sort(function(a,b){var x=a.getAttribute("data-"+key),y=b.getAttribute("data-"+key);
return sign*(num?Number(x)-Number(y):x.localeCompare(y))||Number(a.getAttribute("data-i"))-Number(b.getAttribute("data-i"));});
var frag=d.createDocumentFragment();rows.forEach(function(r){frag.appendChild(r);});body.appendChild(frag);
if(!still)rows.forEach(function(r){var dy=before.get(r)-r.getBoundingClientRect().top;if(dy)anim(r,[{transform:"translateY("+dy+"px)"},{transform:"none"}],{duration:520,easing:SOFT});});
}

/* ---- downloads: every format is rendered at report time and embedded ---- */
/* what a host page added (a site's bar, its meta tags) stays with the host */
function savedPage(){
var page=pristine.cloneNode(true);
each(page.querySelectorAll("[data-host]"),function(n){n.parentNode.removeChild(n);});
page.removeAttribute("data-theme");
return "<!doctype html>\\n"+page.outerHTML+"\\n";
}
function download(btn){
var page=btn.getAttribute("data-page");
if(page)return save(savedPage(),"text/html",page);
var src=d.getElementById(btn.getAttribute("data-src"));if(!src)return;
var data=JSON.parse(src.textContent);
var text=src.getAttribute("data-format")==="json"?JSON.stringify(data,null,2)+"\\n":String(data);
save(text,src.getAttribute("data-type"),src.getAttribute("data-file"));
}
function save(text,type,file){
var url=URL.createObjectURL(new Blob([text],{type:type+";charset=utf-8"}));
var a=d.createElement("a");a.href=url;a.download=file||"openaudit-report";a.hidden=true;
d.body.appendChild(a);a.click();a.remove();
setTimeout(function(){URL.revokeObjectURL(url);},4000);
}
/* ---- copy for AI: the report with a plain-language prompt ---- */
function copyAi(btn){
var src=d.getElementById("data-ai"),label=btn.querySelector(".bl"),status=d.getElementById("copy-status");
if(!src)return;
var text=JSON.parse(src.textContent);
function done(ok){
if(status)status.textContent=ok?"Report copied. Paste it into an AI chat.":"Couldn't copy. Use Download, Markdown instead.";
if(!label)return;
label.textContent=ok?"Copied":"Couldn't copy";
clearTimeout(btn._t);btn._t=setTimeout(function(){label.textContent="Copy for AI";if(status)status.textContent="";},2500);
}
function fallback(){
var area=d.createElement("textarea");area.value=text;area.setAttribute("readonly","");
area.style.position="fixed";area.style.opacity="0";d.body.appendChild(area);area.select();
var ok=false;try{ok=d.execCommand("copy");}catch(e){}
area.remove();btn.focus();done(ok);
}
if(navigator.clipboard&&w.isSecureContext)navigator.clipboard.writeText(text).then(function(){done(true);},fallback);
else fallback();
}
var menuBtn=d.getElementById("dl-button"),menu=d.getElementById("dl-menu");
function items(){return menu?[].slice.call(menu.querySelectorAll("[role=menuitem]")):[];}
function menuOpen(){return menu&&!menu.hidden;}
/* how: 0 close, 1 open at first item, -1 open at last item */
function toggleMenu(how,refocus){
if(!menu)return;
if(!how){if(menu.hidden)return;menu.hidden=true;menuBtn.setAttribute("aria-expanded","false");if(refocus)menuBtn.focus();return;}
menu.hidden=false;menuBtn.setAttribute("aria-expanded","true");
/* keep the menu on screen wherever the button wrapped to */
menu.style.translate="";var mr=menu.getBoundingClientRect(),edge=12,dx=0;
if(mr.right>w.innerWidth-edge)dx=w.innerWidth-edge-mr.right;if(mr.left+dx<edge)dx=edge-mr.left;
if(dx)menu.style.translate=Math.round(dx)+"px 0";
var list=items();(how<0?list[list.length-1]:list[0]).focus();
anim(menu,[{opacity:0,transform:"translateY(-6px) scale(.98)"},{opacity:1,transform:"none"}],{duration:420,easing:SETTLE});
each(list,function(it,i){anim(it,[{opacity:0,transform:"translateY(-4px)"},{opacity:1,transform:"none"}],{duration:380,delay:40+i*35,easing:SOFT,fill:"backwards"});});
}
if(menu){
menuBtn.addEventListener("keydown",function(ev){if(ev.key==="ArrowDown"){ev.preventDefault();toggleMenu(1);}else if(ev.key==="ArrowUp"){ev.preventDefault();toggleMenu(-1);}});
menu.addEventListener("keydown",function(ev){
var list=items(),i=list.indexOf(d.activeElement),k=ev.key,to=-1;
if(k==="ArrowDown")to=(i+1)%list.length;else if(k==="ArrowUp")to=(i-1+list.length)%list.length;else if(k==="Home")to=0;else if(k==="End")to=list.length-1;
else if(k==="Escape"){ev.preventDefault();toggleMenu(0,true);return;}else if(k==="Tab"){toggleMenu(0);return;}
if(to<0)return;ev.preventDefault();list[to].focus();
});
d.addEventListener("click",function(ev){if(menuOpen()&&!closest(ev.target,".dl"))toggleMenu(0);});
}

/* ---- print everything: all panels (CSS) and all details ---- */
var reopened=[];
w.addEventListener("beforeprint",function(){reopened=[].filter.call(d.querySelectorAll("details:not([open])"),function(x){x.open=true;return true;});});
w.addEventListener("afterprint",function(){reopened.forEach(function(x){x.open=false;});reopened=[];});

each(d.querySelectorAll("form.filters"),function(f){apply(f,false);});
route();
if(bar)requestAnimationFrame(function(){moveInk();bar.classList.add("ready");});
})();
`;
