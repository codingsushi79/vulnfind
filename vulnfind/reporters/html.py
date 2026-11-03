"""Self-contained interactive HTML report (no external assets)."""

from __future__ import annotations

import html
import json

from ..models import CATEGORIES, ScanResult
from .formats import to_json

TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vulnfind report · __TITLE__</title>
<style>
:root{--bg:#f7f7f8;--card:#fff;--fg:#17171c;--muted:#6b6b76;--line:#e4e4e9;--crit:#a3127f;--high:#d42a2a;--med:#c27c00;--low:#2f6fd6;--info:#7a7a85;--ok:#1a8a4a;--chip:#efeff3}
@media (prefers-color-scheme:dark){:root{--bg:#0f0f13;--card:#18181e;--fg:#ececf1;--muted:#9a9aa6;--line:#2a2a33;--crit:#e05bc4;--high:#ff6464;--med:#f0b23c;--low:#6aa0ff;--info:#9a9aa6;--ok:#4cc782;--chip:#24242c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:22px;margin:0}h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:32px 0 10px}
.sub{color:var(--muted);margin-top:4px;word-break:break-all}
.top{display:flex;gap:24px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.grade{font-size:44px;font-weight:800;width:84px;height:84px;border-radius:18px;display:grid;place-items:center;color:#fff}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-top:24px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;cursor:pointer;user-select:none}
.tile b{display:block;font-size:26px;font-variant-numeric:tabular-nums}.tile span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.tile.off{opacity:.35}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin-top:18px}
input[type=search]{flex:1;min-width:200px;padding:9px 12px;border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--fg);font:inherit}
.chip{padding:7px 12px;border-radius:999px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer;font:inherit}
.chip.on{background:var(--fg);color:var(--bg);border-color:var(--fg)}
.f{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--sev);border-radius:10px;padding:12px 16px;margin:8px 0}
.f summary{cursor:pointer;list-style:none;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}.f summary::-webkit-details-marker{display:none}
.sev{font-size:11px;font-weight:700;letter-spacing:.05em;color:var(--sev);min-width:64px}
.title{font-weight:600;flex:1;min-width:200px}.loc{color:var(--muted);font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
pre{background:var(--chip);padding:8px 10px;border-radius:8px;overflow-x:auto;font-size:12px;margin:10px 0 6px;white-space:pre-wrap;word-break:break-all}
.fix{color:var(--ok);margin:6px 0}.desc{color:var(--muted);margin:6px 0}.meta{font-size:12px;color:var(--muted)}
.meta a{color:var(--low)}.flow{margin:8px 0;padding-left:14px;border-left:2px solid var(--crit);font:12px/1.7 ui-monospace,Menlo,monospace;color:var(--muted)}
.flow div:first-child,.flow div:last-child{color:var(--fg)}.badge{display:inline-block;font-size:11px;font-weight:700;padding:1px 7px;border-radius:999px;margin-left:6px;vertical-align:1px}
.kev{background:var(--high);color:#fff}.epss{background:var(--chip);color:var(--fg)}.prio{color:var(--muted);font-size:11px;font-variant-numeric:tabular-nums;min-width:28px;text-align:right}
.ctx{color:var(--muted);font-size:12px;margin:4px 0}.empty{padding:40px;text-align:center;color:var(--muted)}
.warn{background:color-mix(in srgb,var(--med) 15%,transparent);border-radius:10px;padding:10px 14px;margin-top:14px}
footer{margin-top:40px;color:var(--muted);font-size:12px}
</style>
</head>
<body>
<main>
<div class="top">
  <div><h1>vulnfind security report</h1><div class="sub" id="root"></div><div class="sub" id="stats"></div></div>
  <div style="display:flex;gap:14px;align-items:center"><div style="text-align:right"><div class="sub">Security grade</div><div id="score" style="font-weight:600"></div></div><div class="grade" id="grade"></div></div>
</div>
<div class="tiles" id="tiles"></div>
<div id="warnings"></div>
<div class="controls"><input type="search" id="q" placeholder="Filter by file, package, CVE, rule…"><span id="cats"></span></div>
<div id="list"></div>
<footer id="foot"></footer>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById('data').textContent);
const CATS = __CATS__;
const SEVS = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
const VAR = {CRITICAL:'--crit',HIGH:'--high',MEDIUM:'--med',LOW:'--low',INFO:'--info'};
const GRADE = {A:'--ok',B:'--ok',C:'--med',D:'--high',F:'--crit'};
const state = {sev:new Set(SEVS), cat:null, q:''};
D.findings.sort((a,b) => (b.extra && b.extra.priority || 0) - (a.extra && a.extra.priority || 0));
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const $ = id => document.getElementById(id);
const S = D.summary;
$('root').textContent = D.root;
$('stats').textContent = `${S.files_scanned} files · ${S.packages} packages · ${S.manifests.length} manifests · ${S.suppressed} suppressed · ${S.duration_seconds}s · ${D.generated_at}`;
$('grade').textContent = S.grade; $('grade').style.background = `var(${GRADE[S.grade]})`;
$('score').textContent = `${S.score}/100`;
$('foot').textContent = `Generated by vulnfind ${D.tool.version}. Vulnerability data from OSV.dev.`;
$('warnings').innerHTML = D.warnings.map(w => `<div class="warn">${esc(w)}</div>`).join('');
$('tiles').innerHTML = SEVS.map(s => `<div class="tile" data-sev="${s}" style="border-top:3px solid var(${VAR[s]})"><b style="color:var(${VAR[s]})">${S.counts[s]}</b><span>${s.toLowerCase()}</span></div>`).join('');
document.querySelectorAll('.tile').forEach(t => t.onclick = () => { const s=t.dataset.sev; state.sev.has(s)?state.sev.delete(s):state.sev.add(s); t.classList.toggle('off'); draw(); });
const present = Object.keys(CATS).filter(c => D.findings.some(f => f.category === c));
$('cats').innerHTML = `<button class="chip on" data-cat="">All</button>` + present.map(c => `<button class="chip" data-cat="${c}">${esc(CATS[c])}</button>`).join(' ');
document.querySelectorAll('.chip').forEach(b => b.onclick = () => { state.cat = b.dataset.cat || null; document.querySelectorAll('.chip').forEach(x => x.classList.toggle('on', x===b)); draw(); });
$('q').oninput = e => { state.q = e.target.value.toLowerCase(); draw(); };
function card(f){
  const ids = (f.extra && f.extra.aliases) ? f.extra.aliases.join(' · ') : f.rule_id;
  const refs = (f.references||[]).slice(0,4).map(r => `<a href="${esc(r)}" target="_blank" rel="noopener">${esc(r.replace(/^https?:\/\//,'').slice(0,60))}</a>`).join(' · ');
  const cvss = f.extra && f.extra.cvss ? ` · CVSS ${f.extra.cvss}` : '';
  const x = f.extra || {};
  const ctx = x.context ? ` · ${esc(x.context)}` : '';
  const kev = x.kev ? `<span class="badge kev">EXPLOITED IN THE WILD${x.kev.ransomware ? ' · RANSOMWARE' : ''}</span>` : '';
  const epss = x.epss >= 0.01 ? `<span class="badge epss">EPSS ${(x.epss*100).toFixed(1)}%</span>` : '';
  const flow = x.flow ? `<div class="flow">${x.flow.map(s => `<div>${esc(s)}</div>`).join('')}</div>` : '';
  const dep = [];
  if (x.direct === true) dep.push('direct dependency'); else if (x.via && x.via.length) dep.push('via ' + x.via.join(' › ')); else if (x.direct === false) dep.push('transitive');
  if (x.imported === true) dep.push('imported by your code'); else if (x.imported === false) dep.push('not imported directly');
  if (x.dev) dep.push('dev-only');
  if (x.history) dep.push(`git history: commit ${String(x.commit).slice(0,10)} by ${x.author} on ${String(x.date).slice(0,10)}`);
  const depLine = dep.length ? `<div class="ctx">${esc(dep.join(' · '))}</div>` : '';
  const head = f.category === 'dependency'
    ? `<code>${esc(f.snippet)}</code> <span style="color:var(--muted)">${esc(f.rule_id)}</span> ${esc(f.title)}${f.extra.fixed ? ` <span style="color:var(--ok)">→ ${esc(f.extra.fixed)}</span>` : ''}`
    : esc(f.title);
  return `<details class="f" style="--sev:var(${VAR[f.severity]})"><summary><span class="prio" title="priority">${x.priority ?? ''}</span><span class="sev">${f.severity}</span><span class="title">${head}${kev}${epss}</span><span class="loc">${esc(f.file)}${f.line?':'+f.line:''}</span></summary>
  ${depLine}
  ${f.snippet ? `<pre>${esc(f.snippet)}</pre>` : ''}
  ${flow}
  ${f.description ? `<div class="desc">${esc(f.description)}</div>` : ''}
  ${f.fix ? `<div class="fix">✔ ${esc(f.fix)}</div>` : ''}
  <div class="meta">${esc(ids)}${f.cwe ? ' · '+esc(f.cwe) : ''}${cvss}${ctx}${refs ? '<br>'+refs : ''}</div></details>`;
}
function draw(){
  const items = D.findings.filter(f => state.sev.has(f.severity) && (!state.cat || f.category === state.cat) &&
    (!state.q || JSON.stringify(f).toLowerCase().includes(state.q)));
  if (!D.findings.length) { $('list').innerHTML = '<div class="empty">✔ No vulnerabilities found.</div>'; return; }
  if (!items.length) { $('list').innerHTML = '<div class="empty">No findings match the current filters.</div>'; return; }
  let out = '';
  for (const c of Object.keys(CATS)) {
    const g = items.filter(f => f.category === c);
    if (g.length) out += `<h2>${esc(CATS[c])} · ${g.length}</h2>` + g.map(card).join('');
  }
  $('list').innerHTML = out;
}
draw();
</script>
</body>
</html>
"""


def to_html(result: ScanResult) -> str:
    data = to_json(result).replace("</", "<\\/")
    return (TEMPLATE.replace("__TITLE__", html.escape(result.root.rstrip("/").rsplit("/", 1)[-1]))
            .replace("__CATS__", json.dumps(CATEGORIES))
            .replace("__DATA__", data))
