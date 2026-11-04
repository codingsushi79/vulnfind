"""Scan history: a one-line summary of every scan, kept locally, plus `vulnfind trend`.

Stored as JSON lines in ~/.local/share/vulnfind/history/<target-hash>.jsonl (summaries only -
counts, grade, timing - never findings or code). Disable with --no-record or VULNFIND_NO_HISTORY=1.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import time
from typing import Dict, List, Optional

from .models import ScanResult

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _dir() -> str:
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "vulnfind", "history")


def _path(target: str) -> str:
    return os.path.join(_dir(), hashlib.sha256(target.encode("utf-8")).hexdigest()[:16] + ".jsonl")


def enabled() -> bool:
    return not os.environ.get("VULNFIND_NO_HISTORY")


def record(result: ScanResult) -> None:
    if not enabled():
        return
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "target": result.root, "grade": result.grade, "score": result.score,
             "counts": result.counts(), "total": len(result.findings), "scanners": result.scanners,
             "duration": round(result.duration, 2)}
    try:
        os.makedirs(_dir(), exist_ok=True)
        with open(_path(result.root), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # history is a convenience; never fail a scan over it


def load(target: str, last: int = 0) -> List[dict]:
    try:
        with open(_path(target), encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
    except (OSError, ValueError):
        return []
    return rows[-last:] if last else rows


def targets() -> List[str]:
    out = []
    try:
        for name in sorted(os.listdir(_dir())):
            rows = []
            with open(os.path.join(_dir(), name), encoding="utf-8") as fh:
                first = fh.readline()
                if first.strip():
                    rows.append(json.loads(first))
            if rows:
                out.append(rows[0]["target"])
    except (OSError, ValueError):
        pass
    return out


SPARK = "▁▂▃▄▅▆▇█"


def sparkline(values: List[int]) -> str:
    hi = max(values) if values else 0
    if hi == 0:
        return SPARK[0] * len(values)
    return "".join(SPARK[min(len(SPARK) - 1, round(v / hi * (len(SPARK) - 1)))] for v in values)


# ---------------------------------------------------------------- HTML chart

def to_html(target: str, rows: List[dict]) -> str:
    data = [{"ts": r["ts"][:16].replace("T", " "), "grade": r["grade"], "score": r["score"],
             **{s: r["counts"].get(s, 0) for s in SEVERITIES}} for r in rows]
    return TEMPLATE.replace("__TITLE__", html.escape(target)).replace("__DATA__", json.dumps(data).replace("</", "<\\/"))


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security trend</title>
<style>
.viz-root{color-scheme:light;--surface-1:#fcfcfb;--page:#f4f4f2;--text-primary:#0b0b0b;--text-secondary:#52514e;--text-muted:#77766f;
  --grid:#e6e5e1;--low:#86b6ef;--medium:#3987e5;--high:#1c5cab;--critical:#0d366b;--good:#006300;--bad:#b42318}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])) .viz-root{color-scheme:dark;--surface-1:#1a1a19;--page:#111110;
  --text-primary:#f0efec;--text-secondary:#c3c2b7;--text-muted:#8f8e86;--grid:#2c2c2a;--low:#184f95;--medium:#2a78d6;--high:#6da7ec;--critical:#b7d3f6;--good:#0ca30c;--bad:#f97066}}
:root[data-theme="dark"] .viz-root{color-scheme:dark;--surface-1:#1a1a19;--page:#111110;--text-primary:#f0efec;--text-secondary:#c3c2b7;
  --text-muted:#8f8e86;--grid:#2c2c2a;--low:#184f95;--medium:#2a78d6;--high:#6da7ec;--critical:#b7d3f6;--good:#0ca30c;--bad:#f97066}
body{margin:0}
.viz-root{background:var(--page);color:var(--text-primary);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh;padding:32px 16px;box-sizing:border-box}
.wrap{max-width:960px;margin:0 auto}
h1{font-size:20px;margin:0}.sub{color:var(--text-secondary);margin:4px 0 20px;word-break:break-all}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:16px}
.tile{background:var(--surface-1);border-radius:12px;padding:12px 14px}.tile b{display:block;font-size:26px;font-variant-numeric:tabular-nums}
.tile span{color:var(--text-secondary);font-size:12px}.delta{font-size:13px;color:var(--text-secondary)}
.card{background:var(--surface-1);border-radius:12px;padding:16px;position:relative}
.legend{display:flex;gap:16px;flex-wrap:wrap;color:var(--text-secondary);font-size:13px;margin-bottom:8px}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px}
svg{display:block;width:100%;height:auto;overflow:visible}
.axis text{fill:var(--text-muted);font-size:11px}.grid line{stroke:var(--grid)}
.tip{position:absolute;pointer-events:none;background:var(--surface-1);color:var(--text-primary);border-radius:8px;padding:8px 10px;font-size:12px;
  box-shadow:0 4px 16px rgba(0,0,0,.18);opacity:0;transition:opacity .08s;white-space:nowrap}
.tip .row{display:flex;justify-content:space-between;gap:14px}.tip i{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px}
details{margin-top:16px}summary{cursor:pointer;color:var(--text-secondary)}
table{border-collapse:collapse;width:100%;margin-top:8px;font-variant-numeric:tabular-nums;font-size:13px}
th,td{text-align:right;padding:4px 8px;border-bottom:1px solid var(--grid)}th:first-child,td:first-child{text-align:left}
</style></head>
<body><div class="viz-root"><div class="wrap">
<h1>Security trend</h1><div class="sub">__TITLE__</div>
<div class="tiles" id="tiles"></div>
<div class="card"><div class="legend" id="legend"></div><svg id="chart" role="img" aria-label="Open findings per scan, by severity"></svg>
<div class="tip" id="tip"></div></div>
<details><summary>Table view</summary><table id="table"></table></details>
</div></div>
<script>
const D = __DATA__;
const S = ["LOW","MEDIUM","HIGH","CRITICAL"];  // stacked bottom -> top
const C = {LOW:"var(--low)",MEDIUM:"var(--medium)",HIGH:"var(--high)",CRITICAL:"var(--critical)"};
const total = d => S.reduce((a,s)=>a+d[s],0);
const $ = id => document.getElementById(id);
const last = D[D.length-1], prev = D[D.length-2];
function tile(label, value, delta, lowerIsBetter){
  let dt = "";
  if (delta !== null && delta !== 0){ const good = lowerIsBetter ? delta < 0 : delta > 0;
    dt = `<span class="delta" style="color:var(${good?'--good':'--bad'})">${delta>0?'▲':'▼'} ${Math.abs(delta)} vs previous</span>`; }
  else if (delta === 0) dt = `<span class="delta">no change</span>`;
  return `<div class="tile"><span>${label}</span><b>${value}</b>${dt}</div>`;
}
$("tiles").innerHTML = tile("Open findings", total(last), prev ? total(last)-total(prev) : null, true)
  + tile("Critical + high", last.CRITICAL+last.HIGH, prev ? (last.CRITICAL+last.HIGH)-(prev.CRITICAL+prev.HIGH) : null, true)
  + tile("Grade", `${last.grade} <span style="font-size:14px;color:var(--text-secondary)">${last.score}/100</span>`, prev ? last.score-prev.score : null, false)
  + tile("Scans recorded", D.length, null, false);
$("legend").innerHTML = S.slice().reverse().map(s=>`<span><i style="background:${C[s]}"></i>${s[0]+s.slice(1).toLowerCase()}</span>`).join("");
const W = 920, H = 300, m = {l:36,r:8,t:8,b:28};
const max = Math.max(1, ...D.map(total));
const raw = max / 4, mag = Math.pow(10, Math.floor(Math.log10(raw)));
const tick = [1, 2, 5, 10].map(k => k * mag).find(t => t >= raw);  // 1/2/5 steps -> round tick labels
const nTicks = Math.ceil(max / tick), yMax = nTicks * tick;
const y = v => m.t + (H-m.t-m.b) * (1 - v/yMax);
const band = (W-m.l-m.r)/D.length, bw = Math.min(24, band*0.6);
let svg = `<g class="grid">`; for (let i=0;i<=nTicks;i++){ const v = tick*i; svg += `<line x1="${m.l}" x2="${W-m.r}" y1="${y(v)}" y2="${y(v)}"/>`; } svg += `</g><g class="axis">`;
for (let i=0;i<=nTicks;i++){ const v = tick*i; svg += `<text x="${m.l-6}" y="${y(v)+4}" text-anchor="end">${Math.round(v)}</text>`; }
const every = Math.max(1, Math.ceil(D.length/8));
D.forEach((d,i)=>{ if (i%every===0 || i===D.length-1) svg += `<text x="${m.l+band*i+band/2}" y="${H-8}" text-anchor="middle">${d.ts.slice(5,10)}</text>`; });
svg += `</g>`;
D.forEach((d,i)=>{
  const x = m.l + band*i + (band-bw)/2; let acc = 0; const segs = S.filter(s=>d[s]>0);
  segs.forEach((s,j)=>{
    const y0 = y(acc), y1 = y(acc+d[s]); acc += d[s];
    const gap = j>0 ? 2 : 0, h = Math.max(1, y0-y1-gap), topSeg = j===segs.length-1, r = topSeg ? Math.min(4, h) : 0;
    const yy = y1, x2 = x+bw;
    svg += topSeg ? `<path fill="${C[s]}" d="M${x},${yy+h} V${yy+r} Q${x},${yy} ${x+r},${yy} H${x2-r} Q${x2},${yy} ${x2},${yy+r} V${yy+h} Z"/>`
                  : `<rect fill="${C[s]}" x="${x}" y="${yy}" width="${bw}" height="${h}"/>`;
  });
  svg += `<rect data-i="${i}" x="${m.l+band*i}" y="${m.t}" width="${band}" height="${H-m.t-m.b}" fill="transparent"/>`;
});
const chart = $("chart"); chart.setAttribute("viewBox", `0 0 ${W} ${H}`); chart.innerHTML = svg;
const tip = $("tip");
chart.addEventListener("mousemove", e => {
  const i = e.target.dataset && e.target.dataset.i; if (i === undefined){ tip.style.opacity = 0; return; }
  const d = D[i]; tip.innerHTML = `<div style="margin-bottom:4px;color:var(--text-secondary)">${d.ts} · grade ${d.grade}</div>`
    + S.slice().reverse().map(s=>`<div class="row"><span><i style="background:${C[s]}"></i>${s.toLowerCase()}</span><b>${d[s]}</b></div>`).join("")
    + `<div class="row" style="margin-top:4px"><span>total</span><b>${total(d)}</b></div>`;
  const card = chart.parentElement.getBoundingClientRect();
  let left = e.clientX - card.left + 14; if (left > card.width - 160) left = e.clientX - card.left - 160;
  tip.style.left = left + "px"; tip.style.top = (e.clientY - card.top - 20) + "px"; tip.style.opacity = 1;
});
chart.addEventListener("mouseleave", () => tip.style.opacity = 0);
$("table").innerHTML = `<tr><th>Scan</th><th>Grade</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>`
  + D.slice().reverse().map(d=>`<tr><td>${d.ts}</td><td>${d.grade}</td><td>${d.CRITICAL}</td><td>${d.HIGH}</td><td>${d.MEDIUM}</td><td>${d.LOW}</td><td>${total(d)}</td></tr>`).join("");
</script></body></html>
"""
