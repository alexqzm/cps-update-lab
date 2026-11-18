"""HMI: веб-страница оператора. Сервер HMI забирает состояние контроллера по его API, поэтому
браузеру нужен доступ только к HMI. Страница только показывает состояние; сброс процесса —
единственное действие, нужное для повторения сценариев."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .util import http_open

PAGE = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ТК-1: HMI</title>
<style>
:root { --bg:#f4f5f2; --panel:#ffffff; --ink:#1d2321; --muted:#5d6763; --line:#d5d9d4; --water:#3a7bbf;
        --ok:#2f7d4f; --warn:#b7791f; --bad:#b3261e; --steel:#8a9590; }
@media (prefers-color-scheme: dark) { :root { --bg:#151918; --panel:#1e2422; --ink:#e7ebe8; --muted:#9aa5a0;
        --line:#323a37; --water:#4f93d8; --ok:#5cb37f; --warn:#d9a441; --bad:#e5675d; --steel:#6d7873; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
header { padding:14px 20px; border-bottom:1px solid var(--line); display:flex; gap:16px; align-items:baseline; flex-wrap:wrap; }
header h1 { font-size:18px; margin:0; }
header .sub { color:var(--muted); }
main { display:grid; grid-template-columns: minmax(260px, 340px) 1fr; gap:16px; padding:16px 20px; }
@media (max-width: 760px) { main { grid-template-columns: 1fr; } }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:14px 16px; }
.panel h2 { font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:0 0 10px; }
svg text { fill: var(--ink); font-size:12px; }
.big { font-size:34px; font-variant-numeric: tabular-nums; font-weight:600; }
.row { display:flex; justify-content:space-between; gap:12px; padding:4px 0; border-bottom:1px dashed var(--line); }
.row:last-child { border-bottom:0; }
.k { color:var(--muted); }
.v { font-variant-numeric: tabular-nums; text-align:right; word-break:break-all; }
.alarm { display:inline-block; padding:2px 8px; border-radius:3px; margin:2px 4px 2px 0; font-weight:600; font-size:13px; }
.alarm.bad { background:var(--bad); color:#fff; } .alarm.warn { background:var(--warn); color:#111; }
.alarm.ok { background:var(--ok); color:#fff; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th, td { text-align:left; padding:5px 6px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:500; }
.acc-true { color:var(--ok); font-weight:600; } .acc-false { color:var(--bad); font-weight:600; }
button { font:inherit; padding:6px 12px; border-radius:4px; border:1px solid var(--line); background:var(--bg); color:var(--ink); cursor:pointer; }
.muted { color:var(--muted); }
</style>
</head>
<body>
<header><h1>Контроллер резервуара ТК-1</h1><span class="sub" id="ident">—</span></header>
<main>
  <section class="panel">
    <h2>Процесс</h2>
    <svg viewBox="0 0 250 260" width="100%" role="img" aria-label="Резервуар">
      <rect x="40" y="20" width="110" height="200" fill="none" stroke="var(--steel)" stroke-width="3"/>
      <rect id="water" x="42" y="218" width="106" height="0" fill="var(--water)"/>
      <line x1="34" y1="22" x2="40" y2="22" stroke="var(--bad)" stroke-width="2"/><text x="2" y="26">100%</text>
      <g id="marks"></g>
      <circle id="pumpc" cx="95" cy="244" r="11" fill="var(--steel)"/>
      <text x="112" y="248" id="pumpt">насос</text>
    </svg>
    <div class="big" id="lvl">—</div>
    <div id="alarms"></div>
    <p><button id="reset">Сбросить процесс (50 %)</button></p>
  </section>
  <section>
    <div class="panel">
      <h2>Контроллер</h2>
      <div class="row"><span class="k">уровень защиты</span><span class="v" id="level">—</span></div>
      <div class="row"><span class="k">программа</span><span class="v" id="prog">—</span></div>
      <div class="row"><span class="k">SHA-256 образа</span><span class="v" id="sha">—</span></div>
      <div class="row"><span class="k">svn</span><span class="v" id="svn">—</span></div>
      <div class="row"><span class="k">уставки</span><span class="v" id="sp">—</span></div>
      <div class="row"><span class="k">блокировки</span><span class="v" id="il">—</span></div>
      <div class="row"><span class="k">рецепт</span><span class="v" id="rcp">—</span></div>
    </div>
    <div class="panel" style="margin-top:16px">
      <h2>Журнал контроллера (подписанные отчёты)</h2>
      <table><thead><tr><th>№</th><th>событие</th><th>путь</th><th>исход</th><th>дайджест</th></tr></thead>
      <tbody id="log"><tr><td colspan="5" class="muted">нет данных</td></tr></tbody></table>
    </div>
  </section>
</main>
<script>
const $ = id => document.getElementById(id);
function esc(s) { return String(s ?? "—").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
async function tick() {
  try {
    const st = await (await fetch("api/status")).json();
    const p = st.process, h = Math.max(0, Math.min(100, p.level));
    $("ident").textContent = `${st.name} · класс ${st.device_class}`;
    $("water").setAttribute("height", (h * 1.96).toFixed(1));
    $("water").setAttribute("y", (218 - h * 1.96).toFixed(1));
    // уставки справа от резервуара; выше 100 % — у верхнего края со стрелкой
    const marks = Object.entries(p.setpoints || {}).map(([k, v]) => ({k, v, y: 218 - Math.max(0, Math.min(v, 100)) * 1.96}))
      .sort((a, b) => b.y - a.y);
    let prev = Infinity;
    $("marks").innerHTML = marks.map(m => { const ly = Math.min(m.y + 4, prev - 13); prev = ly;
      const col = m.k === "hh" ? "var(--warn)" : "var(--muted)";
      return `<line x1="150" y1="${m.y}" x2="158" y2="${m.y}" stroke="${col}" stroke-width="2"/>` +
             `<text x="161" y="${ly}">${esc(m.k)} ${esc(m.v)}${m.v > 100 ? " ↑" : ""}</text>`; }).join("");
    $("pumpc").setAttribute("fill", p.pump ? "var(--ok)" : "var(--steel)");
    $("pumpt").textContent = p.pump ? "насос включён" : "насос выключен";
    $("lvl").textContent = p.level.toFixed(1) + " %";
    $("alarms").innerHTML = p.alarms.length ? p.alarms.map(a => `<span class="alarm ${a === a.toUpperCase() ? "bad" : "warn"}">${esc(a)}</span>`).join("")
                                             : '<span class="alarm ok">норма</span>';
    $("level").textContent = `${st.level} — ${st.level_title}`;
    $("prog").textContent = st.installed.version ? `${st.installed.product} ${st.installed.version} (${st.controller})` : st.controller;
    $("sha").textContent = st.installed.sha256 ? st.installed.sha256.slice(0, 16) + "…" : "—";
    $("svn").textContent = st.installed.svn ?? "—";
    $("sp").textContent = Object.entries(p.setpoints).map(([k, v]) => `${k}=${v}`).join(", ") || "—";
    $("il").textContent = p.interlocks.join(", ") || "не активны";
    const r = st.recipe;
    const RS = {running: "исполняется", completed: "завершён", failed: "отказ партии", aborted: "прерван"};
    $("rcp").textContent = r ? `${r.name} r${r.revision}: ${RS[r.status] || r.status}, шаг ${r.step}/${r.steps}` +
      (r.quality ? `, партия ${r.quality === "ok" ? "в норме" : "брак"}` : "") +
      (p.manual ? `; насос вручную: ${p.manual}` : "") : (p.manual ? `нет; насос вручную: ${p.manual}` : "нет");
    const reps = await (await fetch("api/reports")).json();
    $("log").innerHTML = reps.slice(-12).reverse().map(r => { const e = r.event;
      return `<tr><td>${e.seq}</td><td>${esc(e.event)}${e.command ? " " + esc(e.command) : ""}${e.recipe ? " " + esc(e.recipe) + " r" + esc(e.revision) : ""}</td><td>${esc(e.path)}</td>
              <td class="acc-${e.accepted}">${e.accepted ? "принято" : "отказ"} (${esc(e.reason)})</td>
              <td>${esc((e.candidate_sha256 || "").slice(0, 12))}</td></tr>`; }).join("");
  } catch (e) { $("ident").textContent = "нет связи с контроллером"; }
}
$("reset").onclick = () => fetch("api/process/reset", {method: "POST", body: "{}"});
tick(); setInterval(tick, 1000);
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "cpslab-hmi/0.1"

    def _proxy(self, path: str, data: bytes = None):
        req = urllib.request.Request(self.server.device_url + path, data=data, method="POST" if data else "GET",
                                     headers={"Content-Type": "application/json"})
        try:
            with http_open(req, 5) as r:
                body, code = r.read(), r.status
        except (urllib.error.URLError, OSError) as e:
            body, code = json.dumps({"error": str(e)}).encode(), 502
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path in ("/", "/index.html"):
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path in ("/api/status", "/api/reports"):
            self._proxy(self.path)
        else:
            self.send_error(404)

    def do_POST(self):  # noqa: N802
        if self.path == "/api/process/reset":
            self._proxy(self.path, b"{}")
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        pass


def serve(device_url: str, host: str = "0.0.0.0", port: int = 8081, background: bool = False):
    srv = ThreadingHTTPServer((host, port), _Handler)
    srv.device_url = device_url.rstrip("/")
    if background:
        threading.Thread(target=srv.serve_forever, name="hmi", daemon=True).start()
        return srv
    srv.serve_forever()
