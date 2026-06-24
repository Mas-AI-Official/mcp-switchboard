/**
 * The embedded dashboard UI — a single self-contained HTML document (no build step,
 * no framework, no external requests). Served at `/` by dashboard.ts. It talks to the
 * JSON API on the same origin to render servers/tools, flip enable toggles, and tail
 * the audit log.
 *
 * Kept as a template string on purpose: zero front-end toolchain keeps `npm install`
 * fast and the attack surface tiny. If this grows past a screenful of logic it should
 * graduate to a real `public/` directory.
 */

export function dashboardHtml(): string {
  return /* html */ `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Switchboard</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --panel-2: #1c2330; --border: #2a3340;
    --fg: #e6edf3; --muted: #8b98a5; --accent: #2dd4bf; --accent-dim: #1c8073;
    --danger: #f85149; --warn: #d29922; --ok: #3fb950; --read: #58a6ff;
    --write: #d29922; --full: #f85149;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  header {
    display: flex; align-items: center; gap: 12px; padding: 18px 28px;
    border-bottom: 1px solid var(--border); background: var(--panel);
  }
  header .logo { font-size: 20px; font-weight: 700; letter-spacing: -0.4px; }
  header .logo span { color: var(--accent); }
  header .tag { color: var(--muted); font-size: 13px; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 24px 28px 64px; }
  .grid { display: grid; grid-template-columns: 1fr; gap: 24px; }
  @media (min-width: 900px) { .grid { grid-template-columns: 1.4fr 1fr; } }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
  .card h2 { margin: 0; padding: 14px 18px; font-size: 13px; text-transform: uppercase;
    letter-spacing: 0.6px; color: var(--muted); border-bottom: 1px solid var(--border); }
  .endpoint { padding: 16px 18px; }
  .endpoint code { display: block; background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 8px; padding: 10px 12px; color: var(--accent); font-size: 13px;
    overflow-x: auto; white-space: nowrap; }
  .endpoint .hint { color: var(--muted); font-size: 12px; margin-top: 8px; }
  .server { padding: 14px 18px; border-bottom: 1px solid var(--border); }
  .server:last-child { border-bottom: none; }
  .server .row { display: flex; align-items: center; gap: 12px; }
  .server .id { font-weight: 600; }
  .server .src { color: var(--muted); font-size: 12px; }
  .server .count { margin-left: auto; color: var(--muted); font-size: 12px; }
  .pill { font-size: 11px; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--border); }
  .pill.read { color: var(--read); border-color: var(--read); }
  .pill.write { color: var(--write); border-color: var(--write); }
  .pill.full { color: var(--full); border-color: var(--full); }
  .tools { margin-top: 10px; display: none; flex-wrap: wrap; gap: 6px; }
  .tools.open { display: flex; }
  .tool { font-size: 11px; padding: 3px 8px; border-radius: 6px; background: var(--panel-2);
    border: 1px solid var(--border); color: var(--muted); }
  .tool.off { opacity: 0.4; text-decoration: line-through; }
  .toggle { position: relative; width: 38px; height: 22px; flex: none; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .toggle span { position: absolute; inset: 0; background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 999px; cursor: pointer; transition: 0.15s; }
  .toggle span::before { content: ""; position: absolute; width: 16px; height: 16px; left: 2px; top: 2px;
    background: var(--muted); border-radius: 50%; transition: 0.15s; }
  .toggle input:checked + span { background: var(--accent-dim); border-color: var(--accent); }
  .toggle input:checked + span::before { transform: translateX(16px); background: var(--accent); }
  .expand { background: none; border: none; color: var(--muted); cursor: pointer; font-size: 12px; padding: 0; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  td { padding: 7px 18px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  td.reason { white-space: normal; color: var(--muted); }
  .dec { font-weight: 600; }
  .dec.allow { color: var(--ok); } .dec.deny { color: var(--danger); }
  .dec.approval_required { color: var(--warn); }
  .empty { padding: 18px; color: var(--muted); font-size: 13px; }
  footer { text-align: center; color: var(--muted); font-size: 12px; padding: 20px; }
  footer a { color: var(--accent); text-decoration: none; }
</style>
</head>
<body>
<header>
  <div class="logo">Switch<span>board</span></div>
  <div class="tag">local-first governed MCP aggregator</div>
</header>
<div class="wrap">
  <div class="card" style="margin-bottom:24px">
    <h2>Connect</h2>
    <div class="endpoint">
      <code id="endpoint">loading…</code>
      <div class="hint">Point any MCP client at this URL. Stdio clients: <code style="display:inline;padding:1px 6px">switchboard serve</code></div>
    </div>
  </div>
  <div class="grid">
    <div class="card">
      <h2>Servers &amp; tools</h2>
      <div id="servers"><div class="empty">loading…</div></div>
    </div>
    <div class="card">
      <h2>Audit log</h2>
      <div id="audit"><div class="empty">loading…</div></div>
    </div>
  </div>
</div>
<footer>Switchboard · Apache-2.0 · <a href="https://github.com/Masoud-Masoori/switchboard">github</a></footer>

<script>
const SCOPES = ["read","write","full"];
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
function el(tag, cls, html) { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; }

async function render() {
  const state = await api("/api/state");
  document.getElementById("endpoint").textContent = state.endpoint;

  const box = document.getElementById("servers");
  box.innerHTML = "";
  if (!state.servers.length) { box.appendChild(el("div","empty","No servers mounted. Add one to switchboard.config.yaml.")); }
  for (const s of state.servers) {
    const card = el("div","server");
    const row = el("div","row");
    row.appendChild(el("span","id",s.id));
    row.appendChild(el("span","pill " + s.policy, s.policy));
    row.appendChild(el("span","src",s.source));
    const count = el("span","count",s.tools.length + " tools");
    row.appendChild(count);

    const toggle = el("label","toggle");
    const input = el("input"); input.type = "checkbox"; input.checked = s.enabled;
    input.onchange = async () => {
      try { await api("/api/servers/" + encodeURIComponent(s.id) + "/toggle", { method: "POST" }); render(); }
      catch (e) { alert("toggle failed: " + e.message); input.checked = !input.checked; }
    };
    toggle.appendChild(input); toggle.appendChild(el("span"));
    row.appendChild(toggle);
    card.appendChild(row);

    const tools = el("div","tools");
    for (const t of s.tools) tools.appendChild(el("span","tool" + (t.enabled ? "" : " off"), t.name));
    const exp = el("button","expand", "show " + s.tools.length + " tools ▾");
    exp.onclick = () => { tools.classList.toggle("open"); exp.textContent = tools.classList.contains("open") ? "hide tools ▴" : "show " + s.tools.length + " tools ▾"; };
    if (s.tools.length) { card.appendChild(exp); card.appendChild(tools); }
    box.appendChild(card);
  }

  const audit = await api("/api/audit");
  const ab = document.getElementById("audit");
  ab.innerHTML = "";
  if (!audit.length) { ab.appendChild(el("div","empty","No calls yet.")); return; }
  const table = el("table"); const tb = el("tbody");
  for (const a of audit) {
    const tr = el("tr");
    tr.appendChild(el("td","", new Date(a.ts).toLocaleTimeString()));
    tr.appendChild(el("td","", a.server + "<span style='color:var(--muted)'>__</span>" + a.tool));
    tr.appendChild(el("td","dec " + a.decision, a.decision.replace("_"," ")));
    tr.appendChild(el("td","reason", a.reason || ""));
    tb.appendChild(tr);
  }
  table.appendChild(tb); ab.appendChild(table);
}
render();
setInterval(render, 5000);
</script>
</body>
</html>`;
}
