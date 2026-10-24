/* MCP Switchboard dashboard — single-file vanilla SPA (no build step, no dependencies).
 * Hash router + fetch against the JSON API in src/dashboard.ts. Every endpoint and
 * response shape used here mirrors that file 1:1. */

"use strict";

// ----------------------------------------------------------------------------
// Tiny helpers
// ----------------------------------------------------------------------------
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const view = () => $("#view");

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

function attr(s) {
  return String(s ?? "").replace(/"/g, "&quot;");
}

// ----------------------------------------------------------------------------
// Owner session (design 3.15). The admin API needs the session id in the X-Switchboard-Session header and, on every
// mutating call, the CSRF value. Both come back once from the login exchange and are kept in THIS TAB's sessionStorage:
// storage is scoped to the origin, port included, and the browser never sends it by itself, so no other local port
// can receive it (a cookie is sent to every port of the same host, which is how an unrelated listener on another
// port used to end up holding a working owner session). `switchboard dashboard login` opens this page at
// /#login=<code>; the code is single use.
// ----------------------------------------------------------------------------
const SESSION_STORE = { sid: "switchboard.session", csrf: "switchboard.csrf" };
function storeGet(key) {
  try {
    return window.sessionStorage.getItem(key);
  } catch {
    return null;
  }
}
function storeSet(key, value) {
  try {
    if (value === null) window.sessionStorage.removeItem(key);
    else window.sessionStorage.setItem(key, value);
  } catch {
    /* storage blocked: the session then lives in memory for this page load only */
  }
}
let sessionId = storeGet(SESSION_STORE.sid);
let csrfToken = storeGet(SESSION_STORE.csrf);
function setSession(sid, csrf) {
  sessionId = sid;
  csrfToken = csrf;
  storeSet(SESSION_STORE.sid, sid);
  storeSet(SESSION_STORE.csrf, csrf);
}
function clearSession() {
  setSession(null, null);
}

function showSignInBanner(detail) {
  let el = $("#auth-banner");
  if (!el) {
    el = document.createElement("div");
    el.id = "auth-banner";
    el.className = "auth-banner";
    el.setAttribute("role", "alert");
    document.body.prepend(el);
  }
  el.innerHTML =
    `<strong>Owner sign-in required.</strong> ${detail ? esc(detail) + " " : ""}` +
    `Run <code>switchboard dashboard login</code> in a terminal on this machine; it checks you are present, then opens this dashboard already signed in.`;
}

function hideSignInBanner() {
  const el = $("#auth-banner");
  if (el) el.remove();
}

// The ONE place the SPA talks to the server. Sends the session header and no cookie; adds the CSRF header on anything
// that is not a read; a 401 drops a session the server no longer knows and shows the sign-in banner. `quiet` skips the
// banner (the sign-in probe handles its own 401).
async function api(path, opts = {}) {
  const { quiet, ...init } = opts;
  const method = String(init.method || "GET").toUpperCase();
  const headers = { "content-type": "application/json", ...(init.headers || {}) };
  if (sessionId) headers["X-Switchboard-Session"] = sessionId;
  if (method !== "GET" && method !== "HEAD" && csrfToken) headers["X-Switchboard-CSRF"] = csrfToken;
  const res = await fetch(path, { ...init, method, headers, credentials: "omit" });
  let body = null;
  const text = await res.text();
  if (text) {
    try { body = JSON.parse(text); } catch { body = { raw: text }; }
  }
  if (!res.ok) {
    if (res.status === 401 && sessionId && !(method === "POST" && path === "/api/session")) clearSession();
    if (res.status === 401 && !quiet) showSignInBanner();
    const msg = (body && body.error) || `${res.status} ${res.statusText}`;
    const err = new Error(msg);
    err.status = res.status;
    err.code = body && body.code;
    throw err;
  }
  return body;
}

// Redeem a #login=<code> fragment (then drop it from the address bar at once, so the code never lingers in history),
// or check that the session kept in this tab is still valid. Never throws.
async function establishSession() {
  const m = /^#login=([A-Za-z0-9_-]{16,200})$/.exec(location.hash);
  if (m) {
    history.replaceState(null, "", location.pathname + location.search);
    try {
      const r = await api("/api/session", { method: "POST", body: JSON.stringify({ code: m[1] }), quiet: true });
      setSession(r.session, r.csrf);
      hideSignInBanner();
    } catch {
      clearSession();
      showSignInBanner("That login code is invalid, expired or already used.");
    }
    return;
  }
  if (!sessionId) {
    showSignInBanner();
    return;
  }
  try {
    await api("/api/session", { quiet: true });
    hideSignInBanner();
  } catch {
    clearSession();
    showSignInBanner();
  }
}

// <img> error events do not bubble, so one capture-phase listener replaces the inline onerror
// attributes (the page CSP allows no inline event handlers).
document.addEventListener(
  "error",
  (ev) => {
    const el = ev.target;
    if (!(el instanceof HTMLImageElement)) return;
    if (el.dataset.fallback !== undefined) el.replaceWith(document.createTextNode(el.dataset.fallback));
    else if (el.hasAttribute("data-hide-on-error")) el.style.display = "none";
  },
  true
);

let toastTimer;
function toast(message, kind) {
  const t = $("#toast");
  t.textContent = message;
  t.className = "toast show" + (kind ? ` toast-${kind}` : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = "toast"), 3800);
}

function debounce(fn, ms) {
  let id;
  return (...args) => {
    clearTimeout(id);
    id = setTimeout(() => fn(...args), ms);
  };
}

function relTime(iso) {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return esc(iso);
  const diff = Date.now() - then;
  const s = Math.round(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(iso).toLocaleDateString();
}

function fmtDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? esc(iso) : d.toLocaleString();
}

// ----------------------------------------------------------------------------
// Modal
// ----------------------------------------------------------------------------
function openModal({ title, body, footer }) {
  const root = $("#modal-root");
  root.innerHTML = `
    <div class="modal-backdrop" data-close="1">
      <div class="modal" role="dialog" aria-modal="true" aria-label="${attr(title)}">
        <div class="modal-head">
          <h3>${esc(title)}</h3>
          <button class="modal-close" data-close="1" aria-label="Close">&times;</button>
        </div>
        <div class="modal-body">${body}</div>
        ${footer ? `<div class="modal-foot">${footer}</div>` : ""}
      </div>
    </div>`;
  const close = () => (root.innerHTML = "");
  root.querySelectorAll("[data-close]").forEach((n) =>
    n.addEventListener("click", (e) => {
      if (e.target === n) close();
    })
  );
  document.addEventListener("keydown", function onEsc(e) {
    if (e.key === "Escape") { close(); document.removeEventListener("keydown", onEsc); }
  });
  return { root, close };
}

// ----------------------------------------------------------------------------
// Shared rendering bits
// ----------------------------------------------------------------------------
function pageHead(title, sub, rightHtml) {
  return `
    <div class="page-head">
      <div class="page-head-row">
        <div>
          <h1 class="page-title">${esc(title)}</h1>
          ${sub ? `<p class="page-sub">${esc(sub)}</p>` : ""}
        </div>
        ${rightHtml ? `<div>${rightHtml}</div>` : ""}
      </div>
    </div>`;
}

function errorBanner(err) {
  return `<div class="error-banner">⚠ ${esc(err.message || String(err))}</div>`;
}

function loadingView(label) {
  view().innerHTML = `<div class="loading"><span class="spinner"></span> ${esc(label || "Loading…")}</div>`;
}

function scopeBadge(scope) {
  return `<span class="badge badge-scope">${esc(scope)}</span>`;
}

// ----------------------------------------------------------------------------
// Top-of-sidebar live state (endpoint + org)
// ----------------------------------------------------------------------------
async function refreshSidebar() {
  try {
    const s = await api("/api/state");
    $("#endpoint-url").textContent = s.endpoint;
    $("#endpoint-url").dataset.url = s.endpoint;
    $("#org-line").textContent = `${s.organization} · ${s.project}`;
  } catch {
    $("#endpoint-url").textContent = "endpoint unavailable";
  }
}

$("#copy-endpoint").addEventListener("click", async () => {
  const url = $("#endpoint-url").dataset.url || $("#endpoint-url").textContent;
  try {
    await navigator.clipboard.writeText(url);
    toast("Endpoint copied to clipboard", "ok");
  } catch {
    toast("Copy failed — select and copy manually", "error");
  }
});

// ============================================================================
// VIEW: Toolkit catalog
// ============================================================================
const catalogState = {
  q: "",
  category: "",
  origin: "",
  sort: "mounted",
  offset: 0,
  limit: 60,
  total: 0,
  totalPages: 0,
  catalogTotal: 0,
  items: [],
  categories: [],
  loading: false,
};

async function renderCatalog() {
  catalogState.offset = 0;
  catalogState.items = [];
  view().innerHTML =
    pageHead(
      "Toolkits",
      "Browse every MCP server and OpenAPI integration in the catalog. Add one to expose its tools through your single governed endpoint."
    ) +
    `
    <div class="catalog-toolbar">
      <div class="search-wrap">
        <span class="search-ico">⌕</span>
        <input id="tk-search" class="search-input" type="search" autocomplete="off"
          placeholder="Search toolkits or describe a use case…" value="${attr(catalogState.q)}" />
      </div>
      <select id="tk-origin" class="select" style="width:auto">
        <option value="">All sources</option>
        <option value="mcp-registry">MCP servers</option>
        <option value="apis-guru">OpenAPI</option>
      </select>
      <select id="tk-sort" class="select" style="width:auto" title="Order results">
        <option value="mounted">Mounted first</option>
        <option value="alpha">A → Z</option>
      </select>
    </div>
    <div class="catalog-layout">
      <div class="cat-filter">
        <h4>Categories</h4>
        <div class="cat-list" id="cat-list"><div class="dim">loading…</div></div>
      </div>
      <div>
        <div class="result-meta" id="tk-meta"></div>
        <div class="grid" id="tk-grid"></div>
        <div class="load-more" id="tk-more"></div>
      </div>
    </div>`;

  $("#tk-origin").value = catalogState.origin;
  $("#tk-sort").value = catalogState.sort;

  $("#tk-search").addEventListener(
    "input",
    debounce((e) => {
      catalogState.q = e.target.value.trim();
      reloadCatalog();
    }, 220)
  );
  $("#tk-origin").addEventListener("change", (e) => {
    catalogState.origin = e.target.value;
    reloadCatalog();
  });
  $("#tk-sort").addEventListener("change", (e) => {
    catalogState.sort = e.target.value;
    reloadCatalog();
  });

  loadCategories();
  reloadCatalog();
}

async function loadCategories() {
  try {
    const stats = await api("/api/catalog/stats");
    catalogState.categories = stats.categories || [];
    catalogState.catalogTotal = (stats.counts && stats.counts.total) || 0;
    renderCategoryList();
  } catch (e) {
    $("#cat-list").innerHTML = `<div class="dim">${esc(e.message)}</div>`;
  }
}

function renderCategoryList() {
  const list = $("#cat-list");
  if (!list) return;
  const all = `<button class="cat-pill ${catalogState.category === "" ? "active" : ""}" data-cat="">
      <span>All toolkits</span><span class="count">${catalogState.catalogTotal}</span></button>`;
  const rows = catalogState.categories
    .map(
      (c) => `<button class="cat-pill ${catalogState.category === c.name ? "active" : ""}" data-cat="${attr(c.name)}">
        <span>${esc(c.name)}</span><span class="count">${c.count}</span></button>`
    )
    .join("");
  list.innerHTML = all + rows;
  $$(".cat-pill", list).forEach((b) =>
    b.addEventListener("click", () => {
      catalogState.category = b.dataset.cat;
      renderCategoryList();
      reloadCatalog();
    })
  );
}

async function reloadCatalog() {
  catalogState.offset = 0;
  catalogState.items = [];
  $("#tk-grid").innerHTML = `<div class="loading"><span class="spinner"></span> Searching…</div>`;
  $("#tk-more").innerHTML = "";
  await fetchCatalogPage(true);
}

async function fetchCatalogPage(replace) {
  if (catalogState.loading) return;
  catalogState.loading = true;
  const params = new URLSearchParams({
    q: catalogState.q,
    category: catalogState.category,
    origin: catalogState.origin,
    sort: catalogState.sort,
    offset: String(catalogState.offset),
    limit: String(catalogState.limit),
  });
  try {
    const data = await api(`/api/toolkits?${params}`);
    catalogState.total = data.total;
    catalogState.totalPages = data.total_pages || 0;
    catalogState.catalogTotal = data.catalog_total;
    catalogState.items = replace ? data.items : catalogState.items.concat(data.items);
    renderCatalogGrid();
  } catch (e) {
    $("#tk-grid").innerHTML = errorBanner(e);
  } finally {
    catalogState.loading = false;
  }
}

function toolkitCardHtml(tk) {
  const initial = (tk.name || "?").trim().charAt(0).toUpperCase();
  const logo = tk.logo
    ? `<img src="${attr(tk.logo)}" alt="" loading="lazy" data-fallback="${attr(initial)}" />`
    : esc(initial);
  const originLabel = tk.origin === "mcp-registry" ? "MCP server" : "OpenAPI";
  const tags = (tk.tags || [])
    .slice(0, 3)
    .map((t) => `<span class="tag">${esc(t)}</span>`)
    .join("");
  const action = tk.mounted
    ? `<span class="badge badge-ok" title="Already mounted as a server"><span class="dot"></span>Mounted</span>`
    : `<button class="btn btn-sm btn-primary" data-add="${attr(tk.slug)}">Add</button>`;
  return `
    <div class="tk-card${tk.mounted ? " tk-mounted" : ""}" data-slug="${attr(tk.slug)}">
      <div class="tk-card-head">
        <div class="tk-logo">${logo}</div>
        <div style="min-width:0">
          <div class="tk-name">${esc(tk.name)}</div>
          <div class="tk-origin">${esc(tk.category)} · ${originLabel}</div>
        </div>
      </div>
      <div class="tk-desc">${esc(tk.description || "No description provided.")}</div>
      <div class="tk-foot">
        <div class="tk-tags">${tags}</div>
        ${action}
      </div>
    </div>`;
}

function renderCatalogGrid() {
  const grid = $("#tk-grid");
  const meta = $("#tk-meta");
  if (catalogState.items.length === 0) {
    grid.innerHTML = `
      <div class="empty" style="grid-column:1/-1">
        <div class="empty-ico">⌕</div>
        <div class="empty-title">No toolkits match your search</div>
        <div>Try a broader term, or clear the category filter.${
          catalogState.catalogTotal === 0
            ? ` The catalog is empty — run <code>switchboard toolkits sync</code> to fetch it.`
            : ""
        }</div>
      </div>`;
    meta.textContent = "";
    $("#tk-more").innerHTML = "";
    return;
  }
  grid.innerHTML = catalogState.items.map(toolkitCardHtml).join("");
  const pageLabel = catalogState.totalPages > 1 ? ` · ${catalogState.totalPages} pages` : "";
  meta.textContent = `Showing ${catalogState.items.length} of ${catalogState.total} matching${pageLabel} · ${catalogState.catalogTotal} in catalog`;

  // Card click → detail; Add button → quick add (stopPropagation).
  $$(".tk-card", grid).forEach((card) => {
    card.addEventListener("click", () => openToolkitDetail(card.dataset.slug));
  });
  $$("[data-add]", grid).forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      addToolkit(b.dataset.add, b);
    })
  );

  const more = $("#tk-more");
  if (catalogState.items.length < catalogState.total) {
    more.innerHTML = `<button class="btn" id="load-more-btn">Load more (${
      catalogState.total - catalogState.items.length
    } more)</button>`;
    $("#load-more-btn").addEventListener("click", () => {
      catalogState.offset += catalogState.limit;
      $("#load-more-btn").innerHTML = `<span class="spinner"></span> Loading…`;
      fetchCatalogPage(false);
    });
  } else {
    more.innerHTML = "";
  }
}

function mountSummary(mount) {
  if (!mount) return "—";
  switch (mount.source) {
    case "remote": return `Remote MCP · <code>${esc(mount.url)}</code>`;
    case "npx": return `npx package · <code>${esc(mount.package)}</code>`;
    case "app2mcp": return `OpenAPI → MCP · <code>${esc(mount.openapi)}</code>`;
    case "manual": return `Manual install · ${esc(mount.note || "")}`;
    default: return esc(mount.source);
  }
}

async function openToolkitDetail(slug) {
  let tk;
  try {
    tk = await api(`/api/toolkits/${encodeURIComponent(slug)}`);
  } catch (e) {
    toast(e.message, "error");
    return;
  }
  const links = [
    tk.homepage ? `<a href="${attr(tk.homepage)}" target="_blank" rel="noopener">Homepage ↗</a>` : "",
    tk.repository ? `<a href="${attr(tk.repository)}" target="_blank" rel="noopener">Repository ↗</a>` : "",
  ].filter(Boolean).join(" · ");
  const tags = (tk.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join(" ");
  const manual = tk.mount && tk.mount.source === "manual";
  const body = `
    <dl class="kv">
      <dt>Category</dt><dd>${esc(tk.category)}</dd>
      <dt>Source</dt><dd>${tk.origin === "mcp-registry" ? "MCP Registry" : "APIs.guru (OpenAPI)"}</dd>
      <dt>License</dt><dd>${esc(tk.source_license || "—")}</dd>
      <dt>Mount</dt><dd>${mountSummary(tk.mount)}</dd>
      ${links ? `<dt>Links</dt><dd>${links}</dd>` : ""}
      ${tags ? `<dt>Tags</dt><dd class="tk-tags">${tags}</dd>` : ""}
    </dl>
    <p class="dim" style="margin-top:14px">${esc(tk.description || "")}</p>
    ${manual ? `<div class="error-banner" style="margin-top:14px">This toolkit must be installed manually and cannot be auto-added.</div>` : ""}`;
  const footer = `
    <button class="btn" data-close="1" id="tk-detail-close">Close</button>
    ${manual ? "" : `<button class="btn btn-primary" id="tk-detail-add">Add to MCP Switchboard</button>`}`;
  const m = openModal({ title: tk.name, body, footer });
  const closeBtn = $("#tk-detail-close", m.root);
  if (closeBtn) closeBtn.addEventListener("click", m.close);
  const addBtn = $("#tk-detail-add", m.root);
  if (addBtn) addBtn.addEventListener("click", () => addToolkit(slug, addBtn, m.close));
}

async function addToolkit(slug, btn, onDone, version) {
  const original = btn ? btn.innerHTML : "";
  if (btn) { btn.disabled = true; btn.innerHTML = `<span class="spinner"></span>`; }
  let needVersion = false;
  try {
    const opts = { method: "POST" };
    if (version) opts.body = JSON.stringify({ version });
    const res = await api(`/api/toolkits/${encodeURIComponent(slug)}/add`, opts);
    toast(`Added as server “${res.id}” (disabled). Configure it under Servers, then toggle it on.`, "ok");
    if (onDone) onDone();
    refreshSidebar();
    if ($("#tk-grid")) reloadCatalog(); // flip the card to its Mounted state
  } catch (e) {
    // An npm toolkit is added pinned to one exact version; the server says when it has none to offer.
    if (e.code === "SB_PACKAGE_UNPINNED" && !version) needVersion = true;
    else toast(e.message, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = original; }
  }
  if (needVersion) {
    const v = window.prompt("This toolkit runs an npm package, and a new mount needs one exact version. Enter it (for example 1.2.3):", "");
    if (v && v.trim()) return addToolkit(slug, btn, onDone, v.trim());
  }
}

// ============================================================================
// VIEW: Connected Accounts (OAuth providers)
// ============================================================================
async function renderAccounts() {
  loadingView("Loading providers…");
  let providers;
  try {
    providers = await api("/api/catalog");
  } catch (e) {
    view().innerHTML = pageHead("Connected Accounts") + errorBanner(e);
    return;
  }
  const cards = providers
    .map((p) => {
      let badge;
      if (p.connected && p.expired) badge = `<span class="badge badge-warn"><span class="dot"></span>Expired</span>`;
      else if (p.connected) badge = `<span class="badge badge-ok"><span class="dot"></span>Connected</span>`;
      else badge = `<span class="badge badge-off"><span class="dot"></span>Not connected</span>`;
      const initial = (p.label || "?").charAt(0).toUpperCase();
      const action = p.connectable
        ? `<button class="btn btn-sm ${p.connected ? "" : "btn-primary"}" data-connect="${attr(p.id)}">${
            p.connected ? "Reconnect" : "Connect"
          }</button>`
        : `<button class="btn btn-sm" disabled title="${attr(p.note || "Set a client ID to enable")}">Not configured</button>`;
      return `
        <div class="tk-card" style="cursor:default">
          <div class="tk-card-head">
            <div class="tk-logo">${esc(initial)}</div>
            <div style="min-width:0"><div class="tk-name">${esc(p.label)}</div>
              <div class="tk-origin">${(p.scopes || []).length} scope${(p.scopes || []).length === 1 ? "" : "s"}</div></div>
          </div>
          <div class="tk-foot">${badge}${action}</div>
          ${p.note ? `<div class="tk-origin">${esc(p.note)}</div>` : ""}
        </div>`;
    })
    .join("");
  view().innerHTML =
    pageHead(
      "Connected Accounts",
      "OAuth connections to upstream providers. Tokens are sealed in your local encrypted vault — MCP Switchboard never holds them in plaintext and never sends them anywhere but the provider."
    ) +
    (providers.length ? `<div class="grid">${cards}</div>` : `<div class="empty"><div class="empty-title">No OAuth providers registered</div></div>`);

  $$("[data-connect]").forEach((b) =>
    b.addEventListener("click", async () => {
      const original = b.innerHTML;
      b.disabled = true; b.innerHTML = `<span class="spinner"></span>`;
      try {
        const { authorizeUrl } = await api(`/api/connect/${encodeURIComponent(b.dataset.connect)}`, { method: "POST" });
        window.open(authorizeUrl, "_blank", "noopener");
        toast("Opened the provider's consent screen in a new tab.", "ok");
      } catch (e) {
        toast(e.message, "error");
      } finally {
        b.disabled = false; b.innerHTML = original;
      }
    })
  );
}

// ============================================================================
// VIEW: Servers
// ============================================================================
async function renderServers() {
  loadingView("Loading servers…");
  let state;
  try {
    state = await api("/api/state");
  } catch (e) {
    view().innerHTML = pageHead("Servers") + errorBanner(e);
    return;
  }
  const rows = state.servers
    .map((s) => {
      const enabledTools = s.tools.filter((t) => t.enabled !== false).length;
      const badge = s.enabled
        ? `<span class="badge badge-ok"><span class="dot"></span>On</span>`
        : `<span class="badge badge-off"><span class="dot"></span>Off</span>`;
      return `
        <tr data-id="${attr(s.id)}">
          <td><code>${esc(s.id)}</code></td>
          <td class="dim">${esc(s.source)}</td>
          <td>${scopeBadge(s.policy)}</td>
          <td>${badge}</td>
          <td class="dim">${s.enabled ? `${enabledTools}/${s.tools.length}` : "—"}</td>
          <td class="nowrap" style="text-align:right">
            <label class="switch" title="Enable / disable">
              <input type="checkbox" data-toggle="${attr(s.id)}" ${s.enabled ? "checked" : ""} />
              <span class="track"></span>
            </label>
            <button class="btn btn-sm btn-danger" data-remove="${attr(s.id)}" style="margin-left:8px">Remove</button>
          </td>
        </tr>`;
    })
    .join("");
  view().innerHTML =
    pageHead(
      "Servers",
      "Upstream MCP servers mounted behind your endpoint. Toggle one on to mount it live; tools inherit the server's policy scope.",
      `<a class="btn btn-primary" href="#/catalog">+ Add from catalog</a>`
    ) +
    (state.servers.length
      ? `<div class="panel" style="padding:6px 0">
          <table class="table">
            <thead><tr><th>ID</th><th>Source</th><th>Policy</th><th>Status</th><th>Tools</th><th></th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>`
      : `<div class="empty"><div class="empty-ico">⊟</div><div class="empty-title">No servers yet</div>
          <div>Add one from the <a href="#/catalog">Toolkits</a> catalog to get started.</div></div>`);

  $$("[data-toggle]").forEach((cb) =>
    cb.addEventListener("change", async () => {
      const id = cb.dataset.toggle;
      cb.disabled = true;
      try {
        const res = await api(`/api/servers/${encodeURIComponent(id)}/toggle`, { method: "POST" });
        toast(`Server “${id}” ${res.enabled ? "mounted" : "unmounted"}.`, "ok");
        renderServers();
      } catch (e) {
        toast(e.message, "error");
        cb.checked = !cb.checked;
        cb.disabled = false;
      }
    })
  );
  $$("[data-remove]").forEach((b) =>
    b.addEventListener("click", () => {
      const id = b.dataset.remove;
      const m = openModal({
        title: `Remove server “${id}”?`,
        body: `<p class="dim">This unmounts it and deletes it from your config. Catalog entries are unaffected — you can re-add it anytime.</p>`,
        footer: `<button class="btn" data-close="1" id="rm-cancel">Cancel</button>
                 <button class="btn btn-danger" id="rm-confirm">Remove</button>`,
      });
      $("#rm-cancel", m.root).addEventListener("click", m.close);
      $("#rm-confirm", m.root).addEventListener("click", async () => {
        try {
          await api(`/api/servers/${encodeURIComponent(id)}`, { method: "DELETE" });
          m.close();
          toast(`Server “${id}” removed.`, "ok");
          renderServers();
          refreshSidebar();
        } catch (e) {
          toast(e.message, "error");
        }
      });
    })
  );
}

// ============================================================================
// VIEW: Logs (audit)
// ============================================================================
async function renderLogs() {
  loadingView("Loading audit log…");
  let entries;
  try {
    entries = await api("/api/audit");
  } catch (e) {
    view().innerHTML = pageHead("Logs") + errorBanner(e);
    return;
  }
  const rows = entries
    .map(
      (e) => `
      <tr>
        <td class="dim nowrap">${esc(fmtDateTime(e.ts))}</td>
        <td><code>${esc(e.server)}</code></td>
        <td class="mono">${esc(e.tool)}</td>
        <td>${scopeBadge(e.scope)}</td>
        <td class="decision-${esc(e.decision)} mono">${esc(e.phase === "attempt" ? "attempt" : e.decision)}</td>
        <td class="dim">${esc(e.reason || "")}</td>
      </tr>`
    )
    .join("");
  view().innerHTML =
    pageHead(
      "Logs",
      "Append-only audit of every policy decision. The newest 200 entries are shown; the full log lives at ~/.switchboard/audit.log.",
      `<button class="btn btn-sm" id="logs-refresh">Refresh</button>`
    ) +
    (entries.length
      ? `<div class="panel" style="padding:6px 0"><table class="table log-list">
          <thead><tr><th>Time</th><th>Server</th><th>Tool</th><th>Scope</th><th>Decision</th><th>Reason</th></tr></thead>
          <tbody>${rows}</tbody></table></div>`
      : `<div class="empty"><div class="empty-ico">≡</div><div class="empty-title">No activity yet</div>
          <div>Tool calls through your endpoint will appear here.</div></div>`);
  const r = $("#logs-refresh");
  if (r) r.addEventListener("click", renderLogs);
}

// ============================================================================
// VIEW: Usage
// ============================================================================
async function renderUsage() {
  loadingView("Aggregating usage…");
  let u;
  try {
    u = await api("/api/usage");
  } catch (e) {
    view().innerHTML = pageHead("Usage") + errorBanner(e);
    return;
  }
  const maxDay = Math.max(1, ...u.by_day.map((d) => d.count));
  const spark = u.by_day.length
    ? `<div class="spark">${u.by_day
        .map(
          (d) =>
            `<div class="spark-bar" style="height:${Math.max(2, Math.round((d.count / maxDay) * 100))}%" title="${esc(d.day)}: ${d.count}"></div>`
        )
        .join("")}</div>
       <div class="dim" style="font-size:11.5px;margin-top:6px">${esc(u.by_day[0].day)} → ${esc(u.by_day[u.by_day.length - 1].day)}</div>`
    : `<div class="dim">No daily activity yet.</div>`;

  const maxTool = Math.max(1, ...u.top_tools.map((t) => t.count));
  const toolBars = u.top_tools.length
    ? u.top_tools
        .map(
          (t) => `<div class="bar-row">
            <span class="bar-label" title="${attr(t.server + " · " + t.tool)}">${esc(t.tool)}</span>
            <span class="bar-track"><span class="bar-fill" style="width:${Math.round((t.count / maxTool) * 100)}%"></span></span>
            <span class="bar-count">${t.count}</span></div>`
        )
        .join("")
    : `<div class="dim">No tool calls recorded.</div>`;

  const maxSrv = Math.max(1, ...u.by_server.map((s) => s.count));
  const srvBars = u.by_server.length
    ? u.by_server
        .map(
          (s) => `<div class="bar-row">
            <span class="bar-label">${esc(s.server)}</span>
            <span class="bar-track"><span class="bar-fill" style="width:${Math.round((s.count / maxSrv) * 100)}%"></span></span>
            <span class="bar-count">${s.count}</span></div>`
        )
        .join("")
    : `<div class="dim">No per-server activity yet.</div>`;

  view().innerHTML =
    pageHead(
      "Usage",
      "Tool-call metering — the same unit Composio bills on, here purely local and free. Nothing is reported to any server."
    ) +
    `
    <div class="stat-grid">
      <div class="stat stat-accent"><div class="stat-val">${u.total.toLocaleString()}</div><div class="stat-label">Total tool calls</div></div>
      <div class="stat stat-ok"><div class="stat-val">${u.allow.toLocaleString()}</div><div class="stat-label">Allowed</div></div>
      <div class="stat stat-warn"><div class="stat-val">${u.approval_required.toLocaleString()}</div><div class="stat-label">Approval required</div></div>
      <div class="stat stat-danger"><div class="stat-val">${u.deny.toLocaleString()}</div><div class="stat-label">Denied</div></div>
    </div>
    <div class="panel">
      <div class="panel-title">Calls per day</div>
      <div class="panel-sub">UTC daily totals across the audit log.</div>
      ${spark}
    </div>
    <div class="panel">
      <div class="panel-title">Busiest tools</div>
      <div class="bars">${toolBars}</div>
    </div>
    <div class="panel">
      <div class="panel-title">By server</div>
      <div class="bars">${srvBars}</div>
    </div>`;
}

// ============================================================================
// VIEW: Settings — shared loader
// ============================================================================
async function loadSettings() {
  return api("/api/settings");
}

function settingsScaffold(active, title, sub, inner) {
  return pageHead(title, sub) + `<div id="settings-body">${inner}</div>`;
}

// ----- Settings: General -----
async function renderSettingsGeneral() {
  loadingView();
  let s;
  try { s = await loadSettings(); } catch (e) { view().innerHTML = pageHead("General") + errorBanner(e); return; }
  const g = s.general || {};
  const gw = s.gateway || {};
  view().innerHTML = settingsScaffold(
    "general",
    "General",
    "Identify this MCP Switchboard instance and set the default governance posture for new tools.",
    `
    <div class="panel">
      <div class="panel-title">Identity</div>
      <div class="field"><label for="g-org">Organization name</label>
        <input id="g-org" class="input" value="${attr(g.organization_name || "")}" placeholder="Local" /></div>
      <div class="field"><label for="g-proj">Project name</label>
        <input id="g-proj" class="input" value="${attr(g.project_name || "")}" placeholder="default" /></div>
    </div>
    <div class="panel">
      <div class="panel-title">Defaults</div>
      <div class="field"><label for="g-policy">Default policy</label>
        <select id="g-policy" class="select" style="max-width:240px">
          ${["read", "write", "full"].map((p) => `<option value="${p}" ${gw.default_policy === p ? "selected" : ""}>${p}</option>`).join("")}
        </select>
        <div class="hint">Scope applied to a newly added server's tools unless overridden. <code>read</code> is the safe default.</div></div>
      <div class="field"><label for="g-exposure">Tool exposure</label>
        <select id="g-exposure" class="select" style="max-width:240px">
          ${["namespaced", "flat", "search"].map((p) => `<option value="${p}" ${gw.tool_exposure === p ? "selected" : ""}>${p}</option>`).join("")}
        </select>
        <div class="hint"><code>namespaced</code> prefixes tools with the server id (recommended). <code>flat</code> exposes bare names. <code>search</code> exposes a single search tool.</div></div>
    </div>
    <div class="row"><button class="btn btn-primary" id="g-save">Save changes</button></div>`
  );
  $("#g-save").addEventListener("click", async () => {
    const btn = $("#g-save");
    btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> Saving…`;
    try {
      await api("/api/settings", {
        method: "PUT",
        body: JSON.stringify({
          settings: { general: { organization_name: $("#g-org").value.trim(), project_name: $("#g-proj").value.trim() } },
          gateway: { default_policy: $("#g-policy").value, tool_exposure: $("#g-exposure").value },
        }),
      });
      toast("Settings saved to config.", "ok");
      refreshSidebar();
    } catch (e) { toast(e.message, "error"); }
    finally { btn.disabled = false; btn.innerHTML = "Save changes"; }
  });
}

// ----- Settings: Usage & billing (localized) -----
async function renderSettingsUsage() {
  loadingView();
  let u, st;
  try { [u, st] = await Promise.all([api("/api/usage"), api("/api/state")]); }
  catch (e) { view().innerHTML = pageHead("Usage & billing") + errorBanner(e); return; }
  const enabledServers = st.servers.filter((s) => s.enabled).length;
  view().innerHTML =
    pageHead("Usage & billing", "Where a hosted router would meter and bill you, MCP Switchboard runs on your own machine.") +
    `
    <div class="panel" style="border-left:3px solid var(--accent)">
      <div class="panel-title">$0.00 — self-hosted</div>
      <div class="panel-sub">There is no metered billing. You run the gateway locally, hold your own keys, and pay nothing per tool call. This page exists so the dashboard matches a hosted router's layout — the numbers below are yours alone and leave your machine for no one.</div>
    </div>
    <div class="stat-grid">
      <div class="stat stat-accent"><div class="stat-val">${u.total.toLocaleString()}</div><div class="stat-label">Tool calls (lifetime)</div></div>
      <div class="stat"><div class="stat-val">${st.servers.length}</div><div class="stat-label">Servers configured</div></div>
      <div class="stat stat-ok"><div class="stat-val">${enabledServers}</div><div class="stat-label">Servers active</div></div>
      <div class="stat"><div class="stat-val">∞</div><div class="stat-label">Included quota</div></div>
    </div>
    <div class="panel">
      <div class="panel-title">Plan</div>
      <dl class="kv">
        <dt>Plan</dt><dd>Local / self-hosted (Apache-2.0)</dd>
        <dt>Endpoint</dt><dd><code>${esc(st.endpoint)}</code></dd>
        <dt>Cost model</dt><dd>None — your hardware, your keys, your data.</dd>
      </dl>
      <div class="hint">For full metering breakdowns see the <a href="#/usage">Usage</a> page.</div>
    </div>`;
}

// ----- Settings: Auth screen -----
async function renderSettingsAuthScreen() {
  loadingView();
  let s;
  try { s = await loadSettings(); } catch (e) { view().innerHTML = pageHead("Auth screen") + errorBanner(e); return; }
  const a = s.auth_screen || {};
  view().innerHTML =
    pageHead("Auth screen", "Brand the OAuth callback page users land on after connecting a provider.") +
    `
    <div class="panel" style="display:grid;grid-template-columns:1fr 280px;gap:24px">
      <div>
        <div class="field"><label for="a-title">Title</label>
          <input id="a-title" class="input" value="${attr(a.title || "")}" placeholder="Connected" /></div>
        <div class="field"><label for="a-sub">Subtitle</label>
          <input id="a-sub" class="input" value="${attr(a.subtitle || "")}" placeholder="You can close this tab." /></div>
        <div class="field"><label for="a-logo">Logo URL</label>
          <input id="a-logo" class="input" value="${attr(a.logo_url || "")}" placeholder="https://…/logo.svg" />
          <div class="hint">Must be an absolute https URL.</div></div>
        <div class="field"><label for="a-accent">Accent color</label>
          <div class="row"><input id="a-accent" class="input" style="max-width:140px" value="${attr(a.accent_color || "#2dd4bf")}" placeholder="#2dd4bf" />
          <input id="a-accent-pick" type="color" value="${attr(/^#[0-9a-fA-F]{6}$/.test(a.accent_color || "") ? a.accent_color : "#2dd4bf")}" style="width:42px;height:38px;background:none;border:1px solid var(--border);border-radius:8px;cursor:pointer" /></div>
          <div class="hint">Hex color, e.g. <code>#2dd4bf</code>.</div></div>
        <div class="field"><label for="a-support">Support URL</label>
          <input id="a-support" class="input" value="${attr(a.support_url || "")}" placeholder="https://…/help" /></div>
        <div class="row"><button class="btn btn-primary" id="a-save">Save changes</button></div>
      </div>
      <div>
        <div class="field"><label>Live preview</label></div>
        <div id="a-preview"></div>
      </div>
    </div>`;

  const renderPreview = () => {
    const accent = $("#a-accent").value.trim() || "#2dd4bf";
    const safeAccent = /^#[0-9a-fA-F]{3,8}$/.test(accent) ? accent : "#2dd4bf";
    const title = $("#a-title").value.trim() || "Connected";
    const sub = $("#a-sub").value.trim();
    const logo = $("#a-logo").value.trim();
    $("#a-preview").innerHTML = `
      <div style="border:1px solid var(--border);border-top:3px solid ${attr(safeAccent)};border-radius:14px;background:#0d1117;padding:26px 22px;text-align:center">
        ${/^https?:\/\//.test(logo) ? `<img src="${attr(logo)}" alt="" style="max-height:36px;margin-bottom:12px" data-hide-on-error />` : `<span style="display:inline-block;width:13px;height:13px;border-radius:50%;background:#3fb950;margin-bottom:12px"></span>`}
        <div style="font-size:17px;font-weight:600;margin-bottom:6px">${esc(title)}</div>
        <div style="color:var(--muted);font-size:13px">Connected provider. You can close this tab.</div>
        ${sub ? `<div style="color:var(--muted);font-size:12px;margin-top:8px">${esc(sub)}</div>` : ""}
      </div>`;
  };
  ["a-title", "a-sub", "a-logo", "a-accent"].forEach((id) => $("#" + id).addEventListener("input", renderPreview));
  $("#a-accent-pick").addEventListener("input", (e) => { $("#a-accent").value = e.target.value; renderPreview(); });
  renderPreview();

  $("#a-save").addEventListener("click", async () => {
    const btn = $("#a-save");
    btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> Saving…`;
    try {
      await api("/api/settings", {
        method: "PUT",
        body: JSON.stringify({
          settings: {
            auth_screen: {
              title: $("#a-title").value.trim(),
              subtitle: $("#a-sub").value.trim(),
              logo_url: $("#a-logo").value.trim(),
              accent_color: $("#a-accent").value.trim(),
              support_url: $("#a-support").value.trim(),
            },
          },
        }),
      });
      toast("Auth screen saved.", "ok");
    } catch (e) { toast(e.message, "error"); }
    finally { btn.disabled = false; btn.innerHTML = "Save changes"; }
  });
}

// ----- Settings: Webhook -----
async function renderSettingsWebhook() {
  loadingView();
  let s;
  try { s = await loadSettings(); } catch (e) { view().innerHTML = pageHead("Webhook") + errorBanner(e); return; }
  const w = s.webhook || {};
  const secrets = s.vault_secrets || [];
  const events = w.events || [];
  const evRow = (key, label) =>
    `<label class="row" style="gap:8px;margin-bottom:8px;cursor:pointer">
      <input type="checkbox" data-event="${key}" ${events.includes(key) ? "checked" : ""} /> <span>${label}</span></label>`;
  view().innerHTML =
    pageHead("Webhook", "Forward policy decisions to an external URL. Payloads are signed with an HMAC-SHA256 header when a vault secret is set.") +
    `
    <div class="panel">
      <label class="switch" style="margin-bottom:16px"><input type="checkbox" id="w-enabled" ${w.enabled ? "checked" : ""} /><span class="track"></span>
        <span style="margin-left:10px;font-weight:600">Enabled</span></label>
      <div class="field"><label for="w-url">Delivery URL</label>
        <input id="w-url" class="input" value="${attr(w.url || "")}" placeholder="https://example.com/hooks/switchboard" /></div>
      <div class="field"><label>Events to deliver</label>
        ${evRow("allow", "Allowed calls")}${evRow("deny", "Denied calls")}${evRow("approval_required", "Approval-required calls")}</div>
      <div class="field"><label for="w-secret">Signing secret (vault reference)</label>
        <input id="w-secret" class="input" list="vault-secrets" value="${attr(w.secret_ref || "")}" placeholder="vault key name, e.g. webhook_secret" />
        <datalist id="vault-secrets">${secrets.map((n) => `<option value="${attr(n)}"></option>`).join("")}</datalist>
        <div class="hint">${
          secrets.length
            ? `Available vault secrets: ${secrets.map((n) => `<code>${esc(n)}</code>`).join(", ")}.`
            : `No vault secrets yet — add one with <code>switchboard vault set &lt;name&gt;</code>. Without a secret, payloads are sent unsigned.`
        }</div></div>
      <div class="row">
        <button class="btn btn-primary" id="w-save">Save changes</button>
        <button class="btn" id="w-test">Send test event</button>
      </div>
    </div>`;
  $("#w-save").addEventListener("click", async () => {
    const btn = $("#w-save");
    btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> Saving…`;
    try {
      await api("/api/settings", {
        method: "PUT",
        body: JSON.stringify({
          settings: {
            webhook: {
              enabled: $("#w-enabled").checked,
              url: $("#w-url").value.trim(),
              events: $$("[data-event]").filter((c) => c.checked).map((c) => c.dataset.event),
              secret_ref: $("#w-secret").value.trim(),
            },
          },
        }),
      });
      toast("Webhook settings saved.", "ok");
    } catch (e) { toast(e.message, "error"); }
    finally { btn.disabled = false; btn.innerHTML = "Save changes"; }
  });
  $("#w-test").addEventListener("click", async () => {
    const btn = $("#w-test");
    btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> Sending…`;
    try {
      const r = await api("/api/webhook/test", { method: "POST" });
      toast(`Delivered: HTTP ${r.status}${r.signed ? " (signed)" : " (unsigned)"}.`, r.ok ? "ok" : "error");
    } catch (e) { toast(e.message, "error"); }
    finally { btn.disabled = false; btn.innerHTML = "Send test event"; }
  });
}

// ----- Settings: Council & local model (read-only status) -----
// Surfaces the non-secret council summary from /api/settings. Read-only by design: the council's
// cloud keys are vault/env references that must never be typed into a web form (zero custody), and
// the whole feature is edited in config.yaml. This view answers "is the second-opinion / offline
// local-model path wired, and how do I turn it on?" — the local provider is the zero-cloud option.
async function renderSettingsCouncil() {
  loadingView();
  let s;
  try { s = await loadSettings(); } catch (e) { view().innerHTML = pageHead("Council & local model") + errorBanner(e); return; }
  const c = s.council || { enabled: false, providers: { anthropic: false, openai: false, local: false }, local: null, max_rounds: 3, token_budget: 2048, require_approval: false };
  const p = c.providers || {};
  const onOff = (yes) =>
    yes
      ? `<span class="badge badge-ok"><span class="dot"></span>Configured</span>`
      : `<span class="badge badge-off"><span class="dot"></span>Not set</span>`;
  const providerRow = (label, yes, note) =>
    `<div class="row" style="justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid var(--border-soft)">
      <div><div style="font-weight:600">${label}</div><div class="dim" style="font-size:12px">${note}</div></div>
      ${onOff(yes)}</div>`;

  const localBlock = c.local
    ? `<dl class="kv" style="margin:8px 0 0">
         <dt>Endpoint</dt><dd><code>${esc(c.local.base_url)}</code></dd>
         <dt>Model</dt><dd><code>${esc(c.local.default_model)}</code></dd>
       </dl>
       <div class="hint">This is the zero-cloud path: prompts to the local provider never leave your machine and need no API key.</div>`
    : `<div class="hint">No local model wired. Point it at any OpenAI-compatible server you run yourself — <strong>Ollama</strong> (<code>http://127.0.0.1:11434/v1</code>), <strong>LM Studio</strong> (<code>http://127.0.0.1:1234/v1</code>), <strong>llama.cpp</strong>, or <strong>vLLM</strong> — to get a fully offline second opinion from a downloaded model.</div>`;

  const exampleYaml =
`settings:
  network:
    allow_private: [127.0.0.1]   # the outbound guard refuses local hosts unless the exact host is listed
  council:
    enabled: true
    require_approval: false   # outbound + metered; gate it if you like
    max_rounds: 3
    token_budget: 2048
    providers:
      # Zero-cloud, zero-key: a model you downloaded and run locally.
      local:
        base_url: http://127.0.0.1:11434/v1   # Ollama / LM Studio / llama.cpp / vLLM
        default_model: llama3.1
        # api_key_ref: \${vault:local_llm_key}  # only if your server needs a token
      # Optional cloud peers — keys stay as vault/env refs, never inline.
      anthropic:
        default_model: claude-opus-4-8
        api_key_ref: \${vault:anthropic_key}
      openai:
        default_model: gpt-5.5
        api_key_ref: \${env:OPENAI_API_KEY}`;

  view().innerHTML =
    pageHead(
      "Council & local model",
      "Let a connected agent ask a peer model — the other cloud provider, or a local offline model — for a second opinion. Both tools run through the same policy → approval → audit path as any other call."
    ) +
    `<div class="panel">
      <div class="row" style="justify-content:space-between;align-items:center">
        <div class="panel-title" style="margin:0">Status</div>
        ${c.enabled ? `<span class="badge badge-ok"><span class="dot"></span>Enabled</span>` : `<span class="badge badge-off"><span class="dot"></span>Disabled</span>`}
      </div>
      <div class="hint" style="margin-top:4px">${
        c.enabled
          ? `Two tools are live in the <a href="#/playground">Playground</a> and to every connected client: <code>council__council_consult</code> (one relay) and <code>council__council_debate</code> (a bounded multi-round debate, then a synthesized conclusion).`
          : `Off by default — the council makes outbound, metered model calls. Enable it in <code>config.yaml</code> (template below), then the relay tools appear automatically.`
      }</div>
    </div>

    <div class="panel">
      <div class="panel-title">Providers</div>
      ${providerRow("Local model", Boolean(p.local), "OpenAI-compatible server on your machine — offline, no key.")}
      ${providerRow("Anthropic (Claude)", Boolean(p.anthropic), "Cloud peer. Key stays a vault/env reference.")}
      ${providerRow("OpenAI (ChatGPT)", Boolean(p.openai), "Cloud peer. Key stays a vault/env reference.")}
      <div style="margin-top:14px">${localBlock}</div>
    </div>

    <div class="panel">
      <div class="panel-title">Limits</div>
      <dl class="kv">
        <dt>Max debate rounds</dt><dd>${esc(String(c.max_rounds))}</dd>
        <dt>Token budget / call</dt><dd>${esc(String(c.token_budget))}</dd>
        <dt>Requires approval</dt><dd>${c.require_approval ? "yes — every council call waits for an approval decision" : "no — calls run under the standard policy ceiling"}</dd>
      </dl>
    </div>

    <div class="panel">
      <div class="panel-title">Enable it</div>
      <div class="hint" style="margin-bottom:8px">Edit <code>config.yaml</code> — keys are never entered here. Cloud keys stay as <code>\${vault:..}</code> / <code>\${env:..}</code> references resolved at call time; the local model usually needs none.</div>
      <div class="token-box mono" style="white-space:pre-wrap;color:var(--fg)">${esc(exampleYaml)}</div>
    </div>`;
}

// ----- Settings: API keys -----
async function renderSettingsApiKeys() {
  loadingView();
  let data;
  try { data = await api("/api/apikeys"); } catch (e) { view().innerHTML = pageHead("API keys") + errorBanner(e); return; }
  const posture =
    data.enforced
      ? `<span class="badge badge-ok"><span class="dot"></span>Enforced</span>`
      : `<span class="badge badge-off"><span class="dot"></span>Not enforced (loopback)</span>`;
  const rows = data.keys
    .map(
      (k) => `
      <tr>
        <td><code>${esc(k.prefix)}…</code></td>
        <td>${esc(k.name)}</td>
        <td class="dim nowrap">${esc(relTime(k.created))}</td>
        <td class="dim nowrap">${k.last_used ? esc(relTime(k.last_used)) : "never"}</td>
        <td style="text-align:right"><button class="btn btn-sm btn-danger" data-revoke="${attr(k.id)}">Revoke</button></td>
      </tr>`
    )
    .join("");
  view().innerHTML =
    pageHead(
      "API keys",
      "Bearer tokens that authenticate the /mcp endpoint. Required automatically when you expose MCP Switchboard beyond loopback (e.g. via a tunnel). Tokens are shown once and stored hashed.",
      `<button class="btn btn-primary" id="k-new">+ New key</button>`
    ) +
    `<div class="row" style="margin-bottom:14px">Endpoint auth: ${posture} <span class="dim">· require_auth = <code>${esc(data.require_auth)}</code></span></div>` +
    (data.keys.length
      ? `<div class="panel" style="padding:6px 0"><table class="table">
          <thead><tr><th>Key</th><th>Name</th><th>Created</th><th>Last used</th><th></th></tr></thead>
          <tbody>${rows}</tbody></table></div>`
      : `<div class="empty"><div class="empty-ico">🔑</div><div class="empty-title">No API keys yet</div>
          <div>Issue one before exposing your endpoint to ChatGPT, claude.ai, or any non-local client.</div></div>`);

  $("#k-new").addEventListener("click", () => {
    const m = openModal({
      title: "Issue a new API key",
      body: `<div class="field"><label for="k-name">Name</label>
        <input id="k-name" class="input" placeholder="e.g. chatgpt, claude-desktop" autofocus />
        <div class="hint">A label to recognize this key later. The token is shown only once.</div></div>`,
      footer: `<button class="btn" data-close="1" id="k-cancel">Cancel</button>
               <button class="btn btn-primary" id="k-create">Create key</button>`,
    });
    $("#k-cancel", m.root).addEventListener("click", m.close);
    $("#k-create", m.root).addEventListener("click", async () => {
      const name = $("#k-name", m.root).value.trim();
      const btn = $("#k-create", m.root);
      btn.disabled = true; btn.innerHTML = `<span class="spinner"></span>`;
      try {
        const res = await api("/api/apikeys", { method: "POST", body: JSON.stringify({ name }) });
        m.close();
        showTokenModal(res.token, res.key);
      } catch (e) { toast(e.message, "error"); btn.disabled = false; btn.innerHTML = "Create key"; }
    });
  });

  $$("[data-revoke]").forEach((b) =>
    b.addEventListener("click", () => {
      const id = b.dataset.revoke;
      const m = openModal({
        title: "Revoke this API key?",
        body: `<p class="dim">Any client using it will immediately fail to authenticate. This cannot be undone.</p>`,
        footer: `<button class="btn" data-close="1" id="rv-cancel">Cancel</button>
                 <button class="btn btn-danger" id="rv-confirm">Revoke key</button>`,
      });
      $("#rv-cancel", m.root).addEventListener("click", m.close);
      $("#rv-confirm", m.root).addEventListener("click", async () => {
        try {
          await api(`/api/apikeys/${encodeURIComponent(id)}`, { method: "DELETE" });
          m.close();
          toast("Key revoked.", "ok");
          renderSettingsApiKeys();
        } catch (e) { toast(e.message, "error"); }
      });
    })
  );
}

function showTokenModal(token, key) {
  const m = openModal({
    title: "Save your API key now",
    body: `
      <p class="dim mt-0">This is the only time the full token is shown. Store it somewhere safe — MCP Switchboard keeps only a hash.</p>
      <div class="token-box" id="token-val">${esc(token)}</div>
      <button class="btn btn-sm" id="token-copy">Copy token</button>
      <dl class="kv" style="margin-top:16px">
        <dt>Name</dt><dd>${esc(key.name)}</dd>
        <dt>Prefix</dt><dd><code>${esc(key.prefix)}</code></dd>
      </dl>
      <p class="hint">Use it as <code>Authorization: Bearer ${esc(key.prefix)}…</code> or the <code>x-api-key</code> header.</p>`,
    footer: `<button class="btn btn-primary" data-close="1" id="token-done">Done</button>`,
  });
  $("#token-done", m.root).addEventListener("click", () => { m.close(); renderSettingsApiKeys(); });
  $("#token-copy", m.root).addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(token); toast("Token copied.", "ok"); }
    catch { toast("Copy failed — select the token manually.", "error"); }
  });
}

// ============================================================================
// VIEW: Playground — run any exposed tool against the live gateway
// ============================================================================
let playgroundTools = [];

/** Build a JSON arg stub from a tool's input schema so the form starts pre-filled. */
function argSkeleton(schema) {
  const props = (schema && schema.properties) || {};
  const out = {};
  for (const [key, def] of Object.entries(props)) {
    const t = def && def.type;
    out[key] =
      t === "number" || t === "integer" ? 0
      : t === "boolean" ? false
      : t === "array" ? []
      : t === "object" ? {}
      : "";
  }
  return out;
}

function playgroundResultHtml(name, res) {
  const result = (res && res.result) || {};
  const isError = result.isError === true;
  const text = (result.content || [])
    .filter((c) => c && c.type === "text" && typeof c.text === "string")
    .map((c) => c.text)
    .join("\n");
  const dur = typeof res.duration_ms === "number" ? `${res.duration_ms} ms` : "";
  return `
    <div class="panel" style="border-left:3px solid ${isError ? "var(--danger)" : "var(--ok)"}">
      <div class="row" style="justify-content:space-between;align-items:flex-start">
        <div class="panel-title" style="margin:0">${isError ? "Tool returned an error" : "Result"} · <code>${esc(name)}</code></div>
        <span class="dim nowrap">${esc(dur)}</span>
      </div>
      ${text ? `<div class="token-box" style="white-space:pre-wrap;max-height:42vh;overflow:auto;color:var(--fg)">${esc(text)}</div>` : ""}
      <details style="margin-top:6px">
        <summary class="dim" style="cursor:pointer">Raw result JSON</summary>
        <div class="token-box" style="white-space:pre-wrap;max-height:42vh;overflow:auto;color:var(--fg)">${esc(JSON.stringify(result, null, 2))}</div>
      </details>
    </div>`;
}

async function renderPlayground() {
  loadingView("Loading exposed tools…");
  let data;
  try {
    data = await api("/api/playground/tools");
  } catch (e) {
    view().innerHTML = pageHead("Playground") + errorBanner(e);
    return;
  }
  playgroundTools = data.tools || [];
  const exposure = data.tool_exposure || "namespaced";

  const head = pageHead(
    "Playground",
    "Run any exposed tool against the live gateway. Calls take the exact governed path an agent uses — policy, approval gates, and the audit log all apply. Tools run only from this machine."
  );

  if (playgroundTools.length === 0) {
    view().innerHTML =
      head +
      `<div class="empty">
        <div class="empty-ico">▷</div>
        <div class="empty-title">No tools are exposed</div>
        <div>Enable a server under <a href="#/servers">Servers</a> to expose its tools here.</div>
      </div>`;
    return;
  }

  view().innerHTML =
    head +
    `<div class="panel">
      <div class="row" style="justify-content:space-between;align-items:baseline;margin-bottom:6px">
        <div class="panel-title" style="margin:0">Exposed tools</div>
        <span class="dim">exposure: <code>${esc(exposure)}</code> · ${playgroundTools.length} tool${playgroundTools.length === 1 ? "" : "s"}</span>
      </div>
      <div class="field">
        <label for="pg-tool">Tool</label>
        <select id="pg-tool" class="select">
          ${playgroundTools.map((t, i) => `<option value="${i}">${esc(t.name)}</option>`).join("")}
        </select>
      </div>
      <div id="pg-desc" class="hint" style="margin:-8px 0 16px"></div>
      <div class="field" style="max-width:none">
        <label for="pg-args">Arguments (JSON)</label>
        <textarea id="pg-args" class="input mono" rows="9" spellcheck="false"></textarea>
        <div class="hint">Match the tool's input schema. <a href="#" id="pg-schema-link">View input schema</a> · <a href="#" id="pg-reset-link">reset to defaults</a>.</div>
      </div>
      <div class="row">
        <button class="btn btn-primary" id="pg-run">Run tool</button>
      </div>
    </div>
    <div id="pg-result"></div>`;

  const sel = $("#pg-tool");
  const argsBox = $("#pg-args");

  const loadTool = (i) => {
    const t = playgroundTools[i];
    if (!t) return;
    const required = (t.inputSchema && t.inputSchema.required) || [];
    $("#pg-desc").innerHTML =
      esc(t.description || "No description provided.") +
      (required.length
        ? ` <span class="dim">· required: ${required.map((r) => `<code>${esc(r)}</code>`).join(", ")}</span>`
        : "");
    argsBox.value = JSON.stringify(argSkeleton(t.inputSchema), null, 2);
  };

  sel.addEventListener("change", () => loadTool(Number(sel.value)));
  $("#pg-reset-link").addEventListener("click", (e) => {
    e.preventDefault();
    loadTool(Number(sel.value));
  });
  $("#pg-schema-link").addEventListener("click", (e) => {
    e.preventDefault();
    const t = playgroundTools[Number(sel.value)];
    if (!t) return;
    openModal({
      title: `Input schema · ${t.name}`,
      body: `<div class="token-box" style="white-space:pre-wrap;max-height:52vh;overflow:auto;color:var(--fg)">${esc(JSON.stringify(t.inputSchema || {}, null, 2))}</div>`,
      footer: `<button class="btn btn-primary" data-close="1">Close</button>`,
    });
  });

  $("#pg-run").addEventListener("click", async () => {
    const t = playgroundTools[Number(sel.value)];
    if (!t) return;
    let parsed;
    try {
      const raw = argsBox.value.trim();
      parsed = raw ? JSON.parse(raw) : {};
    } catch {
      toast("Arguments are not valid JSON.", "error");
      return;
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      toast("Arguments must be a JSON object.", "error");
      return;
    }
    const btn = $("#pg-run");
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Running…`;
    const out = $("#pg-result");
    out.innerHTML = `<div class="loading"><span class="spinner"></span> Calling <code>${esc(t.name)}</code>…</div>`;
    try {
      const res = await api("/api/playground/call", {
        method: "POST",
        body: JSON.stringify({ name: t.name, arguments: parsed }),
      });
      out.innerHTML = playgroundResultHtml(t.name, res);
    } catch (e) {
      out.innerHTML = `<div class="panel" style="border-left:3px solid var(--danger)">${errorBanner(e)}</div>`;
    } finally {
      btn.disabled = false;
      btn.innerHTML = "Run tool";
    }
  });

  loadTool(0);
}

// ============================================================================
// VIEW: Triggers (poll-first, local-first change detection)
// ============================================================================
// The editable config (carries args/item_path/item_key the runtime snapshot omits).
// Reassigned on every render; handlers attached in a render close over the live value.
let triggersCfg = { enabled: false, poll_interval_seconds: 60, definitions: [] };

async function renderTriggers() {
  loadingView("Loading triggers…");
  let state, settings, toolData, templateData;
  try {
    [state, settings, toolData, templateData] = await Promise.all([
      api("/api/triggers"),
      loadSettings(),
      api("/api/playground/tools").catch(() => ({ tools: [] })),
      api("/api/trigger-templates").catch(() => ({ templates: [] })),
    ]);
  } catch (e) {
    view().innerHTML = pageHead("Triggers") + errorBanner(e);
    return;
  }

  const templates = templateData.templates || [];
  const raw = settings.triggers || {};
  triggersCfg = {
    enabled: raw.enabled === true,
    poll_interval_seconds: raw.poll_interval_seconds || 60,
    definitions: Array.isArray(raw.definitions) ? raw.definitions.map((d) => ({ ...d })) : [],
  };
  const toolNames = (toolData.tools || []).map((t) => t.name);

  // Pull the (possibly unsaved) global switch + interval back into the cfg before any PUT,
  // so adding/removing/toggling a row never silently discards a pending global edit.
  const syncGlobalFromDom = () => {
    const en = $("#tr-enabled");
    if (en) triggersCfg.enabled = en.checked;
    const iv = $("#tr-interval");
    if (iv) {
      const n = Number(iv.value.trim());
      if (Number.isInteger(n) && n >= 1 && n <= 86400) triggersCfg.poll_interval_seconds = n;
    }
  };
  const putTriggers = () => api("/api/triggers", { method: "PUT", body: JSON.stringify({ triggers: triggersCfg }) });

  const statusBadge = (t) => {
    if (!triggersCfg.enabled) return `<span class="badge badge-off"><span class="dot"></span>Polling off</span>`;
    if (!t.enabled) return `<span class="badge badge-off"><span class="dot"></span>Disabled</span>`;
    if (t.paused) return `<span class="badge badge-off" title="Paused — definition kept, scheduled polling silenced"><span class="dot"></span>Paused</span>`;
    if (t.last_error) return `<span class="badge badge-off" title="${attr(t.last_error)}"><span class="dot"></span>Error</span>`;
    if (!t.baseline) return `<span class="badge"><span class="dot"></span>Arming…</span>`;
    return `<span class="badge badge-ok"><span class="dot"></span>Armed</span>`;
  };

  const rows = state.triggers
    .map((t) => {
      const detail =
        t.detection === "items"
          ? `<span class="dim">items · ${t.seen_count} seen</span>`
          : `<span class="dim">hash</span>`;
      return `
        <tr data-id="${attr(t.id)}">
          <td><div>${esc(t.name || t.id)}</div>${t.name ? `<code class="dim">${esc(t.id)}</code>` : ""}</td>
          <td class="mono">${esc(t.tool)}</td>
          <td>${detail}</td>
          <td class="dim nowrap">${t.interval_seconds}s</td>
          <td class="dim nowrap">${t.last_poll_ts ? esc(relTime(t.last_poll_ts)) : "never"}</td>
          <td class="dim nowrap">${t.last_fire_ts ? esc(relTime(t.last_fire_ts)) : "never"}</td>
          <td>${statusBadge(t)}</td>
          <td class="nowrap" style="text-align:right">
            <button class="btn btn-sm" data-tr-poll="${attr(t.id)}" title="Poll once now">Poll now</button>
            ${t.paused
              ? `<button class="btn btn-sm" data-tr-resume="${attr(t.id)}" style="margin-left:6px" title="Resume scheduled polling">Resume</button>`
              : `<button class="btn btn-sm" data-tr-pause="${attr(t.id)}" style="margin-left:6px" title="Pause scheduled polling — keeps the definition, silences the poll">Pause</button>`}
            <button class="btn btn-sm" data-tr-edit="${attr(t.id)}" style="margin-left:6px">Edit</button>
            <label class="switch" title="Enable / disable" style="margin-left:8px;vertical-align:middle">
              <input type="checkbox" data-tr-toggle="${attr(t.id)}" ${t.enabled ? "checked" : ""} />
              <span class="track"></span>
            </label>
            <button class="btn btn-sm btn-danger" data-tr-remove="${attr(t.id)}" style="margin-left:8px">Remove</button>
          </td>
        </tr>`;
    })
    .join("");

  const fires = state.recent_fires || [];
  const fireRows = fires
    .map(
      (f) => `
      <tr>
        <td class="dim nowrap">${esc(fmtDateTime(f.ts))}</td>
        <td>${esc(f.trigger_name || f.trigger_id)}</td>
        <td class="mono">${esc(f.tool)}</td>
        <td class="dim">${esc(f.detection)}</td>
        <td class="dim nowrap">+${f.new_count}</td>
        <td class="dim">${f.sample_keys && f.sample_keys.length ? esc(f.sample_keys.join(", ")) : "—"}</td>
      </tr>`
    )
    .join("");

  view().innerHTML =
    pageHead(
      "Triggers",
      "Poll-first, local-first change detection. Each trigger periodically calls a (read-scoped) tool through the governed endpoint and fires when the result changes — no inbound port, public tunnel, or provider push required. The poll takes the full policy → approval → audit path; the fire is an observation delivered to your webhook as a distinct switchboard.trigger event and to the local log below.",
      `<button class="btn btn-primary" id="tr-add"${toolNames.length ? "" : " disabled title=\"Enable a server under Servers first\""}>+ Add trigger</button>`
    ) +
    `<div class="panel">
      <div class="row" style="justify-content:space-between;align-items:center">
        <label class="switch"><input type="checkbox" id="tr-enabled" ${triggersCfg.enabled ? "checked" : ""} /><span class="track"></span>
          <span style="margin-left:10px;font-weight:600">Polling enabled</span></label>
        <span class="badge ${state.running ? "badge-ok" : "badge-off"}"><span class="dot"></span>${state.running ? "Running" : "Stopped"}</span>
      </div>
      <div class="field" style="margin-top:14px"><label for="tr-interval">Default poll interval (seconds)</label>
        <input id="tr-interval" class="input" type="number" min="1" max="86400" style="max-width:200px" value="${attr(String(triggersCfg.poll_interval_seconds))}" />
        <div class="hint">Applied to triggers that don't set their own interval. The master switch above must be on for scheduled polling to run — <strong>Poll now</strong> always works for one-shot testing.</div></div>
      <div class="row"><button class="btn btn-primary" id="tr-save">Save changes</button></div>
    </div>` +
    (state.triggers.length
      ? `<div class="panel" style="padding:6px 0">
          <table class="table">
            <thead><tr><th>Trigger</th><th>Tool</th><th>Detection</th><th>Interval</th><th>Last poll</th><th>Last fire</th><th>Status</th><th></th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>`
      : `<div class="empty"><div class="empty-ico">⚡</div><div class="empty-title">No triggers yet</div>
          <div>${toolNames.length ? `Add one to watch a tool's result for changes.` : `Enable a server under <a href="#/servers">Servers</a> first, then add a trigger.`}</div></div>`) +
    `<div class="panel" style="padding:6px 0;margin-top:18px">
      <div class="panel-title" style="padding:6px 16px 0">Recent fires</div>
      ${
        fires.length
          ? `<table class="table">
              <thead><tr><th>Time</th><th>Trigger</th><th>Tool</th><th>Detection</th><th>New</th><th>Sample keys</th></tr></thead>
              <tbody>${fireRows}</tbody>
            </table>`
          : `<div class="dim" style="padding:10px 16px 14px">No fires recorded yet. A trigger fires when its polled result changes after the first (baseline) poll.</div>`
      }
    </div>`;

  // --- global save ---
  $("#tr-save").addEventListener("click", async () => {
    const iv = Number($("#tr-interval").value.trim());
    if (!Number.isInteger(iv) || iv < 1 || iv > 86400) {
      toast("Default interval must be a whole number of seconds (1–86400).", "error");
      return;
    }
    triggersCfg.enabled = $("#tr-enabled").checked;
    triggersCfg.poll_interval_seconds = iv;
    const btn = $("#tr-save");
    btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> Saving…`;
    try {
      await putTriggers();
      toast("Trigger settings saved.", "ok");
      renderTriggers();
    } catch (e) { toast(e.message, "error"); btn.disabled = false; btn.innerHTML = "Save changes"; }
  });

  // --- add ---
  const addBtn = $("#tr-add");
  if (addBtn) addBtn.addEventListener("click", () =>
    openTriggerModal(null, toolNames, async (def, _isEdit, m) => {
      if (triggersCfg.definitions.some((d) => d.id === def.id)) {
        toast(`A trigger with id “${def.id}” already exists.`, "error");
        return;
      }
      syncGlobalFromDom();
      triggersCfg.definitions.push(def);
      try {
        await putTriggers();
        m.close();
        toast(`Trigger “${def.id}” added.`, "ok");
        renderTriggers();
      } catch (e) {
        toast(e.message, "error");
        triggersCfg.definitions = triggersCfg.definitions.filter((d) => d.id !== def.id);
      }
    }, templates)
  );

  // --- edit ---
  $$("[data-tr-edit]").forEach((b) =>
    b.addEventListener("click", () => {
      const id = b.dataset.trEdit;
      const def = triggersCfg.definitions.find((d) => d.id === id);
      if (!def) return;
      openTriggerModal(def, toolNames, async (next, _isEdit, m) => {
        syncGlobalFromDom();
        const i = triggersCfg.definitions.findIndex((d) => d.id === id);
        if (i >= 0) triggersCfg.definitions[i] = next;
        try {
          await putTriggers();
          m.close();
          toast(`Trigger “${id}” saved.`, "ok");
          renderTriggers();
        } catch (e) { toast(e.message, "error"); }
      });
    })
  );

  // --- enable / disable a definition ---
  $$("[data-tr-toggle]").forEach((cb) =>
    cb.addEventListener("change", async () => {
      const id = cb.dataset.trToggle;
      const def = triggersCfg.definitions.find((d) => d.id === id);
      if (!def) return;
      cb.disabled = true;
      syncGlobalFromDom();
      def.enabled = cb.checked;
      try {
        await putTriggers();
        toast(`Trigger “${id}” ${cb.checked ? "enabled" : "disabled"}.`, "ok");
        renderTriggers();
      } catch (e) { toast(e.message, "error"); cb.checked = !cb.checked; cb.disabled = false; }
    })
  );

  // --- poll now ---
  $$("[data-tr-poll]").forEach((b) =>
    b.addEventListener("click", async () => {
      const id = b.dataset.trPoll;
      b.disabled = true;
      const orig = b.innerHTML;
      b.innerHTML = `<span class="spinner"></span>`;
      try {
        const r = await api(`/api/triggers/${encodeURIComponent(id)}/poll`, { method: "POST" });
        if (r.skipped) toast(`Not polled: ${r.skipped}.`, "error");
        else if (!r.ok) toast(`Poll error: ${r.error || "upstream error"}.`, "error");
        else if (r.baseline) toast("Baseline established — nothing fires on the first poll.", "ok");
        else if (r.fired) toast(`Fired — ${r.new_count} new ${r.detection === "items" ? "item(s)" : "change"}.`, "ok");
        else toast("Polled — no change.", "ok");
        renderTriggers();
      } catch (e) { toast(e.message, "error"); b.disabled = false; b.innerHTML = orig; }
    })
  );

  // --- pause / resume (in-memory; keeps the definition, silences the scheduled poll) ---
  $$("[data-tr-pause]").forEach((b) =>
    b.addEventListener("click", async () => {
      const id = b.dataset.trPause;
      b.disabled = true;
      try {
        await api(`/api/triggers/${encodeURIComponent(id)}/pause`, { method: "POST" });
        toast(`Trigger “${id}” paused — definition kept, polling silenced until resumed.`, "ok");
        renderTriggers();
      } catch (e) { toast(e.message, "error"); b.disabled = false; }
    })
  );
  $$("[data-tr-resume]").forEach((b) =>
    b.addEventListener("click", async () => {
      const id = b.dataset.trResume;
      b.disabled = true;
      try {
        await api(`/api/triggers/${encodeURIComponent(id)}/resume`, { method: "POST" });
        toast(`Trigger “${id}” resumed.`, "ok");
        renderTriggers();
      } catch (e) { toast(e.message, "error"); b.disabled = false; }
    })
  );

  // --- remove ---
  $$("[data-tr-remove]").forEach((b) =>
    b.addEventListener("click", () => {
      const id = b.dataset.trRemove;
      const m = openModal({
        title: `Remove trigger “${id}”?`,
        body: `<p class="dim">This deletes the trigger from your config and stops polling it. Its past fired-event history is unaffected.</p>`,
        footer: `<button class="btn" id="trr-cancel" data-close="1">Cancel</button>
                 <button class="btn btn-danger" id="trr-confirm">Remove</button>`,
      });
      $("#trr-cancel", m.root).addEventListener("click", m.close);
      $("#trr-confirm", m.root).addEventListener("click", async () => {
        syncGlobalFromDom();
        const prev = triggersCfg.definitions;
        triggersCfg.definitions = prev.filter((d) => d.id !== id);
        try {
          await putTriggers();
          m.close();
          toast(`Trigger “${id}” removed.`, "ok");
          renderTriggers();
        } catch (e) { toast(e.message, "error"); triggersCfg.definitions = prev; }
      });
    })
  );
}

// Add / edit a trigger definition. `onSaved(def, isEdit, modal)` owns persistence + close.
// `templates` (optional) seeds a "Start from a template" picker shown only when adding — it
// pre-fills the detection wiring (tool hint, item_path/item_key, interval, default args) for a
// common "watch X for new items" recipe; the operator then points the tool field at the exposed
// name their mounted server actually provides.
function openTriggerModal(existing, toolNames, onSaved, templates = []) {
  const isEdit = !!existing;
  const d = existing || {};
  const datalist = (toolNames || []).map((n) => `<option value="${attr(n)}"></option>`).join("");
  const tplPicker =
    !isEdit && templates.length
      ? `<div class="field"><label for="trm-tpl">Start from a template <span class="dim">(optional)</span></label>
          <select id="trm-tpl" class="select">
            <option value="">— blank trigger —</option>
            ${templates
              .map((t) => `<option value="${attr(t.id)}" title="${attr(t.description || "")}">${esc(t.category ? `${t.category} · ` : "")}${esc(t.name)}</option>`)
              .join("")}
          </select>
          <div class="hint">Pre-fills the detection wiring for a common “new item” recipe. Then point <strong>Tool</strong> at the exposed name your mounted server provides (e.g. <code>github__list_issues</code>).</div></div>`
      : "";
  const m = openModal({
    title: isEdit ? `Edit trigger “${esc(d.id)}”` : "Add trigger",
    body: tplPicker + `
      <div class="field"><label for="trm-id">ID</label>
        <input id="trm-id" class="input" value="${attr(d.id || "")}" ${isEdit ? "disabled" : ""} placeholder="new-issues" />
        <div class="hint">A stable, unique key. Appears in the webhook payload and the fired-event log.</div></div>
      <div class="field"><label for="trm-name">Name <span class="dim">(optional)</span></label>
        <input id="trm-name" class="input" value="${attr(d.name || "")}" placeholder="New GitHub issues" /></div>
      <div class="field"><label for="trm-tool">Tool</label>
        <input id="trm-tool" class="input" list="trm-tools" value="${attr(d.tool || "")}" placeholder="github__list_issues" />
        <datalist id="trm-tools">${datalist}</datalist>
        <div class="hint">An exposed tool name (see <a href="#/playground">Playground</a>). Polled on the governed path — keep it read-scoped.</div></div>
      <div class="field"><label for="trm-interval">Interval (seconds) <span class="dim">(optional)</span></label>
        <input id="trm-interval" class="input" type="number" min="1" max="86400" style="max-width:200px" value="${attr(d.interval_seconds != null ? String(d.interval_seconds) : "")}" placeholder="use default" />
        <div class="hint">Overrides the default poll interval for this trigger only.</div></div>
      <div class="field" style="max-width:none"><label for="trm-args">Arguments (JSON) <span class="dim">(optional)</span></label>
        <textarea id="trm-args" class="input mono" rows="4" spellcheck="false" placeholder="{}">${esc(d.args ? JSON.stringify(d.args, null, 2) : "")}</textarea></div>
      <div class="field"><label>Item-level detection <span class="dim">(optional)</span></label>
        <div class="row" style="gap:10px">
          <input id="trm-path" class="input" value="${attr(d.item_path || "")}" placeholder="item_path · e.g. issues" />
          <input id="trm-key" class="input" value="${attr(d.item_key || "")}" placeholder="item_key · e.g. id" />
        </div>
        <div class="hint">Set both to fire on NEW array items keyed by a unique field (the “new row / issue / email” semantic). Leave blank to fire on any whole-response change (hash).</div></div>
      <label class="switch" style="margin-top:4px"><input type="checkbox" id="trm-enabled" ${d.enabled !== false ? "checked" : ""} /><span class="track"></span>
        <span style="margin-left:10px">Enabled</span></label>`,
    footer: `<button class="btn" id="trm-cancel" data-close="1">Cancel</button>
             <button class="btn btn-primary" id="trm-save">${isEdit ? "Save" : "Add trigger"}</button>`,
  });
  $("#trm-cancel", m.root).addEventListener("click", m.close);

  // Template picker → prefill. Resolve the bare tool_hint to the operator's REAL exposed name when
  // their mounted server provides it (e.g. `list_issues` → `github__list_issues`); otherwise seed
  // the bare hint as a starting point. Set item_path/item_key only TOGETHER and only when the
  // template's path is non-empty — that mirrors the runtime's `item_path && item_key` gate, so the
  // form shows the SAME detection mode (item vs hash) the trigger will actually use.
  const tplSel = $("#trm-tpl", m.root);
  if (tplSel) {
    const resolveTool = (hint) =>
      (toolNames || []).find((n) => n === hint || n.endsWith("__" + hint)) || hint || "";
    tplSel.addEventListener("change", () => {
      const t = templates.find((x) => x.id === tplSel.value);
      if (!t) return;
      const idEl = $("#trm-id", m.root);
      if (!idEl.value.trim()) idEl.value = t.id;
      $("#trm-name", m.root).value = t.name || "";
      $("#trm-tool", m.root).value = resolveTool(t.tool_hint);
      $("#trm-tool", m.root).placeholder = t.tool_hint ? `e.g. <server>__${t.tool_hint}` : "github__list_issues";
      $("#trm-interval", m.root).value = t.interval_seconds != null ? String(t.interval_seconds) : "";
      $("#trm-args", m.root).value = t.args ? JSON.stringify(t.args, null, 2) : "";
      const itemMode = !!(t.item_path && t.item_key);
      $("#trm-path", m.root).value = itemMode ? t.item_path : "";
      $("#trm-key", m.root).value = itemMode ? t.item_key : "";
    });
  }

  $("#trm-save", m.root).addEventListener("click", () => {
    const id = $("#trm-id", m.root).value.trim();
    const tool = $("#trm-tool", m.root).value.trim();
    if (!id) { toast("ID is required.", "error"); return; }
    if (!tool) { toast("Tool is required.", "error"); return; }

    let args;
    const rawArgs = $("#trm-args", m.root).value.trim();
    if (rawArgs) {
      try { args = JSON.parse(rawArgs); }
      catch { toast("Arguments are not valid JSON.", "error"); return; }
      if (args === null || typeof args !== "object" || Array.isArray(args)) {
        toast("Arguments must be a JSON object.", "error");
        return;
      }
    }

    let interval_seconds;
    const intervalRaw = $("#trm-interval", m.root).value.trim();
    if (intervalRaw) {
      interval_seconds = Number(intervalRaw);
      if (!Number.isInteger(interval_seconds) || interval_seconds < 1 || interval_seconds > 86400) {
        toast("Interval must be a whole number of seconds (1–86400).", "error");
        return;
      }
    }

    const path = $("#trm-path", m.root).value.trim();
    const key = $("#trm-key", m.root).value.trim();
    if ((path && !key) || (!path && key)) {
      toast("Item-level detection needs BOTH item_path and item_key (or neither).", "error");
      return;
    }

    const name = $("#trm-name", m.root).value.trim();
    const def = { id, tool, enabled: $("#trm-enabled", m.root).checked };
    if (name) def.name = name;
    if (interval_seconds != null) def.interval_seconds = interval_seconds;
    if (args) def.args = args;
    if (path) def.item_path = path;
    if (key) def.item_key = key;
    onSaved(def, isEdit, m);
  });
}

// ============================================================================
// Shared bits for the owner-decision pages
// ============================================================================
function riskBadge(risk) {
  const cls = risk === "high" ? "badge-danger" : risk === "medium" ? "badge-warn" : "badge-off";
  return `<span class="badge ${cls}">${esc(risk)}</span>`;
}

function statusBadge(status) {
  const cls =
    { pending: "badge-warn", approved: "badge-ok", consumed: "badge-ok", denied: "badge-danger", expired: "badge-off" }[status] ||
    "badge-off";
  return `<span class="badge ${cls}">${esc(status)}</span>`;
}

function csvList(text) {
  return String(text || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

// ============================================================================
// VIEW: Approvals (design 3.3) - the calls that wait for the owner
//
// Approving here does not just record a click. The gateway asks for owner presence (Windows Hello, or a
// challenge at its own terminal) with the exact action, and signs the decision only if that succeeds, so a
// script that steals the owner session still cannot approve anything.
// ============================================================================
const approvalsUi = { poll: null, tick: null, busy: false, offsetMs: 0 };

function stopApprovalsTimers() {
  clearInterval(approvalsUi.poll);
  clearInterval(approvalsUi.tick);
  approvalsUi.poll = null;
  approvalsUi.tick = null;
}

function clock(iso) {
  const left = Date.parse(iso) - (Date.now() + approvalsUi.offsetMs);
  if (!Number.isFinite(left)) return "?";
  if (left <= 0) return "expired";
  const s = Math.floor(left / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${ss}` : `${m}:${ss}`;
}

function argsCell(a) {
  let text;
  try { text = JSON.stringify(a.args_preview ?? {}); } catch { text = "(arguments cannot be shown)"; }
  const short = text.length > 140 ? text.slice(0, 137) + "..." : text;
  const pretty = (() => { try { return JSON.stringify(a.args_preview ?? {}, null, 2); } catch { return text; } })();
  return `<code class="args-preview">${esc(short)}</code>` +
    (text.length > 140 ? `<details class="args-full"><summary>full</summary><pre>${esc(pretty)}</pre></details>` : "");
}

function pendingRow(a, withActions) {
  return `
    <tr data-id="${attr(a.id)}">
      <td><strong>${esc(a.client || a.principal)}</strong>${a.client ? `<div class="dim small" title="${attr(a.principal)}">${esc(a.principal)}</div>` : ""}</td>
      <td><code>${esc(a.server)}</code></td>
      <td><code>${esc(a.tool)}</code></td>
      <td>${riskBadge(a.risk)} ${scopeBadge(a.scope)}</td>
      <td>${argsCell(a)}</td>
      <td class="nowrap"><span class="countdown" data-expires="${attr(a.expires)}">${esc(clock(a.expires))}</span></td>
      <td class="table-actions nowrap">${withActions}</td>
    </tr>`;
}

function approvalsHtml(data) {
  const warn = [];
  if (data.auto_approve) warn.push("<code>SWITCHBOARD_AUTO_APPROVE=1</code> is set on the gateway: every gated call is approved with no human decision. That is for test harnesses only.");
  if (data.insecure_presence) warn.push("<code>SWITCHBOARD_INSECURE_APPROVAL=1</code> is set on the gateway: owner presence checks are switched off, so approving needs no Windows Hello. That is for test harnesses only.");
  const warnHtml = warn.map((w) => `<div class="error-banner">${w}</div>`).join("");

  const pending = data.pending || [];
  const approved = data.approved || [];
  const history = data.history || [];

  const pendingHtml = pending.length
    ? `<div class="panel" style="padding:6px 0;overflow-x:auto"><table class="table" id="pending-table">
        <thead><tr><th>Client</th><th>Server</th><th>Tool</th><th>Risk</th><th>Arguments</th><th>Expires in</th><th></th></tr></thead>
        <tbody>${pending
          .map((a) =>
            pendingRow(
              a,
              `<button class="btn btn-sm btn-primary" data-approve="${attr(a.id)}">Approve</button>
               <button class="btn btn-sm btn-danger" data-deny="${attr(a.id)}">Deny</button>`
            )
          )
          .join("")}</tbody></table></div>`
    : `<div class="empty"><div class="empty-ico">✓</div><div class="empty-title">Nothing is waiting for you</div>
        <div>A call that needs approval appears here the moment a client makes it. Approvals expire after ${esc(Math.round(data.ttl_seconds / 60))} minutes.</div></div>`;

  const approvedHtml = approved.length
    ? `<h3 class="section-title">Approved, not used yet</h3>
       <div class="panel" style="padding:6px 0;overflow-x:auto"><table class="table">
        <thead><tr><th>Client</th><th>Server</th><th>Tool</th><th>Risk</th><th>Arguments</th><th>Valid for</th><th></th></tr></thead>
        <tbody>${approved.map((a) => pendingRow(a, `<button class="btn btn-sm btn-danger" data-deny="${attr(a.id)}">Withdraw</button>`)).join("")}</tbody></table></div>`
    : "";

  const historyHtml = history.length
    ? `<h3 class="section-title">History <span class="dim small">(last ${history.length})</span></h3>
       <div class="panel" style="padding:6px 0;overflow-x:auto"><table class="table">
        <thead><tr><th>When</th><th>Status</th><th>Client</th><th>Call</th><th>Risk</th><th>Via</th><th>Arguments</th></tr></thead>
        <tbody>${history
          .map(
            (a) => `<tr>
              <td class="dim nowrap">${esc(relTime(a.decided_at || a.created))}</td>
              <td>${statusBadge(a.status)}</td>
              <td>${esc(a.client || a.principal)}</td>
              <td><code>${esc(a.server)}__${esc(a.tool)}</code></td>
              <td>${riskBadge(a.risk)}</td>
              <td class="dim">${esc(a.decided_via || "none")}${a.presence ? ` <span class="small">(${esc(a.presence)})</span>` : ""}</td>
              <td>${argsCell(a)}</td></tr>`
          )
          .join("")}</tbody></table></div>`
    : "";

  return warnHtml + pendingHtml + approvedHtml + historyHtml;
}

function tickApprovals() {
  let anyExpired = false;
  $$(".countdown").forEach((el) => {
    const t = clock(el.dataset.expires);
    if (el.textContent !== t) el.textContent = t;
    if (t === "expired") anyExpired = true;
  });
  return anyExpired;
}

async function loadApprovals(first) {
  const data = await api("/api/approvals");
  approvalsUi.offsetMs = Date.parse(data.now) - Date.now();
  if (first) {
    view().innerHTML =
      pageHead(
        "Approvals",
        "Calls that wait for you. Approving asks Windows Hello (or the gateway's own terminal) to confirm you are present. An approval covers exactly these arguments, works once, and expires.",
        `<button class="btn" id="ap-refresh">Refresh</button>`
      ) + `<div id="ap-body"></div>`;
    $("#ap-refresh").addEventListener("click", () => loadApprovals(false).catch((e) => toast(e.message, "error")));
  }
  const body = $("#ap-body");
  if (!body) return;
  body.innerHTML = approvalsHtml(data);
  bindApprovalButtons();
  updateNavCount((data.pending || []).length);
}

function bindApprovalButtons() {
  $$("[data-approve]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (approvalsUi.busy) return;
      approvalsUi.busy = true;
      const id = b.dataset.approve;
      $$("[data-approve],[data-deny]").forEach((x) => (x.disabled = true));
      b.innerHTML = `<span class="spinner"></span> Waiting for you`;
      toast("Confirm on the machine that runs the gateway (Windows Hello or its terminal).", "ok");
      try {
        await api(`/api/approvals/${encodeURIComponent(id)}/approve`, { method: "POST", body: "{}" });
        toast("Approved. The client can now repeat the identical call once.", "ok");
      } catch (e) {
        toast(e.message, "error");
      } finally {
        approvalsUi.busy = false;
        loadApprovals(false).catch(() => {});
      }
    })
  );
  $$("[data-deny]").forEach((b) =>
    b.addEventListener("click", async () => {
      if (approvalsUi.busy) return;
      approvalsUi.busy = true;
      try {
        await api(`/api/approvals/${encodeURIComponent(b.dataset.deny)}/deny`, { method: "POST", body: "{}" });
        toast("Denied.", "ok");
      } catch (e) {
        toast(e.message, "error");
      } finally {
        approvalsUi.busy = false;
        loadApprovals(false).catch(() => {});
      }
    })
  );
}

async function renderApprovals() {
  loadingView();
  stopApprovalsTimers();
  try {
    await loadApprovals(true);
  } catch (e) {
    view().innerHTML = pageHead("Approvals") + errorBanner(e);
    return;
  }
  // The countdown moves every second; the list is re-read every few seconds, and at once when one expires.
  approvalsUi.tick = setInterval(() => {
    if (currentPath() !== "/approvals") return stopApprovalsTimers();
    if (tickApprovals() && !approvalsUi.busy) loadApprovals(false).catch(() => {});
  }, 1000);
  approvalsUi.poll = setInterval(() => {
    if (currentPath() !== "/approvals") return stopApprovalsTimers();
    if (!approvalsUi.busy && !document.hidden) loadApprovals(false).catch(() => {});
  }, 3000);
}

// ============================================================================
// VIEW: Clients (design 3.1) - who may call /mcp, and how far
// ============================================================================
function clientFormHtml(c, isNew) {
  const sel = (val, opts) =>
    opts.map(([v, label]) => `<option value="${attr(v)}"${v === (val || "") ? " selected" : ""}>${esc(label)}</option>`).join("");
  return `
    ${isNew ? `<div class="field"><label for="c-id">Client id</label>
      <input id="c-id" class="input" placeholder="e.g. codex" autofocus />
      <div class="hint">1 to 64 characters from a-z, 0-9, '-' and '_'. This is the name the bridge uses: <code>switchboard bridge --client &lt;id&gt;</code>.</div></div>` : ""}
    <div class="field"><label for="c-desc">Description</label>
      <input id="c-desc" class="input" value="${attr(c.description || "")}" placeholder="What this client is" /></div>
    <div class="field"><label for="c-servers">Servers it may see and call</label>
      <input id="c-servers" class="input" value="${attr((c.servers || []).join(", "))}" placeholder="* or voice, youtube" />
      <div class="hint">Comma separated server id globs. <code>*</code> is every server; an empty list is none.</div></div>
    <div class="field"><label for="c-tools">Tool allowlist (optional)</label>
      <input id="c-tools" class="input" value="${attr((c.tools || []).join(", "))}" placeholder="voice__text_*" />
      <div class="hint">Exposed tool name globs. Empty means every tool of the allowed servers.</div></div>
    <div class="field"><label for="c-excl">Hidden tools (optional)</label>
      <input id="c-excl" class="input" value="${attr((c.exclude_tools || []).join(", "))}" placeholder="*__delete_*" /></div>
    <div class="row">
      <div class="field" style="flex:1;min-width:160px"><label for="c-scope">Scope ceiling</label>
        <select id="c-scope" class="select">${sel(c.max_scope, [["", "(server ceiling)"], ["read", "read"], ["write", "write"], ["full", "full"]])}</select></div>
      <div class="field" style="flex:1;min-width:160px"><label for="c-risk">Risk ceiling</label>
        <select id="c-risk" class="select">${sel(c.max_risk, [["", "(high)"], ["low", "low"], ["medium", "medium"], ["high", "high (still needs approval)"]])}</select></div>
      <div class="field" style="flex:1;min-width:160px"><label for="c-rate">Calls per minute</label>
        <input id="c-rate" class="input" type="number" min="1" value="${attr(c.limits && c.limits.per_minute ? c.limits.per_minute : "")}" placeholder="no limit" /></div>
    </div>`;
}

function readClientForm(m, existing) {
  const v = (id) => $(id, m.root).value.trim();
  const body = {
    description: v("#c-desc"),
    servers: csvList(v("#c-servers")),
  };
  const tools = csvList(v("#c-tools"));
  const excl = csvList(v("#c-excl"));
  const rate = Number.parseInt(v("#c-rate"), 10);
  if (existing) {
    // PUT merges; null clears an optional field.
    body.description = body.description || null;
    body.tools = tools.length ? tools : null;
    body.exclude_tools = excl.length ? excl : null;
    body.max_scope = v("#c-scope") || null;
    body.max_risk = v("#c-risk") || null;
    body.limits = Number.isFinite(rate) && rate > 0 ? { per_minute: rate } : null;
  } else {
    if (!body.description) delete body.description;
    if (tools.length) body.tools = tools;
    if (excl.length) body.exclude_tools = excl;
    if (v("#c-scope")) body.max_scope = v("#c-scope");
    if (v("#c-risk")) body.max_risk = v("#c-risk");
    if (Number.isFinite(rate) && rate > 0) body.limits = { per_minute: rate };
  }
  return body;
}

function confirmModal({ title, body, confirmLabel, danger, onConfirm }) {
  const m = openModal({
    title,
    body: `<p class="dim mt-0">${body}</p>`,
    footer: `<button class="btn" data-close="1" id="cf-cancel">Cancel</button>
             <button class="btn ${danger ? "btn-danger" : "btn-primary"}" id="cf-ok">${esc(confirmLabel)}</button>`,
  });
  $("#cf-cancel", m.root).addEventListener("click", m.close);
  $("#cf-ok", m.root).addEventListener("click", async () => {
    const btn = $("#cf-ok", m.root);
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span>`;
    try {
      await onConfirm();
      m.close();
    } catch (e) {
      toast(e.message, "error");
      btn.disabled = false;
      btn.textContent = confirmLabel;
    }
  });
  return m;
}

async function renderClients() {
  loadingView();
  let data;
  try { data = await api("/api/clients"); } catch (e) { view().innerHTML = pageHead("Clients") + errorBanner(e); return; }
  const posture = data.enforced
    ? `<span class="badge badge-ok"><span class="dot"></span>Enforced</span>`
    : `<span class="badge badge-off"><span class="dot"></span>Single-user mode</span>`;
  const rows = data.clients
    .map(
      (c) => `
      <tr data-id="${attr(c.id)}">
        <td><strong>${esc(c.id)}</strong>${c.description ? `<div class="dim small">${esc(c.description)}</div>` : ""}</td>
        <td><code>${esc((c.servers || []).join(", ") || "(none)")}</code>${c.tools && c.tools.length ? `<div class="dim small">tools: ${esc(c.tools.join(", "))}</div>` : ""}${c.exclude_tools && c.exclude_tools.length ? `<div class="dim small">hidden: ${esc(c.exclude_tools.join(", "))}</div>` : ""}</td>
        <td class="nowrap">${scopeBadge(c.max_scope || "server")} ${riskBadge(c.max_risk || "high")}${c.limits && c.limits.per_minute ? `<div class="dim small">${esc(c.limits.per_minute)}/min</div>` : ""}</td>
        <td class="dim">${c.keys.length} key${c.keys.length === 1 ? "" : "s"}${c.key_file ? "" : ` <span class="small">(no key file)</span>`}${c.keys[0] && c.keys[0].last_used ? `<div class="small">used ${esc(relTime(c.keys[0].last_used))}</div>` : ""}</td>
        <td class="table-actions nowrap">
          <button class="btn btn-sm" data-edit="${attr(c.id)}">Edit</button>
          <button class="btn btn-sm" data-rotate="${attr(c.id)}">Rotate key</button>
          <button class="btn btn-sm btn-danger" data-revoke="${attr(c.id)}">Revoke keys</button>
          <button class="btn btn-sm btn-danger" data-remove="${attr(c.id)}">Remove</button>
        </td>
      </tr>`
    )
    .join("");
  view().innerHTML =
    pageHead(
      "Clients",
      "The callers that may use /mcp, what each may see, and how far it may go. A client's keys live in a protected key file read by the bridge; a token is never shown here.",
      `<button class="btn btn-primary" id="cl-new">+ Add client</button>`
    ) +
    `<div class="row" style="margin-bottom:14px">Access control: ${posture}
      <span class="dim">· ${data.clients.length} client${data.clients.length === 1 ? "" : "s"}${data.enforced ? ": /mcp needs a key bound to one of them" : ": add one and /mcp starts requiring a client key"}</span></div>` +
    (data.orphan_keys && data.orphan_keys.length
      ? `<div class="error-banner">${data.orphan_keys.length} key(s) are bound to a client that is not configured and are refused: ${esc(data.orphan_keys.map((k) => `${k.id} (${k.client})`).join(", "))}</div>`
      : "") +
    (data.clients.length
      ? `<div class="panel" style="padding:6px 0;overflow-x:auto"><table class="table">
          <thead><tr><th>Client</th><th>Servers</th><th>Ceilings (scope, risk)</th><th>Keys</th><th></th></tr></thead>
          <tbody>${rows}</tbody></table></div>`
      : `<div class="empty"><div class="empty-ico">☺</div><div class="empty-title">No clients yet</div>
          <div>Add one for each tool that calls Switchboard (Claude Code, Codex, a local model) so each has its own key, its own servers and its own ceiling.</div></div>`);

  $("#cl-new").addEventListener("click", () => {
    const m = openModal({
      title: "Add a client",
      body: clientFormHtml({ servers: ["*"], max_scope: "read", max_risk: "low" }, true),
      footer: `<button class="btn" data-close="1" id="cl-cancel">Cancel</button>
               <button class="btn btn-primary" id="cl-create">Create client</button>`,
    });
    $("#cl-cancel", m.root).addEventListener("click", m.close);
    $("#cl-create", m.root).addEventListener("click", async () => {
      const btn = $("#cl-create", m.root);
      btn.disabled = true;
      btn.innerHTML = `<span class="spinner"></span>`;
      try {
        const body = readClientForm(m, null);
        body.id = $("#c-id", m.root).value.trim();
        await api("/api/clients", { method: "POST", body: JSON.stringify(body) });
        m.close();
        toast("Client created. Its key is in the protected key file for the bridge.", "ok");
        renderClients();
      } catch (e) {
        toast(e.message, "error");
        btn.disabled = false;
        btn.textContent = "Create client";
      }
    });
  });

  $$("[data-edit]").forEach((b) =>
    b.addEventListener("click", () => {
      const c = data.clients.find((x) => x.id === b.dataset.edit);
      if (!c) return;
      const m = openModal({
        title: `Edit ${c.id}`,
        body: clientFormHtml(c, false),
        footer: `<button class="btn" data-close="1" id="cl-cancel">Cancel</button>
                 <button class="btn btn-primary" id="cl-save">Save</button>`,
      });
      $("#cl-cancel", m.root).addEventListener("click", m.close);
      $("#cl-save", m.root).addEventListener("click", async () => {
        const btn = $("#cl-save", m.root);
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner"></span>`;
        try {
          await api(`/api/clients/${encodeURIComponent(c.id)}`, { method: "PUT", body: JSON.stringify(readClientForm(m, c)) });
          m.close();
          toast("Saved. A running gateway applies it on the next call.", "ok");
          renderClients();
        } catch (e) {
          toast(e.message, "error");
          btn.disabled = false;
          btn.textContent = "Save";
        }
      });
    })
  );

  $$("[data-rotate]").forEach((b) =>
    b.addEventListener("click", () => {
      const id = b.dataset.rotate;
      confirmModal({
        title: `Rotate the key of ${id}?`,
        body: "A new key replaces the old one in the client key file. The old key stops working at once, so a client that holds it directly must be given the new one.",
        confirmLabel: "Rotate key",
        onConfirm: async () => {
          await api(`/api/clients/${encodeURIComponent(id)}/rotate`, { method: "POST", body: "{}" });
          toast("Key rotated. The bridge reads the new one from the key file.", "ok");
          renderClients();
        },
      });
    })
  );

  $$("[data-revoke]").forEach((b) =>
    b.addEventListener("click", () => {
      const id = b.dataset.revoke;
      confirmModal({
        title: `Revoke the keys of ${id}?`,
        body: "Every key of this client stops working and its key file is deleted. The client entry stays, so you can rotate a new key in later.",
        confirmLabel: "Revoke keys",
        danger: true,
        onConfirm: async () => {
          await api(`/api/clients/${encodeURIComponent(id)}?purge=0`, { method: "DELETE" });
          toast("Keys revoked.", "ok");
          renderClients();
        },
      });
    })
  );

  $$("[data-remove]").forEach((b) =>
    b.addEventListener("click", () => {
      const id = b.dataset.remove;
      confirmModal({
        title: `Remove ${id}?`,
        body: "Its keys are revoked, its key file is deleted and the client is removed from the config. This cannot be undone.",
        confirmLabel: "Remove client",
        danger: true,
        onConfirm: async () => {
          await api(`/api/clients/${encodeURIComponent(id)}`, { method: "DELETE" });
          toast("Client removed.", "ok");
          renderClients();
        },
      });
    })
  );
}

// ============================================================================
// Chrome: pending count, kill-switch banner and toggle, sign out
// ============================================================================
function updateNavCount(n) {
  const el = $("#nav-approvals-count");
  if (!el) return;
  el.hidden = !(n > 0);
  el.textContent = String(n);
}

let killActive = false;

function paintKill(st) {
  killActive = Boolean(st && st.active);
  let banner = $("#kill-banner");
  if (killActive) {
    if (!banner) {
      banner = document.createElement("div");
      banner.id = "kill-banner";
      banner.className = "kill-banner";
      banner.setAttribute("role", "alert");
      document.body.prepend(banner);
    }
    banner.textContent = `Kill switch is ON${st.since ? ` since ${new Date(st.since).toLocaleString()}` : ""}: every tool call, resource read and prompt get is refused until it is turned off.`;
  } else if (banner) {
    banner.remove();
  }
  const btn = $("#kill-toggle");
  if (btn) {
    btn.textContent = killActive ? "Kill switch ON: turn off" : "Kill switch off: turn on";
    btn.classList.toggle("btn-danger", !killActive);
    btn.classList.toggle("btn-primary", killActive);
  }
}

async function refreshChrome() {
  try {
    const [s, a] = await Promise.all([api("/api/state", { quiet: true }), api("/api/approvals", { quiet: true })]);
    paintKill(s.kill_switch);
    updateNavCount((a.pending || []).length);
  } catch {
    /* the sign-in banner already explains a 401; a transient failure just leaves the last state */
  }
}

$("#kill-toggle").addEventListener("click", () => {
  if (killActive) {
    confirmModal({
      title: "Turn the kill switch off?",
      body: "Every tool call, resource read and prompt get is allowed again. Windows Hello (or the gateway's terminal) will ask you to confirm you are present on the machine that runs the gateway.",
      confirmLabel: "Turn off",
      onConfirm: async () => {
        paintKill(await api("/api/kill", { method: "POST", body: JSON.stringify({ on: false }) }));
        toast("Kill switch off. Calls are allowed again.", "ok");
      },
    });
  } else {
    confirmModal({
      title: "Turn the kill switch on?",
      body: "Every tool call, resource read and prompt get is refused at once, for every client, until you turn it off.",
      confirmLabel: "Turn on",
      danger: true,
      onConfirm: async () => {
        paintKill(await api("/api/kill", { method: "POST", body: JSON.stringify({ on: true }) }));
        toast("Kill switch on. Everything is refused.", "ok");
      },
    });
  }
});

$("#sign-out").addEventListener("click", async () => {
  try {
    await api("/api/session", { method: "DELETE" });
  } catch {
    /* already signed out */
  }
  clearSession();
  stopApprovalsTimers();
  paintKill(null);
  view().innerHTML = pageHead("Signed out", "Run switchboard dashboard login in a terminal on this machine to sign in again.");
  showSignInBanner("You signed out.");
});

setInterval(() => {
  if (sessionId && !document.hidden) refreshChrome();
}, 10000);

// ============================================================================
// VIEW: OAuth consent (design 3.15). A client asked to connect through the OAuth server; the owner decides here, with
// the session header and the CSRF value (the old page and its cookie are gone). Reached from the link on the page the
// client's browser shows: #/oauth/<pending id>.
// ============================================================================
async function renderOAuthConsent(pendingId) {
  loadingView();
  const head = pageHead("Authorize a client", "A client asked to connect to this MCP Switchboard.");
  if (!sessionId) {
    view().innerHTML =
      head +
      `<div class="panel"><div class="panel-title">Sign in first</div>
        <p class="panel-sub">Only the owner of this machine can decide this. Run <code>switchboard dashboard login</code> in a terminal on this machine; it opens a dashboard tab already signed in. Then open this same address in that tab (this tab keeps no sign-in).</p></div>`;
    return;
  }
  let p;
  try {
    p = await api(`/api/oauth/pending/${encodeURIComponent(pendingId)}`);
  } catch (e) {
    view().innerHTML = head + errorBanner(e);
    return;
  }
  const scopes = (p.scopes || []).map((s) => `<li><code>${esc(s)}</code></li>`).join("");
  const maps = p.maps_to_client
    ? `<div class="error-banner">The name this client registered with is <strong>${esc(p.maps_to_client)}</strong>, the id of one of your configured clients. Approving gives it that client's access (servers and ceilings). Approve only if you started this connection yourself.</div>`
    : "";
  view().innerHTML =
    head +
    `<div class="panel">
      <div class="panel-title">${esc(p.client_name)}</div>
      <p class="panel-sub">wants an access token for <code>${esc(p.resource)}</code> with these scopes:</p>
      <ul>${scopes}</ul>
      ${maps}
      <div class="row">
        <button class="btn" id="oc-deny">Deny</button>
        <button class="btn btn-primary" id="oc-approve">Approve</button>
      </div>
    </div>`;
  const decide = async (decision) => {
    $("#oc-deny").disabled = true;
    $("#oc-approve").disabled = true;
    try {
      const r = await api("/api/oauth/consent", { method: "POST", body: JSON.stringify({ pending_id: pendingId, decision }) });
      window.location.assign(r.redirect);
    } catch (e) {
      toast(e.message, "error");
      $("#oc-deny").disabled = false;
      $("#oc-approve").disabled = false;
    }
  };
  $("#oc-deny").addEventListener("click", () => decide("deny"));
  $("#oc-approve").addEventListener("click", () => decide("approve"));
}

// ============================================================================
// Router
// ============================================================================
const routes = {
  "/catalog": renderCatalog,
  "/accounts": renderAccounts,
  "/servers": renderServers,
  "/clients": renderClients,
  "/approvals": renderApprovals,
  "/triggers": renderTriggers,
  "/playground": renderPlayground,
  "/logs": renderLogs,
  "/usage": renderUsage,
  "/settings/general": renderSettingsGeneral,
  "/settings/usage": renderSettingsUsage,
  "/settings/auth-screen": renderSettingsAuthScreen,
  "/settings/webhook": renderSettingsWebhook,
  "/settings/council": renderSettingsCouncil,
  "/settings/api-keys": renderSettingsApiKeys,
};

function currentPath() {
  const h = location.hash.replace(/^#/, "");
  return h || "/catalog";
}

function setActiveNav(path) {
  $$(".nav-item").forEach((a) => {
    const match = a.getAttribute("data-match");
    a.classList.toggle("active", match === "#" + path);
  });
}

async function router() {
  const path = currentPath();
  const consent = /^\/oauth\/([A-Za-z0-9_-]{1,128})$/.exec(path);
  const fn = consent ? () => renderOAuthConsent(consent[1]) : routes[path] || routes["/catalog"];
  stopApprovalsTimers();
  setActiveNav(path);
  window.scrollTo(0, 0);
  try {
    await fn();
  } catch (e) {
    view().innerHTML = pageHead("Error") + errorBanner(e);
  }
}

window.addEventListener("hashchange", router);

let started = false;
async function start() {
  if (started) return;
  started = true;
  await establishSession(); // redeem #login=<code> or recover the CSRF value, before any view fetches
  if (!location.hash) location.hash = "#/catalog";
  refreshSidebar();
  refreshChrome();
  router();
}

window.addEventListener("DOMContentLoaded", start);

// DOMContentLoaded may have already fired (script is at end of body).
if (document.readyState !== "loading") start();
