// Deterministic oracle for src/publicapi.ts (consented no-key public API tools). Zero network by default:
// the fetcher is a stub that records every call. Set PUBLICAPI_LIVE=1 to also make one real call per
// eligible provider (permitted live check; still consent-gated through the same client).
//
// It proves:
//   conformance  every case in publicapi/conformance.v1.json (shared with the Python port) passes.
//   catalog      every provider is auth none, https, base host on its own allowlist, no key-like strings,
//                every recommended provider is eligible in a commercial app.
//   consent      no fetch before consent, after Not now, with the master off, or for a provider switched off;
//                Enable recommended / Customize / Not now persist through a file store; restricted providers
//                cannot be enabled in a commercial app.
//   failures     offline, timeout, 429, non-JSON, redirect off the allowlist map to stable codes; usage counts.
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PublicApiClient, planCall, shapeResult, eligibility, fileStateStore, loadBundledCatalog } from "../dist/publicapi.js";
import { NetGuardError } from "../dist/netguard.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` : ${detail}` : ""}`);
};
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

const catalog = loadBundledCatalog();
const conf = JSON.parse(readFileSync(new URL("../publicapi/conformance.v1.json", import.meta.url), "utf8"));

// ---- conformance
for (const c of conf.plan) {
  const state = { version: 1, usage: {}, ...(c.state ?? conf.default_state) };
  const plan = planCall(catalog, c.app, state, c.provider, c.tool, c.args, { ms: c.now_ms ?? 10 ** 12, day: c.today ?? "2026-11-05" });
  const got = plan.ok ? { url: plan.url } : { error: plan.error.code };
  assert(`conformance plan: ${c.name}`, eq(got, c.expect), eq(got, c.expect) ? "" : JSON.stringify(got));
}
for (const c of conf.shape) {
  const tool = catalog.providers.find((p) => p.id === c.provider).tools.find((t) => t.name === c.tool);
  const got = shapeResult(tool, c.body);
  assert(`conformance shape: ${c.name}`, eq(got, c.expect), eq(got, c.expect) ? "" : JSON.stringify(got));
}

// ---- catalog hygiene
const commercial = { id: "meetingops", commercial: true };
for (const p of catalog.providers) {
  const host = new URL(p.base_url).hostname;
  assert(`catalog ${p.id}: auth none, https, own host allowlisted`, p.auth === "none" && p.base_url.startsWith("https://") && p.allowed_hosts.includes(host));
  assert(`catalog ${p.id}: no key-like strings`, !/(api[_-]?key|token|secret|bearer)=/i.test(JSON.stringify(p)));
  for (const a of p.recommended_for) assert(`catalog ${p.id}: recommended in ${a} implies eligible commercially`, eligibility(p, { id: a, commercial: true }).eligible);
}
const usable = catalog.providers.filter((p) => p.apps.some((a) => eligibility(p, { id: a, commercial: true }).eligible));
assert("at least three providers usable in a commercial app", usable.length >= 3, usable.map((p) => p.id).join(","));

// ---- client with stub fetcher
const dir = mkdtempSync(join(tmpdir(), "publicapi-"));
const statePath = join(dir, "state.json");
let calls = [];
let reply = () => ({ status: 200, body: { base: "USD", date: "2026-11-05", rates: { CAD: 1.4 } } });
const fakeRes = ({ status, body, location, raw }) => ({
  status, ok: status >= 200 && status < 300, headers: new Headers(location ? { location } : {}),
  json: async () => (raw !== undefined ? JSON.parse(raw) : body),
});
const fetcher = async (url, init) => {
  calls.push({ url, ua: init.headers["User-Agent"] });
  const r = reply(url);
  if (r instanceof Error) throw r;
  return fakeRes(r);
};
let now = Date.parse("2026-11-05T12:00:00Z");
const mk = () => new PublicApiClient({ app: commercial, store: fileStateStore(statePath), catalog, fetcher, clock: () => now });

let c = mk();
assert("first run needs prompt", c.needsPrompt());
let r = await c.call("frankfurter", "latest_rates", { base: "USD" });
assert("no fetch before consent", !r.ok && r.error.code === "CONSENT_REQUIRED" && calls.length === 0);

c.decide("not_now");
assert("Not now persists and stops prompting", !mk().needsPrompt() && mk().status().consent === "declined");
r = await mk().call("frankfurter", "latest_rates", { base: "USD" });
assert("no fetch after Not now", !r.ok && r.error.code === "CONSENT_REQUIRED" && calls.length === 0);

let threw = false;
try { mk().decide("custom", ["nager-date"]); } catch { threw = true; }
assert("restricted provider cannot be enabled in a commercial app", threw && mk().status().consent === "declined");

mk().decide("recommended");
const st = mk().status();
assert("Enable recommended enables exactly the recommended set",
  eq(st.providers.filter((p) => p.enabled).map((p) => p.id).sort(), ["frankfurter", "wikidata", "wikipedia"]));
assert("status lists restricted providers with a reason", st.providers.find((p) => p.id === "open-meteo").reason?.includes("commercial"));
assert("status hides providers not offered in this app", !st.providers.some((p) => p.id === "openverse"));

r = await mk().call("frankfurter", "latest_rates", { base: "USD", symbols: "CAD" });
assert("call after consent returns shaped data with source", r.ok && r.data.rates.CAD === 1.4 && r.source.attribution.includes("Frankfurter") && calls.length === 1);
assert("descriptive User-Agent sent", calls[0].ua === catalog.user_agent);
assert("usage counted", mk().status().providers.find((p) => p.id === "frankfurter").used_today === 1);

r = await mk().call("frankfurter", "latest_rates", { base: "USD" });
assert("min interval enforced locally without fetch", !r.ok && r.error.code === "RATE_LIMITED" && calls.length === 1);
now += 5000;

mk().setProvider("frankfurter", false);
r = await mk().call("frankfurter", "latest_rates", { base: "USD" });
assert("per-provider toggle off blocks without fetch", !r.ok && r.error.code === "PROVIDER_DISABLED" && calls.length === 1);
mk().setProvider("frankfurter", true);

mk().setMaster(false);
r = await mk().call("wikipedia", "page_summary", { title: "Canada" });
assert("master off blocks without fetch", !r.ok && r.error.code === "CONSENT_REQUIRED" && calls.length === 1);
mk().setMaster(true);
assert("master on restores provider choices", mk().status().providers.filter((p) => p.enabled).length === 3);

const fails = [
  ["offline", () => new NetGuardError("dns_failed", "x"), "OFFLINE"],
  ["timeout", () => new NetGuardError("timeout", "x"), "TIMEOUT"],
  ["network error", () => new TypeError("fetch failed"), "OFFLINE"],
  ["429", () => ({ status: 429 }), "RATE_LIMITED"],
  ["500", () => ({ status: 500 }), "UPSTREAM_ERROR"],
  ["non-JSON", () => ({ status: 200, raw: "<html>" }), "BAD_RESPONSE"],
  ["redirect off allowlist", () => ({ status: 302, location: "https://evil.example/x" }), "HOST_NOT_ALLOWED"],
];
for (const [name, mkReply, code] of fails) {
  now += 5000;
  reply = mkReply;
  r = await mk().call("wikipedia", "page_summary", { title: "Canada" });
  assert(`failure maps: ${name} -> ${code}`, !r.ok && r.error.code === code, r.ok ? "ok" : r.error.code);
}
{
  const same = mk();
  now += 5000;
  reply = () => ({ status: 503 });
  await same.call("wikipedia", "page_summary", { title: "Canada" });
  assert("last error surfaces in status", same.status().providers.find((p) => p.id === "wikipedia").last_error?.code === "UPSTREAM_ERROR");
}

now += 5000;
let hops = 0;
reply = (url) => (hops++ === 0 ? { status: 301, location: "/api/rest_v1/page/summary/Canada_2" } : { status: 200, body: { title: "Canada" } });
r = await mk().call("wikipedia", "page_summary", { title: "Canada" });
assert("same-host redirect followed", r.ok && calls.at(-1).url.endsWith("Canada_2"));

rmSync(dir, { recursive: true, force: true });

// ---- permitted live checks (opt-in)
if (process.env.PUBLICAPI_LIVE === "1") {
  const liveDir = mkdtempSync(join(tmpdir(), "publicapi-live-"));
  const probes = {
    frankfurter: ["latest_rates", { base: "USD", symbols: "CAD" }],
    wikipedia: ["page_summary", { title: "Toronto" }],
    wikidata: ["search_entities", { search: "Ontario" }],
    "wikimedia-commons": ["search_media", { gsrsearch: "Toronto skyline" }],
    openverse: ["search_images", { q: "city skyline" }],
  };
  const live = new PublicApiClient({ app: { id: "clippilot", commercial: true }, store: fileStateStore(join(liveDir, "s.json")), catalog });
  live.decide("custom", Object.keys(probes));
  for (const [id, [tool, args]] of Object.entries(probes)) {
    const t0 = Date.now();
    const res = await live.call(id, tool, args);
    const n = res.ok ? (Array.isArray(res.data) ? res.data.length : Object.keys(res.data).length) : 0;
    assert(`LIVE ${id}.${tool}`, res.ok && n > 0, res.ok ? `${n} items, ${Date.now() - t0} ms` : `${res.error.code}: ${res.error.message}`);
  }
  rmSync(liveDir, { recursive: true, force: true });
}

const failed = checks.filter((x) => !x.ok).length;
console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
process.exit(failed ? 1 : 0);
