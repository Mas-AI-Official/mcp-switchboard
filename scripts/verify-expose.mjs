// Deterministic oracle for `switchboard expose` (src/expose.ts) — the tunnel command that puts the
// governed `/mcp` endpoint on the public internet. Pure logic + a static wiring scan: NO network, NO
// ports, NO spawned tunnel binaries, NO model tokens. Importing dist/expose.js is side-effect-free
// (runExpose is declared, never invoked at load), exactly like verify-dashboard imports dist/dashboard.js.
//
// Two halves:
//   HALF A (runtime, pure) — exercises the EXPORTED TUNNELS spec table + TUNNEL_KINDS against synthetic
//     inputs: per-kind binary name, the EXACT argv built for a given port, and the URL regex's
//     match / extract / reject behaviour against real provider sample URLs (cloudflared trycloudflare.com,
//     ngrok ngrok(-free).app|dev|io, tailscale *.ts.net) and cross-provider lookalikes. This proves the
//     security-relevant tunnel wiring: the argv only ever targets loopback, and each regex extracts the
//     RIGHT public URL from noisy stdout/stderr while rejecting the other providers' URLs and evil.com.
//   HALF B (static wiring scan of compiled dist/expose.js) — tsc emits readable JS, so the security
//     invariants survive verbatim. Proves the dedicated listener FORCES auth on (requireAuth: () => true),
//     answers JSON for tunnel compat, serves ONLY /mcp (exactly one mountMcpEndpoint, ZERO app.<verb>
//     route registrations) with a catch-all 404, binds 127.0.0.1, spawns the tunnel SHELL-LESSLY,
//     fails CLOSED (spawn error → close the listener → rethrow, never leave a naked port open), and
//     tears everything down on shutdown (kill child → close listener → stop gateway). This is the
//     regression guard against a refactor that accidentally tunnels the dashboard or skips the auth force.
// Zero deps (node stdlib + the package's compiled output). Build first.
import { readFileSync } from "node:fs";
import { TUNNELS, TUNNEL_KINDS } from "../dist/expose.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// =================================================================================================
// HALF A — runtime checks against the exported TUNNELS / TUNNEL_KINDS
// =================================================================================================

const PORT = 8131; // arbitrary non-default local listener port the tunnel points at

// --- 1. TUNNEL_KINDS is the canonical, complete, non-redundant set --------------------------------
{
  assert("TUNNEL_KINDS is exactly [cloudflared, ngrok, tailscale] in order", eq(TUNNEL_KINDS, ["cloudflared", "ngrok", "tailscale"]), JSON.stringify(TUNNEL_KINDS));
  assert("TUNNEL_KINDS has no duplicates", new Set(TUNNEL_KINDS).size === TUNNEL_KINDS.length);
  // Set equality both ways: every kind has a spec, and there is no orphan spec for an unlisted kind.
  assert("every TUNNEL_KINDS entry has a TUNNELS spec", TUNNEL_KINDS.every((k) => TUNNELS[k] && typeof TUNNELS[k] === "object"));
  assert("TUNNELS has no spec for a kind outside TUNNEL_KINDS", Object.keys(TUNNELS).every((k) => TUNNEL_KINDS.includes(k)), JSON.stringify(Object.keys(TUNNELS)));
}

// --- 2. Per-kind spec shape + EXACT argv (the only attack surface: what we spawn) ------------------
const EXPECT = {
  cloudflared: { bin: "cloudflared", argv: ["tunnel", "--url", `http://127.0.0.1:${PORT}`] },
  ngrok: { bin: "ngrok", argv: ["http", String(PORT), "--log=stdout", "--log-format=json"] },
  tailscale: { bin: "tailscale", argv: ["funnel", String(PORT)] },
};
for (const kind of TUNNEL_KINDS) {
  const spec = TUNNELS[kind];
  const ex = EXPECT[kind];
  assert(`${kind}: bin is "${ex.bin}"`, spec.bin === ex.bin, spec.bin);
  assert(`${kind}: args is a function`, typeof spec.args === "function");
  const argv = spec.args(PORT);
  assert(`${kind}: args(port) is a string[] (spawn needs strings, never a number)`, Array.isArray(argv) && argv.every((x) => typeof x === "string"), JSON.stringify(argv));
  assert(`${kind}: args(${PORT}) builds the exact argv`, eq(argv, ex.argv), JSON.stringify(argv));
  assert(`${kind}: args(port) references the listener port`, JSON.stringify(argv).includes(String(PORT)));
  assert(`${kind}: urlRegex is a RegExp`, spec.urlRegex instanceof RegExp);
  assert(`${kind}: install hint is a non-empty string`, typeof spec.install === "string" && spec.install.length > 0);
  assert(`${kind}: note caveat is a non-empty string`, typeof spec.note === "string" && spec.note.length > 0);
}

// --- 3. Argv targets LOOPBACK only — never an external/all-interfaces bind -------------------------
{
  // cloudflared is the only kind that names an explicit host in argv; it MUST be 127.0.0.1.
  assert("cloudflared argv targets http://127.0.0.1 (loopback, not a public bind)", TUNNELS.cloudflared.args(PORT).join(" ").includes(`http://127.0.0.1:${PORT}`));
  // No kind may ever ask the tunnel to reach 0.0.0.0 (all interfaces).
  for (const kind of TUNNEL_KINDS) {
    assert(`${kind}: argv never references 0.0.0.0`, !TUNNELS[kind].args(PORT).join(" ").includes("0.0.0.0"));
  }
}

// --- 4. urlRegex MATCHES the real public URL each provider prints ---------------------------------
{
  assert("cloudflared regex matches a trycloudflare.com URL", TUNNELS.cloudflared.urlRegex.test("https://happy-cat-42.trycloudflare.com"));
  // ngrok: the (?:-free)? infix and the (?:app|dev|io) TLD alternation must all be accepted.
  assert("ngrok regex matches ngrok-free.app", TUNNELS.ngrok.urlRegex.test("https://abcd-12-34.ngrok-free.app"));
  assert("ngrok regex matches ngrok.app", TUNNELS.ngrok.urlRegex.test("https://abcd.ngrok.app"));
  assert("ngrok regex matches ngrok.dev", TUNNELS.ngrok.urlRegex.test("https://abcd.ngrok.dev"));
  assert("ngrok regex matches ngrok.io", TUNNELS.ngrok.urlRegex.test("https://abcd.ngrok.io"));
  assert("tailscale regex matches a multi-label *.ts.net URL", TUNNELS.tailscale.urlRegex.test("https://my-host.tailnet-foo.ts.net"));
}

// --- 5. urlRegex EXTRACTS exactly the URL from noisy tunnel output (what spawnTunnel's scan does) --
{
  // spawnTunnel does `buf.match(spec.urlRegex)` and takes m[0]; replicate against realistic logs.
  const cf = "2024-06-25 INF |  Your quick Tunnel: https://happy-cat-42.trycloudflare.com  | take some time |".match(TUNNELS.cloudflared.urlRegex);
  assert("cloudflared regex extracts the bare URL from a noisy log line", cf && cf[0] === "https://happy-cat-42.trycloudflare.com", cf && cf[0]);

  const ng = '{"lvl":"info","msg":"started tunnel","addr":"http://localhost:8131","url":"https://abcd-12-34.ngrok-free.app"}'.match(TUNNELS.ngrok.urlRegex);
  // Must skip the http://localhost addr field and grab the https url field, without the closing quote.
  assert("ngrok regex extracts the https url field from a JSON log line (skips the http addr)", ng && ng[0] === "https://abcd-12-34.ngrok-free.app", ng && ng[0]);

  const ts = "Available on the internet:\n\nhttps://my-host.tailnet-foo.ts.net/\n|-- proxy http://127.0.0.1:8131\n".match(TUNNELS.tailscale.urlRegex);
  // The regex stops at .ts.net, so the trailing slash tailscale prints is NOT captured.
  assert("tailscale regex extracts the *.ts.net URL without the trailing slash", ts && ts[0] === "https://my-host.tailnet-foo.ts.net", ts && ts[0]);
}

// --- 6. urlRegex REJECTS the other providers' URLs and lookalikes (no cross-provider false match) --
{
  const CF = "https://happy-cat-42.trycloudflare.com";
  const NG = "https://abcd-12-34.ngrok-free.app";
  const TS = "https://my-host.tailnet-foo.ts.net";
  const EVIL = "https://evil.com";

  // cloudflared regex must reject ngrok, tailscale, evil, a wrong TLD, and a non-https scheme.
  for (const [label, url] of [["ngrok URL", NG], ["tailscale URL", TS], ["evil.com", EVIL], ["wrong TLD .org", "https://abc.trycloudflare.org"]]) {
    assert(`cloudflared regex rejects ${label}`, !TUNNELS.cloudflared.urlRegex.test(url));
  }
  // ngrok regex must reject cloudflared, tailscale, evil, and a wrong TLD (.com is not app|dev|io).
  for (const [label, url] of [["cloudflared URL", CF], ["tailscale URL", TS], ["evil.com", EVIL], ["wrong TLD ngrok.com", "https://abc.ngrok.com"]]) {
    assert(`ngrok regex rejects ${label}`, !TUNNELS.ngrok.urlRegex.test(url));
  }
  // tailscale regex must reject cloudflared, ngrok, evil, and a wrong TLD (.ts.com is not .ts.net).
  for (const [label, url] of [["cloudflared URL", CF], ["ngrok URL", NG], ["evil.com", EVIL], ["wrong TLD .ts.com", "https://abc.ts.com"]]) {
    assert(`tailscale regex rejects ${label}`, !TUNNELS.tailscale.urlRegex.test(url));
  }
}

// =================================================================================================
// HALF B — static wiring scan of the compiled dist/expose.js (the security invariants)
// =================================================================================================
{
  const src = readFileSync(new URL("../dist/expose.js", import.meta.url), "utf8");
  assert("dist/expose.js was read", src.length > 0, `${src.length} bytes`);
  const has = (s) => src.includes(s);
  const count = (s) => src.split(s).length - 1;

  // The dist is the compiled CURRENT source (anchors the rest of the scan to a real build).
  assert("dist exports TUNNEL_KINDS verbatim", has('export const TUNNEL_KINDS = ["cloudflared", "ngrok", "tailscale"];'));

  // Auth is FORCED on — this listener is public by definition, so loopback can never imply trust.
  assert("listener forces auth: requireAuth: () => true", has("requireAuth: () => true"));
  // JSON responses for tunnels that don't carry SSE (cloudflared quick tunnels).
  assert("listener sets enableJsonResponse: true", has("enableJsonResponse: true"));

  // Serves ONLY /mcp: exactly one mountMcpEndpoint call, and ZERO express verb route registrations.
  assert("listener mounts /mcp exactly once", count("mountMcpEndpoint(") === 1, `count=${count("mountMcpEndpoint(")}`);
  assert("listener URL path is /mcp", has(":${port}/mcp"));
  for (const verb of ["get", "post", "put", "delete"]) {
    assert(`NO app.${verb}( route is registered (the dashboard/console & /api routes are never tunnelled)`, !has(`app.${verb}(`));
  }
  // Catch-all 404 so nothing but /mcp is ever answered.
  assert("catch-all returns 404", has("res.status(404)"));
  assert('404 body says "only /mcp is exposed"', has("only /mcp is exposed"));

  // Binds loopback only.
  assert('runExpose binds host "127.0.0.1"', has('const host = "127.0.0.1"'));

  // Tunnel binary is spawned SHELL-LESSLY (no shell-injection surface) with the spec's argv.
  assert("tunnel spawned shell-lessly via spawn(spec.bin, spec.args(...))", has("spawn(spec.bin, spec.args("));
  assert("spawn never enables a shell (no `shell: true`)", !has("shell: true"));

  // 45s timeout guard with a clear message.
  assert("spawnTunnel uses a 45_000ms timeout", has("45_000"));
  assert('timeout message says "timed out after 45s"', has("timed out after 45s"));

  // Missing-binary path gives an install hint; busy-port path tells the user to pass --port.
  assert("ENOENT (missing binary) is handled", has('e.code === "ENOENT"'));
  assert("ENOENT message includes an install hint (not found — ...)", has("not found —"));
  assert("EADDRINUSE (busy port) is handled", has('e.code === "EADDRINUSE"'));
  assert('busy-port message says "is busy — pass --port"', has("is busy — pass --port"));

  // FAIL CLOSED: if the tunnel fails to come up, the listener is closed and the error rethrown —
  // never leave a naked auth-forced /mcp port open with no tunnel in front of it.
  const cIdx = src.indexOf("catch (err) {");
  assert("runExpose has a tunnel-spawn catch block", cIdx !== -1);
  const cBody = cIdx === -1 ? "" : src.slice(cIdx, cIdx + 160);
  assert("fail-closed: catch closes the listener", cBody.includes("listener.close()"), cBody.trim());
  assert("fail-closed: catch rethrows the error (does not swallow it)", cBody.includes("throw err"));

  // The public MCP URL is derived by stripping a trailing slash then appending /mcp.
  assert("publicMcp strips a trailing slash before appending /mcp", has('.replace(/\\/$/, "")'));

  // Graceful shutdown tears EVERYTHING down: kill the tunnel child, close the listener, stop the gateway.
  const sIdx = src.indexOf("const shutdown = async");
  assert("runExpose defines a shutdown handler", sIdx !== -1);
  const sBody = sIdx === -1 ? "" : src.slice(sIdx, sIdx + 400);
  assert("shutdown kills the tunnel child process", sBody.includes("tunnel.child.kill()"));
  assert("shutdown closes the /mcp listener", sBody.includes("listener.close()"));
  assert("shutdown stops the gateway", sBody.includes("gateway.shutdown()"));

  // Operator-facing intent: the log line documents that the dashboard/console stay local & un-tunnelled.
  assert("log states the dashboard/console stay local and un-tunnelled", has("dashboard/console stay local"));
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
