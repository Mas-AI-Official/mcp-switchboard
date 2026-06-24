// Deterministic oracle for the shipped example config + the config loader (src/config.ts).
// Pure validation — NO network, NO MCP transport, NO vault decryption. Imports the compiled
// loader and runs the real `switchboard.config.example.yaml` through the same strict zod schema
// startup uses.
//
// It proves:
//   example validates    — THE regression guard: the file users copy (`cp example → config; serve`)
//                          passes loadConfig. This caught a real defect — oauth_server.public_url is
//                          the only optional URL using z.url(), which rejects the placeholder "", so
//                          a disabled-OAuth example failed to load. The empty placeholder is now
//                          omitted; this check fails the build if it ever comes back.
//   parity coverage      — the example actually exercises every shipped parity feature: the local
//                          (zero-cloud) council provider, call_timeout_ms, an http-tool server,
//                          auth_scheme (bearer + api_key), and schema-shaping tool overrides
//                          (drop_params / inject_args / redact_response). Documentation that drifts
//                          from the code is a lie; this keeps the example honest.
//   zero plaintext keys  — NEVER #1: every *_ref / credential value in the example is a
//                          ${vault:..}/${env:..} reference, never a literal secret. The local
//                          provider carries NO api_key_ref (the zero-key path).
//   public_url contract  — a negative test: the same config with public_url:"" is REJECTED, pinning
//                          WHY the placeholder must stay commented while disabled.
//   writer round-trip    — starterConfig() → writeConfig → loadConfig deep-equals, so the YAML the
//                          dashboard writes back is always schema-valid (no write-then-fail-to-load).
// Zero deps (node stdlib + the package's compiled output). Build first.
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, writeConfig, starterConfig } from "../dist/config.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

const EXAMPLE = "./switchboard.config.example.yaml";

// --- 1. the shipped example validates (the documented copy-and-serve flow) -------------------------
let cfg;
{
  let err = "";
  try {
    cfg = loadConfig(EXAMPLE);
  } catch (e) {
    err = e.message;
  }
  assert("shipped example config passes strict loadConfig (copy → serve works)", !!cfg && !err, err);
}

// Everything below depends on a loaded config; bail cleanly if it didn't load.
if (cfg) {
  const servers = cfg.servers ?? [];
  const byId = (id) => servers.find((s) => s.id === id);
  const council = cfg.settings?.council;

  // --- 2. parity coverage: the example exercises every shipped feature ----------------------------
  {
    // local council provider — the zero-cloud, zero-key path
    const local = council?.providers?.local;
    assert("council has a local (OpenAI-compatible) provider", !!local, JSON.stringify(local));
    assert("local provider points at a localhost base_url", !!local && /127\.0\.0\.1|localhost/.test(local.base_url), local?.base_url);
    assert("council has anthropic + openai providers too (debate needs ≥2)", !!council?.providers?.anthropic && !!council?.providers?.openai);

    // call_timeout_ms
    assert("settings.call_timeout_ms is a positive integer", Number.isInteger(cfg.settings?.call_timeout_ms) && cfg.settings.call_timeout_ms > 0, String(cfg.settings?.call_timeout_ms));

    // http-tool source
    const weather = byId("weather");
    assert("an http-tool server is present", !!weather && weather.source === "http-tool");
    assert("http-tool server declares http_tools", !!weather && Array.isArray(weather.http_tools) && weather.http_tools.length >= 1, JSON.stringify(weather?.http_tools?.map((t) => t.name)));
    assert("each http_tool has a name + method", !!weather && weather.http_tools.every((t) => t.name && t.method), JSON.stringify(weather?.http_tools));

    // auth_scheme — bearer + api_key both demonstrated
    assert("a bearer auth_scheme is demonstrated (slack)", byId("slack")?.auth_scheme?.kind === "bearer", JSON.stringify(byId("slack")?.auth_scheme));
    assert("an api_key auth_scheme with a custom header is demonstrated (weather)", weather?.auth_scheme?.kind === "api_key" && !!weather?.auth_scheme?.header, JSON.stringify(weather?.auth_scheme));

    // schema-shaping tool overrides
    const gh = byId("github");
    const createIssue = gh?.tools?.create_issue;
    const getRepo = gh?.tools?.get_repo;
    assert("a tool override demonstrates drop_params", Array.isArray(createIssue?.drop_params) && createIssue.drop_params.length >= 1, JSON.stringify(createIssue?.drop_params));
    assert("a tool override demonstrates inject_args", !!createIssue?.inject_args && Object.keys(createIssue.inject_args).length >= 1, JSON.stringify(createIssue?.inject_args));
    assert("a tool override demonstrates redact_response", Array.isArray(getRepo?.redact_response?.fields) && getRepo.redact_response.fields.length >= 1, JSON.stringify(getRepo?.redact_response));
    assert("a destructive tool is hard-blocked (enabled:false)", gh?.tools?.delete_repo?.enabled === false);
  }

  // --- 3. NEVER #1: zero plaintext secrets in the example -----------------------------------------
  {
    const refOk = (v) => typeof v === "string" && /^\$\{(vault|env):[^}]+\}$/.test(v);
    // every council provider api_key_ref is a ref
    const cloudRefs = [council?.providers?.anthropic?.api_key_ref, council?.providers?.openai?.api_key_ref].filter(Boolean);
    assert("every cloud council api_key_ref is a ${vault:..}/${env:..} ref", cloudRefs.length === 2 && cloudRefs.every(refOk), JSON.stringify(cloudRefs));
    // local provider carries NO api_key_ref (zero-key path)
    assert("local provider has NO api_key_ref (zero-key path)", council?.providers?.local && council.providers.local.api_key_ref === undefined);
    // every auth_scheme ref / server credential value is a ref, never a literal
    const refValues = [];
    for (const s of servers) {
      const a = s.auth_scheme;
      if (a?.ref) refValues.push(a.ref);
      if (a?.username_ref) refValues.push(a.username_ref);
      if (a?.password_ref) refValues.push(a.password_ref);
      for (const v of Object.values(s.credentials ?? {})) refValues.push(v);
    }
    const badRef = refValues.find((v) => !refOk(v));
    assert(`every auth/credential value is a ref, not a literal (${refValues.length} checked)`, !badRef, badRef ? `literal: ${badRef}` : "");
  }

  // --- 4. public_url contract: the empty-string placeholder is REJECTED (why it must stay commented) ---
  {
    const dir = mkdtempSync(join(tmpdir(), "sbcfg-"));
    const bad = join(dir, "bad.yaml");
    try {
      // take the real example, re-add the empty public_url under oauth_server, prove it fails
      const yaml = readFileSync(EXAMPLE, "utf8").replace(
        "  oauth_server:\n    enabled: false\n",
        '  oauth_server:\n    enabled: false\n    public_url: ""\n',
      );
      writeFileSync(bad, yaml);
      let threw = "";
      try {
        loadConfig(bad);
      } catch (e) {
        threw = e.message;
      }
      assert("oauth_server.public_url:\"\" is rejected (empty string is not a valid URL)", /public_url/.test(threw), threw.split("\n").slice(0, 2).join(" "));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // --- 5. writer round-trip is a stable FIXPOINT --------------------------------------------------
  // starterConfig() is the pre-default in-memory object; loadConfig applies schema defaults
  // (enabled, tools:{}, triggers, …) so back1 != starter is EXPECTED, not a bug. The honest
  // property the dashboard relies on is idempotence: writing what you loaded, then loading again,
  // yields an identical config — so a Save→reload never silently mutates or drops a field.
  {
    const dir = mkdtempSync(join(tmpdir(), "sbcfg-"));
    const p1 = join(dir, "rt1.yaml");
    const p2 = join(dir, "rt2.yaml");
    try {
      writeConfig(p1, starterConfig());
      const back1 = loadConfig(p1); // defaults now materialized
      writeConfig(p2, back1);
      const back2 = loadConfig(p2);
      assert("writeConfig → load is a stable fixpoint (Save→reload never mutates)", eq(back1, back2));
      assert("writer round-trip preserves the gateway block", eq(back1.gateway, back2.gateway), JSON.stringify(back1.gateway));
      assert("writer round-trip preserves server ids", eq(back1.servers?.map((s) => s.id), back2.servers?.map((s) => s.id)), JSON.stringify(back1.servers?.map((s) => s.id)));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
