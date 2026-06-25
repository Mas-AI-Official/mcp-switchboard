/**
 * verify-local-llm.mjs — deterministic oracle for `switchboard local-llm`.
 *
 * Proves the PURE pieces of src/localllm.ts without a network or a running model:
 *   • parseOpenAiModels / parseOllamaTags — tolerant extraction from real + junk bodies
 *   • pickDefaultModel — preference order + case-insensitivity + fallbacks
 *   • buildLocalProvider — exact council provider shape (keyless)
 *   • withLocalProvider — idempotent merge, council creation, opt-out respect, no mutation
 *   • installGuide — per-OS copy-paste steps (printed, never executed)
 *   • a real config round-trip proving the wired block survives the zod schema (loadConfig)
 *
 * Run: node scripts/verify-local-llm.mjs   (exit 0 = all green, 1 = a check failed)
 */

import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  KNOWN_RUNTIMES,
  parseOpenAiModels,
  parseOllamaTags,
  pickDefaultModel,
  buildLocalProvider,
  withLocalProvider,
  installGuide,
} from "../dist/localllm.js";
import { starterConfig, writeConfig, loadConfig } from "../dist/config.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "ok  " : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// minimal SwitchboardConfig-shaped object; withLocalProvider only ever touches settings.council
const baseCfg = (settings) => ({ gateway: {}, vault: {}, servers: [], ...(settings ? { settings } : {}) });

const root = mkdtempSync(join(tmpdir(), "sb-localllm-"));
try {
  // ---- KNOWN_RUNTIMES ----------------------------------------------------
  assert("4 known runtimes", KNOWN_RUNTIMES.length === 4, KNOWN_RUNTIMES.map((r) => r.id).join(","));
  for (const id of ["ollama", "lmstudio", "llamacpp", "vllm"]) {
    assert(`runtime '${id}' present`, KNOWN_RUNTIMES.some((r) => r.id === id));
  }
  for (const r of KNOWN_RUNTIMES) {
    assert(`${r.id} baseUrl ends /v1`, r.baseUrl.endsWith("/v1"), r.baseUrl);
    assert(`${r.id} modelsUrl = baseUrl + /models`, r.modelsUrl === `${r.baseUrl}/models`, r.modelsUrl);
    assert(`${r.id} binds loopback`, r.baseUrl.includes("127.0.0.1"), r.baseUrl);
  }
  assert("ollama on :11434", KNOWN_RUNTIMES.find((r) => r.id === "ollama")?.baseUrl === "http://127.0.0.1:11434/v1");
  assert("lmstudio on :1234", KNOWN_RUNTIMES.find((r) => r.id === "lmstudio")?.baseUrl === "http://127.0.0.1:1234/v1");

  // ---- parseOpenAiModels -------------------------------------------------
  assert("openai: extracts ids", eq(parseOpenAiModels({ data: [{ id: "a" }, { id: "b" }] }), ["a", "b"]));
  assert("openai: empty object → []", eq(parseOpenAiModels({}), []));
  assert("openai: null → []", eq(parseOpenAiModels(null), []));
  assert("openai: string → []", eq(parseOpenAiModels("nope"), []));
  assert("openai: data not array → []", eq(parseOpenAiModels({ data: { id: "x" } }), []));
  assert(
    "openai: filters non-string / empty ids",
    eq(parseOpenAiModels({ data: [{ id: "a" }, { id: 5 }, {}, { id: "" }, null] }), ["a"]),
  );
  // shape Ollama actually serves at /v1/models (OpenAI-compatible)
  assert(
    "openai: ollama /v1 shape",
    eq(parseOpenAiModels({ object: "list", data: [{ id: "llama3.1:8b", object: "model" }] }), ["llama3.1:8b"]),
  );

  // ---- parseOllamaTags ---------------------------------------------------
  assert("ollama: extracts names", eq(parseOllamaTags({ models: [{ name: "x" }, { name: "y" }] }), ["x", "y"]));
  assert("ollama: empty → []", eq(parseOllamaTags({}), []));
  assert("ollama: null → []", eq(parseOllamaTags(null), []));
  assert("ollama: filters junk", eq(parseOllamaTags({ models: [{ name: "x" }, {}, { name: 3 }] }), ["x"]));

  // ---- pickDefaultModel --------------------------------------------------
  assert("pick: prefers llama3.1 over earlier mistral", pickDefaultModel(["mistral", "llama3.1:8b", "qwen2.5"]) === "llama3.1:8b");
  assert("pick: falls to qwen2.5 when no llama", pickDefaultModel(["mistral", "qwen2.5:7b"]) === "qwen2.5:7b");
  assert("pick: case-insensitive", pickDefaultModel(["CodeLlama", "Llama3.1-Instruct"]) === "Llama3.1-Instruct");
  assert("pick: first when no preferred", pickDefaultModel(["foo-1", "bar-2"]) === "foo-1");
  assert("pick: empty → undefined", pickDefaultModel([]) === undefined);

  // ---- buildLocalProvider ------------------------------------------------
  const prov = buildLocalProvider("http://127.0.0.1:11434/v1", "llama3.1");
  assert("provider: base_url", prov.base_url === "http://127.0.0.1:11434/v1");
  assert("provider: default_model", prov.default_model === "llama3.1");
  assert("provider: keyless (no api_key_ref)", !("api_key_ref" in prov));

  // ---- withLocalProvider: create council from nothing --------------------
  {
    const cfg = baseCfg(undefined);
    const before = JSON.stringify(cfg);
    const r = withLocalProvider(cfg, prov);
    assert("wire(empty): changed", r.changed === true);
    assert("wire(empty): enabled true", r.enabled === true);
    assert("wire(empty): no note", r.note === undefined);
    assert("wire(empty): local set", eq(r.config.settings.council.providers.local, prov));
    assert("wire(empty): council enabled in config", r.config.settings.council.enabled === true);
    assert("wire(empty): input NOT mutated", JSON.stringify(cfg) === before);
  }

  // ---- withLocalProvider: idempotent -------------------------------------
  {
    const r1 = withLocalProvider(baseCfg(undefined), prov);
    const r2 = withLocalProvider(r1.config, prov);
    assert("wire(idempotent): second pass no change", r2.changed === false);
    assert("wire(idempotent): provider stable", eq(r2.config.settings.council.providers.local, prov));
  }

  // ---- withLocalProvider: respects explicit enabled:false ----------------
  {
    const cfg = baseCfg({ council: { enabled: false } });
    const r = withLocalProvider(cfg, prov);
    assert("wire(opt-out): stays disabled", r.enabled === false);
    assert("wire(opt-out): emits note", typeof r.note === "string" && r.note.includes("enabled"));
    assert("wire(opt-out): local still set", eq(r.config.settings.council.providers.local, prov));
    assert("wire(opt-out): enabled untouched", r.config.settings.council.enabled === false);
  }

  // ---- withLocalProvider: preserves sibling providers & settings ---------
  {
    const cfg = baseCfg({
      redact_response: { enabled: true },
      council: { enabled: true, providers: { anthropic: { api_key_ref: "${vault:anthropic}", default_model: "claude" } } },
    });
    const r = withLocalProvider(cfg, prov);
    assert("wire(merge): keeps anthropic", eq(r.config.settings.council.providers.anthropic, { api_key_ref: "${vault:anthropic}", default_model: "claude" }));
    assert("wire(merge): adds local", eq(r.config.settings.council.providers.local, prov));
    assert("wire(merge): keeps unrelated setting", eq(r.config.settings.redact_response, { enabled: true }));
  }

  // ---- installGuide ------------------------------------------------------
  for (const plat of ["win32", "darwin", "linux"]) {
    const steps = installGuide(plat);
    assert(`guide(${plat}): ≥4 steps`, steps.length >= 4, `${steps.length} steps`);
    assert(`guide(${plat}): all strings`, steps.every((s) => typeof s === "string"));
    assert(`guide(${plat}): mentions \`ollama pull\``, steps.some((s) => s.includes("ollama pull")));
    assert(`guide(${plat}): names the /v1 endpoint`, steps.some((s) => s.includes("127.0.0.1:11434/v1")));
  }
  assert("guide(win32): windows installer", installGuide("win32")[0].includes("download/windows"));
  assert("guide(darwin): brew", installGuide("darwin")[0].includes("brew install ollama"));
  assert("guide(linux): install.sh", installGuide("linux")[0].includes("install.sh"));

  // ---- real config round-trip: wired block survives the zod schema -------
  {
    const wired = withLocalProvider(starterConfig(), prov);
    const p = join(root, "switchboard.config.yaml");
    writeConfig(p, wired.config);
    const reloaded = loadConfig(p); // throws if the merged config is schema-invalid
    assert("roundtrip: local provider survives load", eq(reloaded.settings.council.providers.local, prov));
    assert("roundtrip: council enabled survives load", reloaded.settings.council.enabled === true);
    assert("roundtrip: starter server preserved", reloaded.servers.length === 1 && reloaded.servers[0].id === "everything");
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) console.log("FAILED:", failed.map((c) => c.name).join(", "));
process.exitCode = failed.length === 0 ? 0 : 1;
