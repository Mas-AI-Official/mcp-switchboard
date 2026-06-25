/**
 * verify-profiles.mjs — deterministic oracle for `switchboard profile` (Feature: Profiles).
 *
 * A profile is a named, switchable VIEW over the configured servers/tools: it can only ever HIDE
 * servers/tools and LOWER scope, never reveal a disabled tool or raise a server's policy. This
 * oracle proves the PURE resolver logic (src/profiles.ts) with no network and no boot, plus the
 * policy-engine integration (a profile ceiling genuinely lowers the effective scope cap), plus a
 * real config round-trip proving profiles + active_profile + the refine guard survive the zod schema.
 *
 *   • profileAllowsServer  — allowlist semantics (empty/absent ⇒ allow all)
 *   • profileAllowsTool    — allowlist + denylist, denylist beats allowlist
 *   • profileScopeCeiling  — surfaces profile.policy
 *   • applyProfileEnvOverride — env precedence: unset / empty / "none" / unknown / defined / already-active
 *   • withActiveProfile    — set, clear, throws on unknown, never mutates input
 *   • activeProfileName / getActiveProfile / describeProfile
 *   • evaluate(..., profileCeiling) — the cap actually lowers the ceiling AND is attributed to the profile
 *   • round-trip: a config with profiles + active_profile survives writeConfig→loadConfig
 *   • refine guard: active_profile naming an undefined profile is REJECTED by loadConfig
 *
 * Run: node scripts/verify-profiles.mjs   (exit 0 = all green, 1 = a check failed)
 */

import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  activeProfileName,
  getActiveProfile,
  profileAllowsServer,
  profileAllowsTool,
  profileScopeCeiling,
  applyProfileEnvOverride,
  describeProfile,
  withActiveProfile,
} from "../dist/profiles.js";
import { evaluate } from "../dist/policy.js";
import { starterConfig, writeConfig, loadConfig } from "../dist/config.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "ok  " : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const throws = (fn) => {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
};

// A config carrying one profile of each shape, plus an active selection.
const cfgWith = (settings) => ({ gateway: { default_policy: "full" }, vault: {}, servers: [], settings });
const PROFILES = {
  coding: { description: "dev tools only", servers: ["git", "fs"], exclude_tools: ["git__push"] },
  readonly: { description: "everything, read-only", policy: "read" },
  support: { servers: ["zendesk"], tools: ["zendesk__list_tickets", "zendesk__get_ticket"] },
};

const root = mkdtempSync(join(tmpdir(), "sb-profiles-"));
try {
  // ---- profileAllowsServer -----------------------------------------------
  assert("server: no profile ⇒ allow", profileAllowsServer(undefined, "anything") === true);
  assert("server: empty servers list ⇒ allow", profileAllowsServer({}, "git") === true);
  assert("server: on allowlist ⇒ allow", profileAllowsServer(PROFILES.coding, "git") === true);
  assert("server: off allowlist ⇒ hide", profileAllowsServer(PROFILES.coding, "email") === false);
  assert("server: empty array ⇒ allow all (no allowlist)", profileAllowsServer({ servers: [] }, "x") === true);

  // ---- profileAllowsTool: allowlist + denylist ---------------------------
  assert("tool: no profile ⇒ allow", profileAllowsTool(undefined, "git__push") === true);
  assert("tool: not on denylist, no allowlist ⇒ allow", profileAllowsTool(PROFILES.coding, "git__status") === true);
  assert("tool: on exclude_tools ⇒ hide", profileAllowsTool(PROFILES.coding, "git__push") === false);
  assert("tool: on allowlist ⇒ allow", profileAllowsTool(PROFILES.support, "zendesk__get_ticket") === true);
  assert("tool: not on allowlist ⇒ hide", profileAllowsTool(PROFILES.support, "zendesk__delete_ticket") === false);
  // denylist beats allowlist
  {
    const p = { tools: ["s__a", "s__b"], exclude_tools: ["s__b"] };
    assert("tool: denylist beats allowlist", profileAllowsTool(p, "s__b") === false);
    assert("tool: allowlist still admits the rest", profileAllowsTool(p, "s__a") === true);
  }

  // ---- profileScopeCeiling -----------------------------------------------
  assert("ceiling: read profile ⇒ read", profileScopeCeiling(PROFILES.readonly) === "read");
  assert("ceiling: no policy ⇒ undefined", profileScopeCeiling(PROFILES.coding) === undefined);
  assert("ceiling: undefined profile ⇒ undefined", profileScopeCeiling(undefined) === undefined);

  // ---- activeProfileName / getActiveProfile ------------------------------
  {
    const cfg = cfgWith({ profiles: PROFILES, active_profile: "coding" });
    assert("active: name resolved", activeProfileName(cfg) === "coding");
    assert("active: getActiveProfile returns block", eq(getActiveProfile(cfg)?.profile, PROFILES.coding));
    assert("active: getActiveProfile name", getActiveProfile(cfg)?.name === "coding");
    const none = cfgWith({ profiles: PROFILES });
    assert("active: none ⇒ undefined name", activeProfileName(none) === undefined);
    assert("active: none ⇒ undefined block", getActiveProfile(none) === undefined);
    // active_profile naming a non-existent profile resolves to undefined (defensive, not a throw)
    const ghost = cfgWith({ profiles: PROFILES, active_profile: "ghost" });
    assert("active: unknown name ⇒ undefined block", getActiveProfile(ghost) === undefined);
  }

  // ---- applyProfileEnvOverride: env precedence ---------------------------
  {
    const base = cfgWith({ profiles: PROFILES, active_profile: "coding" });

    // unset ⇒ file value stands, no mutation
    {
      const r = applyProfileEnvOverride(base, {});
      assert("env(unset): keeps file active", r.active === "coding");
      assert("env(unset): same object (no clone)", r.config === base);
      assert("env(unset): no note", r.note === undefined);
    }
    // explicit "none" ⇒ disables for this run, input untouched
    {
      const before = JSON.stringify(base);
      const r = applyProfileEnvOverride(base, { SWITCHBOARD_PROFILE: "none" });
      assert("env(none): clears active", r.active === undefined);
      assert("env(none): config has no active_profile", r.config.settings.active_profile === undefined);
      assert("env(none): note explains", typeof r.note === "string" && r.note.includes("cleared"));
      assert("env(none): input NOT mutated", JSON.stringify(base) === before);
    }
    // empty string ⇒ same as none
    {
      const r = applyProfileEnvOverride(base, { SWITCHBOARD_PROFILE: "" });
      assert("env(empty): clears active", r.active === undefined);
    }
    // unknown name ⇒ ignored, file value stands, advisory note
    {
      const r = applyProfileEnvOverride(base, { SWITCHBOARD_PROFILE: "nope" });
      assert("env(unknown): keeps file active", r.active === "coding");
      assert("env(unknown): same object (ignored)", r.config === base);
      assert("env(unknown): note names the bad value", typeof r.note === "string" && r.note.includes("nope"));
    }
    // a different defined name ⇒ activates it (new object), input untouched
    {
      const before = JSON.stringify(base);
      const r = applyProfileEnvOverride(base, { SWITCHBOARD_PROFILE: "readonly" });
      assert("env(switch): activates readonly", r.active === "readonly");
      assert("env(switch): config reflects it", r.config.settings.active_profile === "readonly");
      assert("env(switch): new object (cloned)", r.config !== base);
      assert("env(switch): input NOT mutated", JSON.stringify(base) === before);
    }
    // env names the already-active profile ⇒ no-op, same object
    {
      const r = applyProfileEnvOverride(base, { SWITCHBOARD_PROFILE: "coding" });
      assert("env(same): no-op same object", r.config === base && r.active === "coding");
    }
    // env activates a profile when the file had NONE active
    {
      const noActive = cfgWith({ profiles: PROFILES });
      const r = applyProfileEnvOverride(noActive, { SWITCHBOARD_PROFILE: "support" });
      assert("env(from-none): activates", r.active === "support" && r.config.settings.active_profile === "support");
    }
    // "none" when nothing was active ⇒ no note, same object
    {
      const noActive = cfgWith({ profiles: PROFILES });
      const r = applyProfileEnvOverride(noActive, { SWITCHBOARD_PROFILE: "none" });
      assert("env(none, none-active): no-op no note", r.active === undefined && r.note === undefined);
    }
  }

  // ---- withActiveProfile -------------------------------------------------
  {
    const base = cfgWith({ profiles: PROFILES });
    const before = JSON.stringify(base);
    const set = withActiveProfile(base, "readonly");
    assert("with: sets active", set.settings.active_profile === "readonly");
    assert("with: input NOT mutated", JSON.stringify(base) === before);
    const cleared = withActiveProfile(set, undefined);
    assert("with: clears active", cleared.settings.active_profile === undefined);
    assert("with: throws on unknown name", throws(() => withActiveProfile(base, "ghost")));
  }

  // ---- describeProfile: one-line summary ---------------------------------
  {
    const d = describeProfile("coding", PROFILES.coding);
    assert("describe: includes name", d.startsWith("coding —"));
    assert("describe: includes description", d.includes("dev tools only"));
    assert("describe: lists servers", d.includes("git, fs"));
    assert("describe: counts hidden tools", d.includes("hides: 1"));
    const r = describeProfile("readonly", PROFILES.readonly);
    assert("describe: shows scope cap", r.includes("scope ≤ read"));
    const empty = describeProfile("noop", {});
    assert("describe: no restrictions when empty", empty.includes("no restrictions"));
  }

  // ---- policy integration: the ceiling genuinely lowers the effective cap -
  {
    // server allows `full`; a `read` profile must force read-only and attribute the cap to the profile.
    const server = { id: "git", source: "npx", policy: "full" };
    const cfg = { gateway: { default_policy: "full" }, vault: {}, servers: [server] };
    const allowed = evaluate(server, "get_status", cfg, undefined, "read");
    assert("policy: read tool under read ceiling ⇒ allow", allowed.decision === "allow" && allowed.scope === "read");
    const denied = evaluate(server, "delete_branch", cfg, undefined, "read");
    assert("policy: full tool under read ceiling ⇒ deny", denied.decision === "deny");
    assert("policy: deny attributed to active profile", denied.reason.includes("active profile"), denied.reason);
    // without the profile ceiling the SAME call is allowed by the full server — proves the profile is what capped it
    const noProfile = evaluate(server, "delete_branch", cfg, undefined, undefined);
    assert("policy: same call allowed without the profile ceiling", noProfile.decision === "allow");
    // a profile can only LOWER: a `full` profile over a `read` server stays capped at the server's read
    const readServer = { id: "ro", source: "npx", policy: "read" };
    const cfg2 = { gateway: { default_policy: "read" }, vault: {}, servers: [readServer] };
    const stillCapped = evaluate(readServer, "delete_thing", cfg2, undefined, "full");
    assert("policy: profile cannot RAISE above server cap", stillCapped.decision === "deny" && stillCapped.reason.includes("ro"));
  }

  // ---- real config round-trip: profiles + active_profile survive the schema
  {
    const cfg = starterConfig();
    cfg.settings = {
      profiles: {
        coding: { description: "dev only", servers: ["everything"], exclude_tools: ["everything__longRunningOperation"] },
        readonly: { description: "read cap", policy: "read" },
      },
      active_profile: "readonly",
    };
    const p = join(root, "switchboard.config.yaml");
    writeConfig(p, cfg);
    const reloaded = loadConfig(p); // throws if profiles/active_profile are schema-invalid
    assert("roundtrip: profiles survive load", Object.keys(reloaded.settings.profiles).length === 2);
    assert("roundtrip: active_profile survives", reloaded.settings.active_profile === "readonly");
    assert("roundtrip: scope cap preserved", reloaded.settings.profiles.readonly.policy === "read");
    assert("roundtrip: exclude_tools preserved", eq(reloaded.settings.profiles.coding.exclude_tools, ["everything__longRunningOperation"]));
    assert("roundtrip: starter server preserved", reloaded.servers.length === 1 && reloaded.servers[0].id === "everything");
  }

  // ---- refine guard: active_profile must name a defined profile ----------
  {
    const cfg = starterConfig();
    cfg.settings = { profiles: { a: { policy: "read" } }, active_profile: "ghost" };
    const p = join(root, "bad.config.yaml");
    writeConfig(p, cfg);
    assert("refine: undefined active_profile is REJECTED", throws(() => loadConfig(p)));
  }
  {
    // active_profile with NO profiles block at all is also rejected
    const cfg = starterConfig();
    cfg.settings = { active_profile: "x" };
    const p = join(root, "bad2.config.yaml");
    writeConfig(p, cfg);
    assert("refine: active_profile without profiles is REJECTED", throws(() => loadConfig(p)));
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) console.log("FAILED:", failed.map((c) => c.name).join(", "));
process.exitCode = failed.length === 0 ? 0 : 1;
