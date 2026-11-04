// One-off measurement, NOT part of the verify chain (it needs the network): run the importers against the real
// public vendor documents named by the shipped overlays and report what they produce. Everything is written to a
// temporary SWITCHBOARD_HOME that is deleted afterwards; nothing is committed and no credential is used or needed.
//
//   node scripts/live-sync-check.mjs [toolkit ...]        default: youtube gmail drive
//
// Prints, per toolkit: the spec source, operations, actions, how many input schemas compile in Ajv, the longest
// `<toolkit>__<action>` name, the warnings, and the listed/unlisted split. Exit 1 if any toolkit fails the gate.
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOME = mkdtempSync(join(tmpdir(), "sb-live-sync-"));
process.env.SWITCHBOARD_HOME = HOME;
const mod = (p) => import(pathToFileURL(join(ROOT, "dist", p)).href);
const { Connectors } = await mod("connectors/index.js");
const { Vault } = await mod("vault.js");
const { syncToolkits } = await mod("connectors/sync.js");

const targets = process.argv.slice(2).length ? process.argv.slice(2) : ["youtube", "gmail", "drive"];
const kit = new Connectors({ vault: new Vault("encrypted-file") }).kit;
let failed = 0;
try {
  for (const t of targets) {
    const started = Date.now();
    const results = await syncToolkits(kit, t);
    for (const r of results) {
      const src = kit.toolkits.sourceOf(r.toolkit);
      const line = [`${r.toolkit}: ${r.status}`];
      if (r.status === "synced") {
        const tk = kit.toolkits.load(r.toolkit);
        const important = tk.actions.filter((a) => a.important).length;
        line.push(`version ${r.version}`, `${r.operations} operations`, `${r.actions} actions`, `compile ${r.compile.compiled}/${r.compile.total}`, `longest tool name ${r.max_tool_name}`, `listed ${Math.min(important, 28)} + 2 meta, unlisted ${tk.actions.length - Math.min(important, 28)}`);
        if (r.compile.compiled !== r.compile.total) failed += 1;
        const bytes = readFileSync(join(HOME, "toolkits", r.toolkit, r.version, "actions.json")).length;
        line.push(`${(bytes / 1024).toFixed(0)} KiB generated`, `overlay issues ${tk.overlay_issues.length}`);
        for (const i of tk.overlay_issues.slice(0, 8)) console.log(`  overlay: ${i}`);
      } else {
        failed += 1;
        if (r.message) line.push(r.message);
      }
      line.push(`${((Date.now() - started) / 1000).toFixed(1)} s`);
      console.log(line.join(" | "));
      console.log(`  source ${src?.kind} ${src?.url}`);
      for (const w of r.warnings.slice(0, 5)) console.log(`  warning: ${w}`);
      if (r.warnings.length > 5) console.log(`  ... ${r.warnings.length - 5} more warnings`);
    }
  }
} finally {
  rmSync(HOME, { recursive: true, force: true });
}
console.log(failed ? `\n${failed} toolkit(s) failed the gate` : "\nall toolkits passed the gate (nothing was written outside the temporary home)");
process.exit(failed ? 1 : 0);
