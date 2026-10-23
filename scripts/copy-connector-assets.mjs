#!/usr/bin/env node
// Copy the connector data files (provider definitions and the JSON Schema they are validated against)
// from src/connectors/ to dist/connectors/ so the compiled package finds them next to its code.
// tsc only emits TypeScript; these are plain JSON read at runtime. The destination folders are emptied
// first, so a provider file deleted from src cannot linger in dist as a stale definition.
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
let copied = 0;
for (const sub of ["providers", "schemas"]) {
  const src = join(root, "src", "connectors", sub);
  const dst = join(root, "dist", "connectors", sub);
  if (!existsSync(src)) {
    console.error(`copy-connector-assets: missing ${src}`);
    process.exit(1);
  }
  rmSync(dst, { recursive: true, force: true });
  mkdirSync(dst, { recursive: true });
  for (const name of readdirSync(src)) {
    if (!name.endsWith(".json")) continue;
    cpSync(join(src, name), join(dst, name));
    copied++;
  }
}
// Bundled toolkit overlays and recipes: src/connectors/toolkits/<slug>/{overlay.json,recipes/*.json}. Vendor
// specs are never here: `toolkits sync` writes them to SWITCHBOARD_HOME on the operator's machine.
const toolkitsSrc = join(root, "src", "connectors", "toolkits");
const toolkitsDst = join(root, "dist", "connectors", "toolkits");
rmSync(toolkitsDst, { recursive: true, force: true });
if (existsSync(toolkitsSrc)) {
  cpSync(toolkitsSrc, toolkitsDst, { recursive: true, filter: (p) => !p.endsWith(".md") });
  const count = (d) => readdirSync(d, { withFileTypes: true }).reduce((n, e) => n + (e.isDirectory() ? count(join(d, e.name)) : 1), 0);
  copied += count(toolkitsDst);
}
console.log(`copy-connector-assets: ${copied} files -> dist/connectors/`);
