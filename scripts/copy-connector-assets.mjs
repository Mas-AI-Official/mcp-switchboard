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
console.log(`copy-connector-assets: ${copied} files -> dist/connectors/`);
