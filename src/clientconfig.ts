/**
 * clientconfig.ts: the `clients` section of the config file, live (design 3.1).
 *
 * Two jobs, both about a file that several processes share:
 *
 *  - {@link ClientConfigWatcher} keeps a running gateway's `cfg.clients` current. The YAML is otherwise read once
 *    at startup; this watches the file's identity (mtime, size, inode) and, when it changed, re-parses the WHOLE
 *    file through the strict schema and swaps in only its `clients` section with a single assignment. A file that
 *    does not parse or validate is ignored (the previous clients stay in force and a warning says why), so a bad
 *    edit can never open the gateway up or lock every client out. Nothing else in the config is touched: servers,
 *    settings and the gateway block keep the values they started with and still need a restart.
 *
 *  - {@link editConfigFile} changes the file for `switchboard client ...` and the admin API. It edits the YAML
 *    document in place so comments and key order survive, validates the result (re-parsed from the text it is
 *    about to write) before touching disk, and writes atomically under the cross-process lock with a `.bak`.
 */

import { existsSync, readFileSync } from "node:fs";
import { parse, parseDocument, isMap, type Document } from "yaml";
import { atomicWriteFileSync, fileStamp, withFileLock } from "./atomicfile.js";
import { loadConfig, validateConfig } from "./config.js";
import { log } from "./logger.js";
import type { ClientConfig, SwitchboardConfig } from "./types.js";

type Clients = Record<string, ClientConfig>;

const canon = (c: Clients | undefined): string => JSON.stringify(c ? Object.keys(c).sort().map((k) => [k, c[k]]) : []);

export class ClientConfigWatcher {
  /** undefined = never looked, so the first sync() reads the file even if it never changes afterwards. */
  private stamp: string | null | undefined = undefined;

  /** `path` undefined = nothing to watch (an in-memory configuration). */
  constructor(
    private readonly cfg: SwitchboardConfig,
    readonly path: string | undefined,
  ) {}

  /**
   * Bring `cfg.clients` up to date with the file. Cheap when nothing changed (one stat), so it is called on
   * every /mcp request and before every admin write. Returns true when the clients map was replaced.
   */
  sync(): boolean {
    if (!this.path) return false;
    const stamp = fileStamp(this.path);
    if (stamp === this.stamp) return false;
    this.stamp = stamp;
    if (stamp === null) {
      log.warn(`config file ${this.path} is missing: keeping the clients already loaded`);
      return false;
    }
    let next: Clients | undefined;
    try {
      next = loadConfig(this.path).clients;
    } catch (err) {
      log.warn(`ignoring the change to ${this.path}, keeping the clients already loaded: ${err instanceof Error ? err.message.split("\n").slice(0, 3).join(" ") : String(err)}`);
      return false;
    }
    if (canon(next) === canon(this.cfg.clients)) return false;
    const before = new Set(Object.keys(this.cfg.clients ?? {}));
    // One assignment: a request in flight sees the old map or the new one, never a mix.
    if (next && Object.keys(next).length > 0) this.cfg.clients = next;
    else delete this.cfg.clients;
    const after = new Set(Object.keys(next ?? {}));
    const added = [...after].filter((k) => !before.has(k));
    const removed = [...before].filter((k) => !after.has(k));
    log.info(
      `reloaded clients from ${this.path}: ${after.size} configured` +
        (added.length ? `, added ${added.join(", ")}` : "") +
        (removed.length ? `, removed ${removed.join(", ")}` : ""),
    );
    return true;
  }
}

/** Keep a `.bak` only when the file being replaced still parses as YAML (the same rule as writeConfig). */
const backupIfParses = (current: Buffer): boolean => {
  try {
    parse(current.toString("utf8"));
    return true;
  } catch {
    return false;
  }
};

/**
 * Edit the config file under the cross-process lock. `edit` changes the parsed YAML document in place (comments
 * and order are kept); the result must still be a valid config or nothing is written and the error is thrown.
 * Line endings of the original file are kept. Returns true when the file changed.
 */
export function editConfigFile(path: string, edit: (doc: Document) => void): boolean {
  return withFileLock(path, () => {
    if (!existsSync(path)) throw new Error(`config not found: ${path}: run \`switchboard init\` to create one`);
    const text = readFileSync(path, "utf8");
    const doc = parseDocument(text);
    if (doc.errors.length > 0) throw new Error(`cannot edit ${path}: ${doc.errors[0]!.message}`);
    edit(doc);
    // lineWidth 0: never re-wrap a long value (a path, a URL, a quoted string) that the owner wrote on one line.
    let out = doc.toString({ lineWidth: 0 });
    // Validate what will actually be on disk, not the in-memory tree.
    validateConfig(parse(out) ?? {}, path);
    if (text.includes("\r\n")) out = out.replace(/\r?\n/g, "\r\n");
    if (out === text) return false;
    atomicWriteFileSync(path, out, { backup: backupIfParses });
    return true;
  });
}

/** Make sure `clients:` is a map in the document (a bare `clients:` key parses as null and would reject setIn). */
export function ensureClientsMap(doc: Document): void {
  const node = doc.get("clients", true);
  if (!isMap(node)) doc.set("clients", doc.createNode({}));
}

/**
 * Set a client entry to `entry`, key by key, so comments on untouched keys survive: keys that differ are set,
 * keys that are gone are deleted.
 */
export function writeClientEntry(doc: Document, id: string, entry: ClientConfig): void {
  ensureClientsMap(doc);
  const existing = doc.getIn(["clients", id]);
  if (!isMap(existing)) doc.setIn(["clients", id], doc.createNode({}));
  const current = (doc.getIn(["clients", id]) as { toJSON(): Record<string, unknown> }).toJSON();
  const want = entry as unknown as Record<string, unknown>;
  for (const key of Object.keys(current)) {
    if (want[key] === undefined) doc.deleteIn(["clients", id, key]);
  }
  for (const [key, value] of Object.entries(want)) {
    if (value === undefined) continue;
    if (JSON.stringify(current[key]) !== JSON.stringify(value)) doc.setIn(["clients", id, key], doc.createNode(value));
  }
}

/** Remove a client entry; the whole `clients` key goes when it was the last one. */
export function deleteClientEntry(doc: Document, id: string): void {
  doc.deleteIn(["clients", id]);
  const node = doc.get("clients", true);
  if (isMap(node) && node.items.length === 0) doc.delete("clients");
}
