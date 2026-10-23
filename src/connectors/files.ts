/**
 * File handling (ADR local-composio, section 6.5): the Composio method without S3.
 *
 * UPLOAD inputs name a file by one of three forms:
 *   - an absolute local path, which must resolve (by realpath) inside a directory the owner allowlisted in
 *     `settings.connectors.upload_allowlist`. With no allowlist no local path is accepted: the default is
 *     closed. Inside the allowlist these are STILL refused: `.ssh`, `.aws`, `.gnupg`, `.kube`, `.env` files,
 *     vault, key and certificate files, browser profile directories, and anything under SWITCHBOARD_HOME
 *     except its own `files/` folder. The owner may add deny segments; none can be removed.
 *   - an `https://` URL, fetched through the SSRF guard with the size cap;
 *   - `staged:<run_id>/<name>`, a file an earlier action downloaded (or `stage()` copied) under
 *     `<SWITCHBOARD_HOME>/files/`.
 * A symlink or junction that leaves the allowlist is refused because the check is made on the REAL path of
 * the opened file, and the bytes are read from that same open handle (no gap to swap the file in). The size
 * cap is checked before any byte is read.
 *
 * DOWNLOAD outputs are written to `<SWITCHBOARD_HOME>/files/<run_id>/<name>` (mode 0600) and the agent gets
 * `{ uri, bytes, sha256, mimeType, name }`, never the bytes themselves.
 *
 * This copies the intent of the Composio SDK's `sensitiveFileUploadProtection`, `fileUploadPathDenySegments`
 * and `fileUploadAllowlist` without its S3 presign hop.
 */

import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readSync, realpathSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { basename, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { guardedFetch, type NetworkSource } from "../netguard.js";
import type { ConnectorSettings } from "../types.js";
import { CONNECTOR_ERR, ConnectorError } from "./errors.js";

export const DEFAULT_MAX_UPLOAD_BYTES = 256 * 1024 * 1024;
export const DEFAULT_MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024;

/** Path segments (case-insensitive) that are never uploadable, wherever they sit. */
export const DENY_SEGMENTS: readonly string[] = [
  ".ssh", ".aws", ".gnupg", ".gpg", ".kube", ".docker", ".azure", ".config", ".mozilla", ".switchboard",
  "user data", "mozilla", "google-chrome", "chromium", "chrome", "firefox", "bravesoftware",
];

/** File names that are never uploadable. Matched against the base name, case-insensitive. */
const DENY_NAME = /^(\.env(\..*)?|\.npmrc|\.netrc|\.pgpass|vault\.(json|key|key\.dpapi)|.*\.(key|pem|pfx|p12|keystore|jks|ppk|kdbx)|id_(rsa|dsa|ecdsa|ed25519).*|credentials(\.json)?|client_secrets?.*\.json|service[-_]account.*\.json|.*\.(token|secrets?)|known_hosts|authorized_keys|login data|cookies|local state)$/i;

const MIME: Record<string, string> = {
  ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp",
  ".mp4": "video/mp4", ".mov": "video/quicktime", ".webm": "video/webm", ".mkv": "video/x-matroska",
  ".mp3": "audio/mpeg", ".wav": "audio/wav", ".m4a": "audio/mp4",
  ".pdf": "application/pdf", ".txt": "text/plain", ".md": "text/markdown", ".csv": "text/csv", ".json": "application/json",
  ".zip": "application/zip", ".html": "text/html", ".xml": "application/xml",
};

export function mimeFor(name: string, fallback = "application/octet-stream"): string {
  return MIME[extname(name).toLowerCase()] ?? fallback;
}

export interface ResolvedFile {
  bytes: Buffer;
  name: string;
  mimeType: string;
  sha256: string;
  source: "path" | "url" | "staged";
}

export interface FileRef {
  uri: string;
  bytes: number;
  sha256: string;
  mimeType: string;
  name: string;
}

export const sha256Hex = (b: Uint8Array | string): string => createHash("sha256").update(b).digest("hex");

function refuse(message: string, hint?: string): ConnectorError {
  return new ConnectorError(CONNECTOR_ERR.FILE_REFUSED, message, hint ? { hint } : {});
}

/** `inner` is `outer` or below it (both already real paths). Case-insensitive on Windows. */
export function isInside(outer: string, inner: string): boolean {
  const ci = process.platform === "win32";
  const a = ci ? outer.toLowerCase() : outer;
  const b = ci ? inner.toLowerCase() : inner;
  const rel = relative(a, b);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function segmentsOf(path: string): string[] {
  return path.split(/[\\/]+/).filter(Boolean).map((s) => s.toLowerCase());
}

function safeName(raw: string): string {
  // eslint-disable-next-line no-control-regex
  const base = basename(raw.replace(/\\/g, "/")).replace(/[\u0000-\u001f<>:"|?*]/g, "_").replace(/^\.+/, "_").trim();
  return (base || "file").slice(0, 120);
}

export function newRunId(now: number): string {
  return `run_${now.toString(36)}_${randomBytes(5).toString("hex")}`;
}

export class FileService {
  private readonly filesRoot: string;

  constructor(
    private readonly opts: {
      home: string;
      settings: () => ConnectorSettings | undefined;
      network?: NetworkSource;
      now: () => number;
    },
  ) {
    this.filesRoot = join(opts.home, "files");
  }

  get root(): string {
    return this.filesRoot;
  }

  maxUpload(): number {
    return this.opts.settings()?.max_upload_bytes ?? DEFAULT_MAX_UPLOAD_BYTES;
  }

  maxDownload(): number {
    return this.opts.settings()?.max_download_bytes ?? DEFAULT_MAX_DOWNLOAD_BYTES;
  }

  private denySegments(): Set<string> {
    return new Set([...DENY_SEGMENTS, ...(this.opts.settings()?.upload_deny_segments ?? []).map((s) => s.toLowerCase())]);
  }

  /** Resolve an upload argument to bytes, applying every rule. Throws a ConnectorError (FILE_REFUSED, FILE_TOO_LARGE). */
  async resolveUpload(arg: unknown, maxBytes = this.maxUpload()): Promise<ResolvedFile> {
    if (typeof arg !== "string" || !arg.trim()) throw refuse("a file argument must be a path, an https URL or staged:<id>");
    const ref = arg.trim();
    if (ref.startsWith("staged:")) return this.readStaged(ref.slice(7), maxBytes);
    if (/^https?:\/\//i.test(ref)) return this.fetchUrl(ref, maxBytes);
    if (/^file:\/\//i.test(ref)) {
      let p: string;
      try {
        p = fileURLToPath(ref);
      } catch {
        throw refuse("the file:// URL could not be read as a path");
      }
      return this.readLocal(p, maxBytes);
    }
    return this.readLocal(ref, maxBytes);
  }

  // ── local path ───────────────────────────────────────────────────────────────────────────────

  private readLocal(path: string, maxBytes: number): ResolvedFile {
    if (!isAbsolute(path)) throw refuse(`'${path}' is not an absolute path`, "give the full path of the file");
    const allow = (this.opts.settings()?.upload_allowlist ?? []).filter((d) => typeof d === "string" && d.trim());
    const ownFiles = this.safeReal(this.filesRoot);
    if (allow.length === 0 && !ownFiles) {
      throw refuse("local file uploads are off: settings.connectors.upload_allowlist is empty", "list the folders agents may upload from, for example settings.connectors.upload_allowlist: [\"D:/Ideas/creative\"]");
    }
    const lexical = resolve(path);
    this.checkSensitive(lexical, "path");
    let real: string;
    try {
      real = realpathSync.native(lexical);
    } catch {
      throw refuse(`file not found: ${basename(lexical)}`);
    }
    // The real path is what counts: a link inside the allowlist that points outside is an escape.
    this.checkSensitive(real, "real path");
    const roots = [...allow.map((d) => this.safeReal(resolve(d))), ownFiles].filter((r): r is string => Boolean(r));
    if (!roots.some((r) => isInside(r, real))) {
      throw refuse(`'${basename(lexical)}' is outside the upload allowlist${real.toLowerCase() !== lexical.toLowerCase() ? " (it resolves through a link to somewhere else)" : ""}`, "move the file into an allowlisted folder, or add its folder to settings.connectors.upload_allowlist");
    }
    const home = this.safeReal(this.opts.home);
    if (home && isInside(home, real) && !(ownFiles && isInside(ownFiles, real))) throw refuse("files inside SWITCHBOARD_HOME (vault, tokens, audit) are never uploadable");
    return this.readHandle(real, maxBytes, "path");
  }

  private safeReal(p: string): string | undefined {
    try {
      return realpathSync.native(p);
    } catch {
      return undefined;
    }
  }

  private checkSensitive(path: string, label: string): void {
    const deny = this.denySegments();
    const segs = segmentsOf(path);
    const hit = segs.find((s) => deny.has(s));
    if (hit) throw refuse(`the ${label} passes through '${hit}', which is never uploadable (sensitive location)`);
    const name = basename(path);
    if (DENY_NAME.test(name)) throw refuse(`'${name}' looks like a secret, key or credential file and is never uploadable`);
  }

  private readHandle(real: string, maxBytes: number, source: ResolvedFile["source"]): ResolvedFile {
    const fd = openSync(real, "r");
    try {
      const st = fstatSync(fd);
      if (!st.isFile()) throw refuse(`'${basename(real)}' is not a regular file`);
      if (st.size > maxBytes) throw new ConnectorError(CONNECTOR_ERR.FILE_TOO_LARGE, `'${basename(real)}' is ${st.size} bytes, over the ${maxBytes} byte upload limit (settings.connectors.max_upload_bytes)`);
      const bytes = Buffer.alloc(st.size);
      let off = 0;
      while (off < st.size) {
        const n = readSync(fd, bytes, off, st.size - off, off);
        if (n === 0) break;
        off += n;
      }
      const name = basename(real);
      return { bytes: off === st.size ? bytes : bytes.subarray(0, off), name, mimeType: mimeFor(name), sha256: sha256Hex(bytes.subarray(0, off)), source };
    } finally {
      closeSync(fd);
    }
  }

  // ── staged ───────────────────────────────────────────────────────────────────────────────────

  /** `<run_id>/<name>` under files/. Both segments are plain names, so there is nothing to traverse. */
  stagedPath(id: string): string {
    const m = id.match(/^([A-Za-z0-9_-]{3,64})\/([^/\\]{1,160})$/);
    if (!m || m[2] === "." || m[2] === ".." || m[2]!.includes("\0")) throw refuse(`'staged:${id}' is not a staged file id (expected staged:<run_id>/<name>)`);
    return join(this.filesRoot, m[1]!, m[2]!);
  }

  private readStaged(id: string, maxBytes: number): ResolvedFile {
    const path = this.stagedPath(id);
    const real = this.safeReal(path);
    const root = this.safeReal(this.filesRoot);
    if (!real || !root) throw refuse(`staged file 'staged:${id}' does not exist`);
    if (!isInside(root, real)) throw refuse("a staged file must live under SWITCHBOARD_HOME/files");
    return this.readHandle(real, maxBytes, "staged");
  }

  /** Copy bytes into files/ as a new staged file and return its `staged:` reference. */
  stage(bytes: Uint8Array, name: string): { ref: string; file: FileRef } {
    const runId = `stg_${randomBytes(6).toString("hex")}`;
    const file = this.saveDownload(runId, bytes, { name });
    return { ref: `staged:${runId}/${file.name}`, file };
  }

  // ── https URL ────────────────────────────────────────────────────────────────────────────────

  private async fetchUrl(url: string, maxBytes: number): Promise<ResolvedFile> {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw refuse("the upload URL could not be parsed");
    }
    const loop = parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost" || parsed.hostname === "[::1]";
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loop)) throw refuse("an upload URL must be https");
    let res;
    try {
      res = await guardedFetch(parsed, { maxBytes, timeoutMs: 120_000 }, this.opts.network);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/limit|too_large|bytes/i.test(msg)) throw new ConnectorError(CONNECTOR_ERR.FILE_TOO_LARGE, `the upload URL is over the ${maxBytes} byte limit`);
      throw refuse(`the upload URL was refused or failed: ${msg.slice(0, 160)}`);
    }
    if (!res.ok) throw refuse(`the upload URL answered HTTP ${res.status}`);
    const bytes = Buffer.from(await res.bytes());
    const name = safeName(decodeURIComponent(parsed.pathname.split("/").filter(Boolean).pop() ?? "file"));
    const ct = res.headers.get("content-type")?.split(";")[0]?.trim();
    return { bytes, name, mimeType: ct && ct !== "application/octet-stream" ? ct : mimeFor(name), sha256: sha256Hex(bytes), source: "url" };
  }

  // ── download ─────────────────────────────────────────────────────────────────────────────────

  /** Save an output file under files/<run_id>/ and describe it. Never overwrites: a second name gets a suffix. */
  saveDownload(runId: string, bytes: Uint8Array, hint: { name?: string; mimeType?: string } = {}): FileRef {
    if (!/^[A-Za-z0-9_-]{3,64}$/.test(runId)) throw refuse("bad run id for a download");
    if (bytes.byteLength > this.maxDownload()) throw new ConnectorError(CONNECTOR_ERR.FILE_TOO_LARGE, `the file is ${bytes.byteLength} bytes, over the ${this.maxDownload()} byte download limit (settings.connectors.max_download_bytes)`);
    const dir = join(this.filesRoot, runId);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    let name = safeName(hint.name ?? "download");
    if (existsSync(join(dir, name))) {
      const ext = extname(name);
      name = `${name.slice(0, name.length - ext.length)}_${randomBytes(3).toString("hex")}${ext}`;
    }
    const path = join(dir, name);
    // 'wx': never follow or replace something that appeared since the existence check.
    writeFileSync(path, bytes, { mode: 0o600, flag: "wx" });
    return { uri: pathToFileURL(path).href, bytes: bytes.byteLength, sha256: sha256Hex(bytes), mimeType: hint.mimeType ?? mimeFor(name), name };
  }

  /** Where a saved file lives (for the oracle and `files` CLI). */
  pathOf(ref: FileRef): string {
    return fileURLToPath(ref.uri);
  }

  isOwnFile(path: string): boolean {
    const real = this.safeReal(path);
    const root = this.safeReal(this.filesRoot);
    return Boolean(real && root && isInside(root, real));
  }

  /** Path with forward slashes for messages. */
  static display(p: string): string {
    return p.split(sep).join("/");
  }
}
