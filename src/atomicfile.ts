/**
 * Crash-safe local storage primitives (design vNext 3.9).
 *
 * Every durable store (vault, API keys, OAuth state, trigger state, config writes, owner sessions)
 * goes through this one module so the guarantees live in one place:
 *
 *  - ATOMIC REPLACE: write a temp file next to the target, fsync it, then rename it over the target.
 *    A crash leaves either the old file or the new file, never a half-written one.
 *  - KEEP `.bak`: before the rename the previous good version is copied to `<file>.bak` (itself written
 *    by temp + rename), so one bad generation is always recoverable by hand.
 *  - CORRUPT IS AN ERROR, NEVER AN EMPTY STORE: a file that exists but does not parse throws a
 *    `StoreCorruptError` that names the file and the backup. Returning `{}` for a torn file is how a
 *    revoked key, a vault or a trigger cursor silently resets, so no reader here ever does it. A file
 *    that does not exist is a normal first run and reads as `undefined`.
 *  - CROSS-PROCESS READ-MODIFY-WRITE: `withFileLock` serialises writers (the CLI and the gateway are
 *    separate processes), and `WatchedJsonFile` re-reads when the file's mtime, size or inode changed,
 *    so a CLI change reaches a running gateway and the gateway never writes stale memory back.
 *
 * Zero dependencies; everything is synchronous like the rest of the stores.
 */

import {
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";

/** A store file exists but is unusable (not valid JSON, empty, or the wrong shape). */
export class StoreCorruptError extends Error {
  readonly code = "SB_STORE_CORRUPT";
  constructor(
    readonly path: string,
    readonly reason: string,
    /** State of `<path>.bak`: a usable previous version, an unusable one, or none. */
    readonly backup: "valid" | "invalid" | "absent",
  ) {
    super(
      `store file ${path} exists but cannot be used (${reason}). It was NOT replaced with an empty store. ` +
        (backup === "valid"
          ? `A backup of the previous version parses at ${path}.bak: inspect it and, if it is right, copy it over ${path}.`
          : backup === "invalid"
            ? `The backup ${path}.bak is also unusable. Restore the file from your own backup or remove it to start empty.`
            : `There is no backup (${path}.bak). Restore the file from your own backup or remove it to start empty.`),
    );
    this.name = "StoreCorruptError";
  }
}

// ── directories ─────────────────────────────────────────────────────────────────────────────────

/**
 * Create `dir` (and parents) if missing, owner-only (0700) where the OS supports modes. An existing
 * directory is left as it is: only creation sets the mode. chmod is a no-op on Windows, where the
 * per-user profile ACL is the boundary.
 */
export function ensureDir(dir: string): void {
  if (existsSync(dir)) return;
  const firstCreated = mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform === "win32") return;
  // mkdir's mode is masked by the umask, which can only narrow it; chmod makes 0700 exact.
  try {
    chmodSync(dir, 0o700);
    if (firstCreated && firstCreated !== dir) chmodSync(firstCreated, 0o700);
  } catch {
    /* best-effort */
  }
}

// ── change detection ────────────────────────────────────────────────────────────────────────────

/**
 * A cheap identity of the file's current content: mtime (ns), size and inode. Null when the file is
 * absent. An atomic replace gives a new inode on POSIX and a new mtime everywhere, so a change is
 * seen even when the new content happens to have the same size.
 */
export function fileStamp(path: string): string | null {
  try {
    const st = statSync(path, { bigint: true });
    return `${st.mtimeNs}:${st.size}:${st.ino}`;
  } catch {
    return null;
  }
}

// ── low-level helpers ───────────────────────────────────────────────────────────────────────────

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

const TRANSIENT = new Set(["EPERM", "EACCES", "EBUSY", "EMFILE", "ENFILE"]);

/** Run an fs operation, retrying briefly on the transient errors Windows raises while another process
 *  (an indexer, antivirus, a concurrent reader) briefly holds the file. */
function retrying<T>(op: () => T, attempts = 8): T {
  for (let i = 0; ; i++) {
    try {
      return op();
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? "";
      if (i >= attempts - 1 || !TRANSIENT.has(code)) throw err;
      sleepSync(5 * (i + 1));
    }
  }
}

let tmpCounter = 0;

function tmpNameFor(path: string): string {
  // Never ends in `.json`: a directory scan for `*.json` must not pick up a temp file.
  return `${path}.${process.pid}.${Date.now().toString(36)}.${tmpCounter++}.tmp`;
}

function fsyncDir(dir: string): void {
  if (process.platform === "win32") return; // a directory cannot be opened for fsync on Windows
  try {
    const fd = openSync(dir, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    /* best-effort: the rename itself is already atomic */
  }
}

// ── atomic write ────────────────────────────────────────────────────────────────────────────────

export interface AtomicWriteOptions {
  /** File mode for a secret store (0o600). Omitted: keep the existing file's mode, else the default. */
  mode?: number;
  /**
   * Keep the previous version as `<file>.bak`. `true` always copies it; a function copies only when it
   * returns true for the current bytes (so a corrupt current file never overwrites a good backup).
   * Default false.
   */
  backup?: boolean | ((current: Buffer) => boolean);
}

/** Write `data` to `path` atomically: temp file, fsync, optional `.bak`, rename. Throws on failure and
 *  leaves the previous file untouched. */
export function atomicWriteFileSync(path: string, data: string | Buffer, opts: AtomicWriteOptions = {}): void {
  const dir = dirname(path);
  ensureDir(dir);
  let mode = opts.mode;
  if (mode === undefined) {
    try {
      mode = statSync(path).mode & 0o777;
    } catch {
      /* new file: default mode */
    }
  }
  const tmp = tmpNameFor(path);
  const payload = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  try {
    const fd = openSync(tmp, "wx", mode ?? 0o666);
    try {
      let off = 0;
      while (off < payload.length) off += writeSync(fd, payload, off, payload.length - off);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    if (opts.backup && existsSync(path)) keepBackup(path, opts.backup);
    retrying(() => renameSync(tmp, path));
    fsyncDir(dir);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      /* the temp file may not exist */
    }
    throw err;
  }
}

function keepBackup(path: string, backup: true | ((current: Buffer) => boolean)): void {
  try {
    if (typeof backup === "function") {
      const current = readFileSync(path);
      if (!backup(current)) return;
    }
    const bak = `${path}.bak`;
    const bakTmp = tmpNameFor(bak);
    try {
      copyFileSync(path, bakTmp);
      retrying(() => renameSync(bakTmp, bak));
    } catch (err) {
      try {
        unlinkSync(bakTmp);
      } catch {
        /* nothing to clean */
      }
      throw err;
    }
  } catch {
    // A failed backup must not block the write it protects: the primary is still intact until the rename.
  }
}

// ── JSON read/write ─────────────────────────────────────────────────────────────────────────────

const parsesAsJson = (current: Buffer): boolean => {
  try {
    JSON.parse(current.toString("utf8"));
    return true;
  } catch {
    return false;
  }
};

function backupState(path: string): "valid" | "invalid" | "absent" {
  const bak = `${path}.bak`;
  if (!existsSync(bak)) return "absent";
  return parsesAsJson(readFileSync(bak)) ? "valid" : "invalid";
}

export interface ReadJsonOptions {
  /** Return an error message when the parsed value has the wrong shape; null when it is fine. */
  validate?: (value: unknown) => string | null;
}

/**
 * Read and parse a JSON store file. Absent file: `undefined` (a first run). Present but unusable
 * (empty, truncated, not JSON, wrong shape): throws `StoreCorruptError`. Never returns an empty store
 * for a file that exists.
 */
export function readJsonFileSync<T>(path: string, opts: ReadJsonOptions = {}): T | undefined {
  let text: string;
  try {
    text = retrying(() => readFileSync(path, "utf8"));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (err) {
    const why = text.trim() === "" ? "the file is empty" : `not valid JSON: ${err instanceof Error ? err.message : String(err)}`;
    throw new StoreCorruptError(path, why, backupState(path));
  }
  const shape = opts.validate?.(value) ?? null;
  if (shape) throw new StoreCorruptError(path, shape, backupState(path));
  return value as T;
}

export interface WriteJsonOptions {
  mode?: number;
  /** Keep `<file>.bak` of the previous version when it parses. Default true. */
  backup?: boolean;
  /** JSON.stringify indent. Default 2. */
  space?: number;
}

/** Serialize `value` and replace `path` atomically, keeping a `.bak` of the previous parseable version. */
export function writeJsonAtomic(path: string, value: unknown, opts: WriteJsonOptions = {}): void {
  atomicWriteFileSync(path, JSON.stringify(value, null, opts.space ?? 2), {
    ...(opts.mode !== undefined ? { mode: opts.mode } : {}),
    backup: opts.backup === false ? false : parsesAsJson,
  });
}

// ── cross-process lock ──────────────────────────────────────────────────────────────────────────

export interface LockOptions {
  /** Give up after this long. Default 5000 ms. */
  timeoutMs?: number;
  /** A lock file older than this is from a crashed holder and is broken. Default 10000 ms. */
  staleMs?: number;
}

/**
 * Run `fn` while holding an exclusive lock on `<path>.lock` (created with O_EXCL). Held for
 * milliseconds around a read-modify-write, so waiters spin with a short sleep. A lock left by a
 * crashed process is broken once it is older than `staleMs`. Throws if the lock cannot be taken in
 * `timeoutMs` (nothing is written in that case).
 */
export function withFileLock<R>(path: string, fn: () => R, opts: LockOptions = {}): R {
  const lock = `${path}.lock`;
  const timeoutMs = opts.timeoutMs ?? 5000;
  const staleMs = opts.staleMs ?? 10_000;
  ensureDir(dirname(path));
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const fd = openSync(lock, "wx", 0o600);
      try {
        writeSync(fd, `${process.pid}\n${Date.now()}\n`);
      } finally {
        closeSync(fd);
      }
      break;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? "";
      if (code !== "EEXIST" && !TRANSIENT.has(code)) throw err;
      let held = false;
      try {
        const age = Date.now() - statSync(lock).mtimeMs;
        held = true;
        if (age > staleMs) {
          unlinkSync(lock);
          continue; // broke a crashed holder's lock: take it now
        }
      } catch {
        /* the holder released it between our open and our stat, or the directory refuses us (a permission problem) */
      }
      if (Date.now() >= deadline) {
        throw new Error(`could not lock ${path} within ${timeoutMs} ms (${held ? `lock file ${lock} is held` : `cannot create ${lock}: ${code}`})`);
      }
      sleepSync(held ? 5 : 15);
    }
  }
  try {
    return fn();
  } finally {
    try {
      unlinkSync(lock);
    } catch {
      /* already gone */
    }
  }
}

// ── a JSON store that stays current with the file ───────────────────────────────────────────────

/**
 * An in-memory view of a JSON store file that is re-read whenever the file changed on disk, and whose
 * writes are read-modify-write under the cross-process lock. Two processes sharing the file (the CLI
 * and the gateway) therefore always see each other's changes, and a stale instance can never write its
 * old memory back over a newer file.
 */
export class WatchedJsonFile<T> {
  private value: T;
  private stamp: string | null | undefined = undefined; // undefined = never loaded

  constructor(
    readonly path: string,
    private readonly init: () => T,
    private readonly opts: { validate?: (v: unknown) => string | null; mode?: number } = {},
  ) {
    this.value = init();
    this.get(); // load now so a corrupt file fails at construction, not on the first request
  }

  /** The current content. Re-reads when the file changed since the last read; throws `StoreCorruptError`
   *  when it exists but is unusable. */
  get(): T {
    const stamp = fileStamp(this.path);
    if (stamp !== this.stamp) {
      this.value = readJsonFileSync<T>(this.path, this.opts.validate ? { validate: this.opts.validate } : {}) ?? this.init();
      this.stamp = stamp;
    }
    return this.value;
  }

  /**
   * Read the file fresh under the lock, apply `mutate`, and write the result atomically. `mutate`
   * returns the new content, or `undefined` to leave the file alone. Returns what the file now holds.
   */
  update(mutate: (current: T) => T | undefined): T {
    return withFileLock(this.path, () => {
      const current = readJsonFileSync<T>(this.path, this.opts.validate ? { validate: this.opts.validate } : {}) ?? this.init();
      const next = mutate(current);
      if (next !== undefined) {
        writeJsonAtomic(this.path, next, this.opts.mode !== undefined ? { mode: this.opts.mode } : {});
      }
      this.value = next ?? current;
      this.stamp = undefined; // the next get() re-reads once, so a write by another process is never masked
      return this.value;
    });
  }
}
