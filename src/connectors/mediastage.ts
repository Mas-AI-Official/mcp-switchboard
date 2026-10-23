/**
 * Media staging (ADR local-composio, section 6.6): the part Composio hides behind S3.
 *
 * Some platforms (Instagram image posts, TikTok PULL_FROM_URL) fetch the media themselves from a public
 * URL. `MediaStage` hands out an EPHEMERAL URL for exactly one file:
 *
 *   - `<public_base_url>/media/<192-bit random id>`, served by `mountMediaRoutes` on the dashboard listener
 *     (the same listener `switchboard expose` fronts with a tunnel; `/media/` is the only path of it a
 *     public host may reach);
 *   - valid for at most 15 minutes, whatever the caller asks, and for a small bounded number of GETs
 *     (default 3, at most 10); a handful of HEADs is allowed without using a fetch;
 *   - a copy of the file on disk under `files/media/<id>` that is DELETED when the last fetch is made, when
 *     the URL expires, or when the action that created it ends (`release`);
 *   - an unknown, expired or used-up id answers one identical 404, so nothing is learned from probing.
 *
 * Two backends are named by `settings.connectors.media.backend`:
 *   - `expose` (default): the stage above. It needs `public_base_url` (the tunnel URL) and a listener in this
 *     process; with neither, `publish` refuses with SB_MEDIA_NOT_CONFIGURED and says what to do, so an
 *     Instagram image post fails loudly instead of silently doing nothing.
 *   - `s3`: an S3-compatible bucket with presigned URLs. Only the interface exists in this build:
 *     `S3PresignBackend.publish` always refuses until a later phase implements it.
 */

import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import type { Express, Request, Response } from "express";
import type { ConnectorSettings } from "../types.js";
import { CONNECTOR_ERR, ConnectorError } from "./errors.js";

export const MEDIA_MAX_TTL_S = 15 * 60;
export const MEDIA_DEFAULT_FETCHES = 3;
export const MEDIA_MAX_FETCHES = 10;
const MAX_HEADS = 10;
const ID_RE = /^[A-Za-z0-9_-]{32,64}$/;

export interface StagedMedia {
  id: string;
  url: string;
  expires_at: string;
  max_fetches: number;
}

export interface MediaFile {
  bytes: Uint8Array;
  name: string;
  mimeType: string;
}

/** The seam a bucket backed implementation plugs into. */
export interface MediaBackend {
  readonly kind: "expose" | "s3";
  publish(file: MediaFile, opts?: { ttlSeconds?: number; maxFetches?: number }): Promise<StagedMedia>;
}

export class S3PresignBackend implements MediaBackend {
  readonly kind = "s3" as const;
  async publish(): Promise<StagedMedia> {
    throw new ConnectorError(
      CONNECTOR_ERR.MEDIA_NOT_CONFIGURED,
      "the S3-compatible media backend is not implemented in this build: it refuses until a bucket, credentials and a presign step are configured",
      { hint: "use backend: expose with a tunnel (settings.connectors.media.public_base_url), or wait for the s3 backend" },
    );
  }
}

interface Entry {
  id: string;
  path: string;
  name: string;
  mimeType: string;
  size: number;
  expires: number;
  fetchesLeft: number;
  heads: number;
}

export class MediaStage implements MediaBackend {
  readonly kind = "expose" as const;
  private readonly entries = new Map<string, Entry>();
  private readonly dir: string;
  private localBase: string | undefined;

  constructor(
    private readonly opts: {
      home: string;
      settings: () => ConnectorSettings | undefined;
      now: () => number;
    },
  ) {
    this.dir = join(opts.home, "files", "media");
  }

  /** Called when the routes are mounted on a listener in this process (the local address it serves on). */
  attach(localBase: string): void {
    this.localBase = localBase.replace(/\/+$/, "");
  }

  get attached(): boolean {
    return this.localBase !== undefined;
  }

  /** The backend the settings select. `s3` yields the refusing stub. */
  backend(): MediaBackend {
    return this.opts.settings()?.media?.backend === "s3" ? new S3PresignBackend() : this;
  }

  private base(): string {
    const m = this.opts.settings()?.media;
    const pub = m?.public_base_url?.trim();
    if (pub) {
      let u: URL;
      try {
        u = new URL(pub);
      } catch {
        throw new ConnectorError(CONNECTOR_ERR.MEDIA_NOT_CONFIGURED, "settings.connectors.media.public_base_url is not a valid URL");
      }
      if (u.protocol !== "https:" && !(m?.allow_local === true)) {
        throw new ConnectorError(CONNECTOR_ERR.MEDIA_NOT_CONFIGURED, "settings.connectors.media.public_base_url must be https (a tunnel URL)");
      }
      return pub.replace(/\/+$/, "");
    }
    if (m?.allow_local === true && this.localBase) return this.localBase;
    throw new ConnectorError(
      CONNECTOR_ERR.MEDIA_NOT_CONFIGURED,
      "this platform fetches the media from a public URL and none is configured, so nothing was sent",
      { hint: "run `switchboard expose --tunnel cloudflared` and set settings.connectors.media.public_base_url to its https URL, or configure an S3 backend" },
    );
  }

  async publish(file: MediaFile, o: { ttlSeconds?: number; maxFetches?: number } = {}): Promise<StagedMedia> {
    const base = this.base();
    if (!this.attached) {
      throw new ConnectorError(CONNECTOR_ERR.MEDIA_NOT_CONFIGURED, "no media listener is running in this process: start the gateway (`switchboard dashboard` or `serve`) so /media/<id> can be served", { hint: "media staging only works inside a running gateway" });
    }
    this.sweep();
    const cfg = this.opts.settings()?.media;
    const ttl = Math.max(1, Math.min(MEDIA_MAX_TTL_S, Math.floor(o.ttlSeconds ?? cfg?.ttl_seconds ?? MEDIA_MAX_TTL_S)));
    const fetches = Math.max(1, Math.min(MEDIA_MAX_FETCHES, Math.floor(o.maxFetches ?? cfg?.max_fetches ?? MEDIA_DEFAULT_FETCHES)));
    const id = randomBytes(24).toString("base64url");
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const path = join(this.dir, id);
    writeFileSync(path, file.bytes, { mode: 0o600, flag: "wx" });
    const expires = this.opts.now() + ttl * 1000;
    this.entries.set(id, { id, path, name: file.name, mimeType: file.mimeType, size: file.bytes.byteLength, expires, fetchesLeft: fetches, heads: 0 });
    return { id, url: `${base}/media/${id}`, expires_at: new Date(expires).toISOString(), max_fetches: fetches };
  }

  /** Serve one fetch: the bytes, or undefined (unknown, expired, used up). The last fetch deletes the file. */
  take(id: string, method: "GET" | "HEAD" = "GET"): { bytes: Buffer; mimeType: string; name: string; size: number } | undefined {
    this.sweep();
    if (!ID_RE.test(id)) return undefined;
    const e = this.entries.get(id);
    if (!e) return undefined;
    if (method === "HEAD") {
      if (e.heads >= MAX_HEADS) return undefined;
      e.heads += 1;
      return { bytes: Buffer.alloc(0), mimeType: e.mimeType, name: e.name, size: e.size };
    }
    let bytes: Buffer;
    try {
      bytes = readFileSync(e.path);
    } catch {
      this.drop(id);
      return undefined;
    }
    e.fetchesLeft -= 1;
    if (e.fetchesLeft <= 0) this.drop(id);
    return { bytes, mimeType: e.mimeType, name: e.name, size: e.size };
  }

  /** Delete one staged file now (the action that made it is finished). */
  release(id: string): void {
    this.drop(id);
  }

  /** Remove every expired entry and its file. Returns how many. */
  sweep(): number {
    const now = this.opts.now();
    let n = 0;
    for (const e of [...this.entries.values()]) {
      if (e.expires <= now) {
        this.drop(e.id);
        n += 1;
      }
    }
    return n;
  }

  /** For the oracle and `doctor`: how many files are staged right now. */
  count(): number {
    return this.entries.size;
  }

  has(id: string): boolean {
    return this.entries.has(id);
  }

  fileOf(id: string): string | undefined {
    return this.entries.get(id)?.path;
  }

  /** Delete everything (shutdown). */
  clear(): void {
    for (const id of [...this.entries.keys()]) this.drop(id);
  }

  private drop(id: string): void {
    const e = this.entries.get(id);
    if (!e) return;
    this.entries.delete(id);
    try {
      if (existsSync(e.path)) rmSync(e.path, { force: true });
    } catch {
      /* the file is already gone */
    }
  }
}

/**
 * Mount `GET|HEAD /media/:id`. The route does nothing else and lists nothing; an id the stage did not hand
 * out is a 404. `localBase` is the address this listener answers on (for local-only test setups).
 */
export function mountMediaRoutes(app: Express, stage: MediaStage, localBase: string): void {
  stage.attach(localBase);
  const handler = (req: Request, res: Response): void => {
    const id = String(req.params.id ?? "");
    const method = req.method === "HEAD" ? "HEAD" : "GET";
    const hit = stage.take(id, method);
    res.set("Cache-Control", "no-store");
    res.set("X-Content-Type-Options", "nosniff");
    if (!hit) {
      res.status(404).type("text/plain").send("not found");
      return;
    }
    res.status(200);
    res.set("Content-Type", hit.mimeType);
    res.set("Content-Length", String(hit.size));
    if (method === "HEAD") {
      res.end();
      return;
    }
    res.end(hit.bytes);
  };
  app.get("/media/:id", handler);
  app.head("/media/:id", handler);
}
