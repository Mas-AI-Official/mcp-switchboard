/**
 * netguard.ts: the SSRF guard for every outbound request the gateway makes on behalf of config or
 * tools (http-tool calls, app2mcp spec fetches and calls, webhooks, OAuth token and refresh calls,
 * the council relay, catalog syncs, local model probes).
 *
 * A configured URL, a URL inside an OpenAPI document, or a redirect `Location` is attacker-influenced
 * input: it can point the gateway at loopback services, the LAN, or a cloud metadata endpoint and
 * carry the operator's credentials there. Rules enforced here, per request and per redirect hop:
 *
 *   1. Only http: and https: URLs without embedded credentials.
 *   2. DNS is resolved FIRST and every answer is classified. Loopback, RFC1918, CGNAT 100.64/10,
 *      link-local (169.254/16, fe80::/10), ULA (fc00::/7), unspecified, multicast, reserved and cloud
 *      metadata addresses are refused, including their IPv4-mapped, NAT64 and 6to4 encodings. One bad
 *      answer among several refuses the host. The literal names localhost, *.localhost and the
 *      well-known metadata names are refused without asking DNS.
 *   3. The connection is made to the address that was validated (pinned lookup), so a second DNS
 *      answer cannot redirect it after the check (DNS rebinding). TLS still verifies the host name.
 *   4. Redirects are followed manually, at most 3. Every hop repeats steps 1 to 3. Credential headers
 *      (Authorization, Cookie, API-key style names and any name the caller lists) are dropped when the
 *      origin changes. A 301/302 POST and a 303 become a body-less GET; a 307/308 that would re-send a
 *      request body to another origin is refused; an https to http downgrade is refused.
 *   5. One deadline covers resolution, connect, headers and body (default 15 s). The body is capped
 *      while streaming, on the DECODED bytes (default 5 MiB), so a gzip bomb or an endless chunked
 *      stream is cut instead of buffered.
 *
 * Exemption, exact host only: `settings.network.allow_private` lists host names or IP addresses that
 * may resolve to non-public addresses (a local model server on 127.0.0.1, a LAN API). "Exact" means
 * the host in the URL, after normalisation, equals an entry: listing 127.0.0.1 does not allow
 * localhost, and listing localhost does not allow 127.0.0.1. No wildcards, no CIDR, no ports.
 *
 * Which callers rely on the allowlist and which are explicit local probes:
 *   - council `local` provider (settings.council.providers.local.base_url): allowlisted by config; its
 *     host must be listed in allow_private (`switchboard local-llm wire` adds it).
 *   - local-llm probes (`switchboard local-llm`, `probeRuntime`) and the CLI's own /healthz check:
 *     explicit local probes (`allowLoopback`): loopback targets pass without a config entry, nothing
 *     else is exempted (a LAN or metadata URL is still refused unless allowlisted).
 *
 * Range choices worth knowing: 198.18.0.0/15 (benchmarking) is deliberately NOT blocked, because
 * fake-IP proxy and VPN setups answer every lookup from it and would otherwise break all outbound
 * calls. Remote MCP upstreams (`source: remote`) use the MCP SDK's HTTP transport with
 * {@link guardedMcpFetch} as its fetch, so their POSTs, event streams and redirects pass the same checks.
 *
 * Test seam: {@link setResolverForTests} and {@link useFetchStubForTests} let oracles inject DNS answers
 * and a fetch-shaped transport. Production never calls them.
 */

import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import net from "node:net";
import zlib from "node:zlib";
import { pipeline, type Readable } from "node:stream";
import type { NetworkSettings } from "./types.js";

export type { NetworkSettings };

/** Where the effective settings come from: an object, a thunk (live config), or nothing (defaults). */
export type NetworkSource = NetworkSettings | (() => NetworkSettings | undefined) | undefined;

export const DEFAULT_TIMEOUT_MS = 15_000;
export const DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
export const MAX_REDIRECTS = 3;
/** Bulk public documents (OpenAPI specs, catalog registries) are far larger than tool responses. */
export const BULK_DOCUMENT_MAX_BYTES = 64 * 1024 * 1024;
export const BULK_DOCUMENT_TIMEOUT_MS = 60_000;

export type NetGuardCode =
  | "invalid_url"
  | "bad_scheme"
  | "blocked_host"
  | "blocked_address"
  | "dns_failed"
  | "redirect_limit"
  | "redirect_blocked"
  | "timeout"
  | "aborted"
  | "too_large"
  | "bad_encoding";

/** Every refusal the guard makes. `code` is stable; `message` is written for the operator. */
export class NetGuardError extends Error {
  readonly code: NetGuardCode;
  constructor(code: NetGuardCode, message: string) {
    super(message);
    this.name = "NetGuardError";
    this.code = code;
  }
}

// --- address classification ----------------------------------------------------------------------

interface Verdict {
  kind: "loopback" | "metadata" | "special";
  reason: string;
}

function ipv4Octets(ip: string): number[] | null {
  return net.isIPv4(ip) ? ip.split(".").map(Number) : null;
}

function classifyV4(o: number[]): Verdict | null {
  const [a, b, c, d] = o;
  if (a === 0) return { kind: "special", reason: a === 0 && b === 0 && c === 0 && d === 0 ? "unspecified address (0.0.0.0)" : "this-network address (0.0.0.0/8)" };
  if (a === 10) return { kind: "special", reason: "private network (10.0.0.0/8)" };
  if (a === 100 && b >= 64 && b <= 127) return { kind: "special", reason: "carrier-grade NAT (100.64.0.0/10)" };
  if (a === 127) return { kind: "loopback", reason: "loopback (127.0.0.0/8)" };
  if (a === 169 && b === 254) {
    return c === 169 && d === 254
      ? { kind: "metadata", reason: "cloud metadata address (169.254.169.254)" }
      : { kind: "special", reason: "link-local (169.254.0.0/16)" };
  }
  if (a === 172 && b >= 16 && b <= 31) return { kind: "special", reason: "private network (172.16.0.0/12)" };
  if (a === 192 && b === 0 && c === 0) return { kind: "special", reason: "IETF protocol assignments (192.0.0.0/24)" };
  if (a === 192 && b === 0 && c === 2) return { kind: "special", reason: "documentation range (192.0.2.0/24)" };
  if (a === 192 && b === 168) return { kind: "special", reason: "private network (192.168.0.0/16)" };
  if (a === 198 && b === 51 && c === 100) return { kind: "special", reason: "documentation range (198.51.100.0/24)" };
  if (a === 203 && b === 0 && c === 113) return { kind: "special", reason: "documentation range (203.0.113.0/24)" };
  if (a === 168 && b === 63 && c === 129 && d === 16) return { kind: "metadata", reason: "cloud metadata address (Azure wire server 168.63.129.16)" };
  if (a >= 224 && a <= 239) return { kind: "special", reason: "multicast (224.0.0.0/4)" };
  if (a >= 240) return { kind: "special", reason: "reserved (240.0.0.0/4)" };
  return null;
}

/** 16 bytes of an IPv6 address, or null when it does not parse. A zone id (%eth0) is ignored. */
function ipv6Bytes(ip: string): number[] | null {
  const addr = ip.split("%")[0];
  if (!net.isIPv6(addr)) return null;
  let s = addr.toLowerCase();
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const o = tail.split(".").map(Number);
    s = `${s.slice(0, lastColon + 1)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  let groups: string[];
  const dbl = s.indexOf("::");
  if (dbl >= 0) {
    const left = s.slice(0, dbl);
    const right = s.slice(dbl + 2);
    const l = left ? left.split(":") : [];
    const r = right ? right.split(":") : [];
    groups = [...l, ...Array<string>(Math.max(0, 8 - l.length - r.length)).fill("0"), ...r];
  } else {
    groups = s.split(":");
  }
  if (groups.length !== 8) return null;
  const bytes: number[] = [];
  for (const g of groups) {
    const v = parseInt(g, 16);
    if (!Number.isFinite(v) || v < 0 || v > 0xffff) return null;
    bytes.push(v >> 8, v & 255);
  }
  return bytes;
}

const allZero = (b: number[], from: number, to: number) => b.slice(from, to).every((x) => x === 0);

function classifyV6(b: number[]): Verdict | null {
  if (allZero(b, 0, 16)) return { kind: "special", reason: "unspecified address (::)" };
  if (allZero(b, 0, 15) && b[15] === 1) return { kind: "loopback", reason: "loopback (::1)" };
  const v4 = b.slice(12, 16);
  // ::ffff:0:0/96 IPv4-mapped: the embedded IPv4 decides.
  if (allZero(b, 0, 10) && b[10] === 0xff && b[11] === 0xff) {
    const r = classifyV4(v4);
    return r ? { kind: "special", reason: `IPv4-mapped ${r.reason}` } : null;
  }
  // 64:ff9b::/96 NAT64: the embedded IPv4 decides. 64:ff9b:1::/48 is local-use.
  if (b[0] === 0 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) {
    if (allZero(b, 4, 12)) {
      const r = classifyV4(v4);
      return r ? { kind: "special", reason: `NAT64 ${r.reason}` } : null;
    }
    if (b[4] === 0 && b[5] === 1) return { kind: "special", reason: "NAT64 local-use range (64:ff9b:1::/48)" };
  }
  // 2002::/16 6to4: the embedded IPv4 (bytes 2..5) decides.
  if (b[0] === 0x20 && b[1] === 0x02) {
    const r = classifyV4(b.slice(2, 6));
    return r ? { kind: "special", reason: `6to4 ${r.reason}` } : null;
  }
  if (b[0] === 0) return { kind: "special", reason: "reserved (::/8, includes IPv4-compatible addresses)" };
  if (b[0] === 0x01 && allZero(b, 1, 8)) return { kind: "special", reason: "discard-only (100::/64)" };
  if ((b[0] & 0xfe) === 0xfc) return { kind: "special", reason: "unique local address (fc00::/7)" };
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return { kind: "special", reason: "link-local (fe80::/10)" };
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return { kind: "special", reason: "site-local (fec0::/10, deprecated)" };
  if (b[0] === 0xff) return { kind: "special", reason: "multicast (ff00::/8)" };
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] < 0x02) return { kind: "special", reason: "IETF protocol assignments (2001::/23)" };
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return { kind: "special", reason: "documentation range (2001:db8::/32)" };
  if (b[0] === 0x3f && b[1] === 0xff && (b[2] & 0xf0) === 0) return { kind: "special", reason: "documentation range (3fff::/20)" };
  return null;
}

function classify(ip: string): Verdict | null {
  const s = ip.trim().replace(/^\[|\]$/g, "");
  const v4 = ipv4Octets(s);
  if (v4) return classifyV4(v4);
  const v6 = ipv6Bytes(s);
  if (v6) return classifyV6(v6);
  return { kind: "special", reason: `not a valid IP address (${JSON.stringify(ip)})` };
}

/**
 * Why an IP address must not be reached by an outbound request, or null when it is public. An
 * unparseable string is refused too (fail closed).
 */
export function classifyAddress(ip: string): string | null {
  return classify(ip)?.reason ?? null;
}

// --- host names and the allowlist ----------------------------------------------------------------

const METADATA_NAMES = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
  "instance-data",
  "instance-data.ec2.internal",
]);

function bareHost(u: URL): string {
  return u.hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
}

function isLocalhostName(host: string): boolean {
  return host === "localhost" || host.endsWith(".localhost");
}

/** Names refused without asking DNS. */
function nameVerdict(host: string): string | null {
  if (isLocalhostName(host)) return "a loopback host name";
  if (METADATA_NAMES.has(host)) return "a cloud metadata host name";
  return null;
}

/**
 * Validate and normalise one `allow_private` entry: a bare host name or IP address, compared exactly
 * (no scheme, port, path, wildcard or CIDR). Decimal and hex IPv4 spellings, bracketed IPv6, case and
 * a trailing dot collapse to what a request URL will carry.
 */
export function parseAllowEntry(entry: unknown): { host: string } | { error: string } {
  if (typeof entry !== "string") return { error: "must be a string" };
  const raw = entry.trim();
  if (!raw) return { error: "must not be empty" };
  if (/[\s/\\@?#*]/.test(raw) || raw.includes("://")) {
    return { error: "must be a bare host name or IP address (no scheme, path, wildcard, CIDR or credentials)" };
  }
  let h = raw;
  if (h.startsWith("[")) {
    if (!h.endsWith("]")) return { error: "must not include a port; list the host only" };
    h = h.slice(1, -1);
    if (!net.isIPv6(h)) return { error: "is not a valid IPv6 address" };
  } else if (!net.isIPv6(h) && h.includes(":")) {
    return { error: "must not include a port; list the host only" };
  }
  if (h.includes("[") || h.includes("]")) return { error: "is not a valid host name or IP address" };
  let host: string;
  try {
    host = new URL(`http://${net.isIPv6(h) ? `[${h}]` : h}/`).hostname;
  } catch {
    return { error: "is not a valid host name or IP address" };
  }
  host = host.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
  return host ? { host } : { error: "is not a valid host name or IP address" };
}

interface Effective {
  allow: Set<string>;
  timeoutMs: number;
  maxBytes: number;
}

function settingsOf(src: NetworkSource): NetworkSettings {
  try {
    return (typeof src === "function" ? src() : src) ?? {};
  } catch {
    return {};
  }
}

const positive = (n: unknown): n is number => typeof n === "number" && Number.isFinite(n) && n > 0;

function effective(src: NetworkSource, init: GuardedInit): Effective {
  const s = settingsOf(src);
  const allow = new Set<string>();
  for (const entry of Array.isArray(s.allow_private) ? s.allow_private : []) {
    const p = parseAllowEntry(entry);
    if ("host" in p) allow.add(p.host);
  }
  return {
    allow,
    timeoutMs: positive(init.timeoutMs) ? init.timeoutMs : positive(s.timeout_ms) ? s.timeout_ms : DEFAULT_TIMEOUT_MS,
    maxBytes: positive(init.maxBytes) ? init.maxBytes : positive(s.max_response_bytes) ? s.max_response_bytes : DEFAULT_MAX_RESPONSE_BYTES,
  };
}

// --- resolution and the test seam ----------------------------------------------------------------

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}
export type Resolver = (host: string) => Promise<ResolvedAddress[]>;

const systemResolver: Resolver = async (host) => {
  const out = await dns.promises.lookup(host, { all: true, verbatim: true });
  return out.map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 }));
};

export interface TransportRequest {
  url: URL;
  method: string;
  headers: Record<string, string>;
  /** The body exactly as the caller supplied it. */
  body: string | Uint8Array | URLSearchParams | undefined;
  /** The validated addresses the connection must use. */
  addresses: ResolvedAddress[];
  signal: AbortSignal;
}
export interface TransportResponse {
  status: number;
  statusText: string;
  headers: Headers;
  body: AsyncIterable<Uint8Array> | null;
  destroy(): void;
}
export type Transport = (req: TransportRequest) => Promise<TransportResponse>;

let resolver: Resolver = systemResolver;
let transport: Transport = nodeTransport;

/** Test seam: replace DNS. Pass null to restore the system resolver. */
export function setResolverForTests(r: Resolver | null): void {
  resolver = r ?? systemResolver;
}

type FetchLike = (input: URL, init?: RequestInit) => Promise<Response>;

/**
 * Test seam: route guarded requests through a fetch-shaped function (an oracle's capturing stub) and
 * answer every DNS lookup with a public address unless `answer` says otherwise. Returns a restore
 * function. The guard's own checks (scheme, address classes, redirects, caps) still run.
 */
export function useFetchStubForTests(getFetch: () => unknown, answer?: Resolver): () => void {
  const prevTransport = transport;
  const prevResolver = resolver;
  transport = async (req) => {
    const init: RequestInit = { method: req.method, headers: req.headers, redirect: "manual", signal: req.signal };
    if (req.body !== undefined) init.body = req.body as RequestInit["body"];
    const resp = await (getFetch() as FetchLike)(req.url, init);
    return {
      status: resp.status,
      statusText: resp.statusText,
      headers: resp.headers,
      body: resp.body ? (resp.body as unknown as AsyncIterable<Uint8Array>) : null,
      destroy: () => {
        try {
          void resp.body?.cancel().catch(() => undefined);
        } catch {
          /* stream is locked or already closed */
        }
      },
    };
  };
  resolver = answer ?? (async () => [{ address: "93.184.216.34", family: 4 }]);
  return () => {
    transport = prevTransport;
    resolver = prevResolver;
  };
}

function raceAbort<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener("abort", onAbort);
        resolve(v);
      },
      (e) => {
        signal.removeEventListener("abort", onAbort);
        reject(e);
      },
    );
  });
}

const ALLOW_HINT = (host: string) => `If this target is intended, list the exact host "${host}" in settings.network.allow_private.`;

/**
 * Policy and DNS for one hop. Returns the addresses the connection must use. Throws NetGuardError.
 */
async function authorize(url: URL, eff: Effective, allowLoopback: boolean, signal: AbortSignal): Promise<ResolvedAddress[]> {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new NetGuardError("bad_scheme", `only http: and https: URLs are allowed (got ${url.protocol})`);
  }
  if (url.username || url.password) {
    throw new NetGuardError("invalid_url", "URLs with embedded credentials are not allowed; use the credentials or auth_scheme settings");
  }
  const host = bareHost(url);
  if (!host) throw new NetGuardError("invalid_url", "the URL has no host");
  const allowed = eff.allow.has(host);
  const literal = net.isIP(host) !== 0;

  if (!allowed && !literal) {
    const nv = nameVerdict(host);
    if (nv && !(allowLoopback && isLocalhostName(host))) {
      throw new NetGuardError("blocked_host", `request blocked: ${host} is ${nv}. ${ALLOW_HINT(host)}`);
    }
  }

  let addresses: ResolvedAddress[];
  if (literal) {
    addresses = [{ address: host, family: net.isIPv6(host) ? 6 : 4 }];
  } else {
    try {
      addresses = await raceAbort(resolver(host), signal);
    } catch (e) {
      if (signal.aborted) throw e;
      const code = (e as NodeJS.ErrnoException)?.code ?? (e as Error)?.message ?? "unknown error";
      throw new NetGuardError("dns_failed", `DNS lookup failed for ${host}: ${code}`);
    }
    if (!addresses.length) throw new NetGuardError("dns_failed", `DNS lookup for ${host} returned no addresses`);
  }

  if (!allowed) {
    for (const a of addresses) {
      const v = classify(a.address);
      if (!v) continue;
      if (allowLoopback && v.kind === "loopback") continue;
      const via = literal ? `${host} is` : `${host} resolves to ${a.address}, which is`;
      throw new NetGuardError("blocked_address", `request blocked: ${via} ${v.reason}. ${ALLOW_HINT(host)}`);
    }
  }
  return addresses;
}

/**
 * Check that a URL may be requested (scheme, host, DNS answers) without requesting it. Throws
 * NetGuardError when it may not.
 */
export async function assertUrlAllowed(
  input: string | URL,
  network?: NetworkSource,
  opts: { allowLoopback?: boolean } = {},
): Promise<void> {
  const url = parseUrl(input);
  await authorize(url, effective(network, {}), opts.allowLoopback === true, new AbortController().signal);
}

// --- the pinned node transport -------------------------------------------------------------------

function toBytes(body: string | Uint8Array | URLSearchParams): Buffer {
  if (typeof body === "string") return Buffer.from(body, "utf8");
  if (body instanceof URLSearchParams) return Buffer.from(body.toString(), "utf8");
  return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
}

function pinnedLookup(addresses: ResolvedAddress[]) {
  return (
    _hostname: string,
    options: dns.LookupOptions | number | undefined,
    cb: (err: NodeJS.ErrnoException | null, address?: string | dns.LookupAddress[], family?: number) => void,
  ): void => {
    const opts = typeof options === "object" && options ? options : {};
    const want = opts.family === 4 || opts.family === 6 ? opts.family : 0;
    const usable = addresses.filter((a) => want === 0 || a.family === want);
    if (!usable.length) {
      const err: NodeJS.ErrnoException = new Error("no validated address of the requested family");
      err.code = "ENOTFOUND";
      return cb(err);
    }
    if (opts.all) return cb(null, usable.map((a) => ({ address: a.address, family: a.family })));
    cb(null, usable[0].address, usable[0].family);
  };
}

const HOP_HEADERS = new Set(["host", "content-length", "transfer-encoding", "connection"]);

function nodeTransport(req: TransportRequest): Promise<TransportResponse> {
  return new Promise<TransportResponse>((resolve, reject) => {
    const { url, signal } = req;
    if (signal.aborted) return reject(signal.reason);
    const secure = url.protocol === "https:";
    const hostname = bareHost(url);
    const bytes = req.body === undefined ? undefined : toBytes(req.body);

    const headers: Record<string, string> = {};
    const seen = new Set<string>();
    for (const [k, v] of Object.entries(req.headers)) {
      const lower = k.toLowerCase();
      if (HOP_HEADERS.has(lower)) continue;
      headers[k] = v;
      seen.add(lower);
    }
    if (!seen.has("user-agent")) headers["user-agent"] = "mcp-switchboard";
    if (!seen.has("accept")) headers.accept = "*/*";
    if (!seen.has("accept-encoding")) headers["accept-encoding"] = "gzip, deflate, br";
    headers.host = url.host;
    headers.connection = "close";
    if (bytes) headers["content-length"] = String(bytes.length);
    else if (req.method === "POST" || req.method === "PUT" || req.method === "PATCH") headers["content-length"] = "0";

    const options: https.RequestOptions = {
      protocol: url.protocol,
      hostname,
      port: url.port || (secure ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      method: req.method,
      headers,
      agent: false,
      lookup: pinnedLookup(req.addresses) as unknown as net.LookupFunction,
    };
    if (secure && net.isIP(hostname) === 0) options.servername = hostname;

    let settled = false;
    const request = (secure ? https : http).request(options, (res) => {
      settled = true;
      signal.removeEventListener("abort", onAbort);
      const out = decodeBody(res);
      if ("error" in out) {
        res.destroy();
        request.destroy();
        return reject(out.error);
      }
      const hdrs = new Headers();
      for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) {
        const name = res.rawHeaders[i];
        if (out.decoded && /^content-(encoding|length)$/i.test(name)) continue;
        try {
          hdrs.append(name, res.rawHeaders[i + 1]);
        } catch {
          /* a header the Headers class refuses is not one we need */
        }
      }
      const gone = () => {
        res.destroy();
        request.destroy();
      };
      signal.addEventListener("abort", gone, { once: true });
      resolve({
        status: res.statusCode ?? 0,
        statusText: res.statusMessage ?? "",
        headers: hdrs,
        body: out.stream as unknown as AsyncIterable<Uint8Array>,
        destroy: gone,
      });
    });
    const onAbort = () => request.destroy(signal.reason instanceof Error ? signal.reason : new Error("aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    request.on("error", (err) => {
      signal.removeEventListener("abort", onAbort);
      if (!settled) reject(err);
    });
    request.end(bytes);
  });
}

/** Wrap a response in the decoders its Content-Encoding names (gzip, deflate, br). */
function decodeBody(res: http.IncomingMessage): { stream: Readable; decoded: boolean } | { error: Error } {
  const raw = String(res.headers["content-encoding"] ?? "").toLowerCase();
  const tokens = raw.split(",").map((t) => t.trim()).filter((t) => t && t !== "identity");
  if (!tokens.length) return { stream: res, decoded: false };
  const stages: NodeJS.ReadWriteStream[] = [];
  for (const token of tokens.reverse()) {
    if (token === "gzip" || token === "x-gzip") stages.push(zlib.createGunzip());
    else if (token === "deflate") stages.push(zlib.createInflate());
    else if (token === "br") stages.push(zlib.createBrotliDecompress());
    else return { error: new NetGuardError("bad_encoding", `unsupported Content-Encoding "${token}"`) };
  }
  const last = (pipeline as (...a: unknown[]) => unknown)(res, ...stages, () => undefined) as Readable;
  return { stream: last, decoded: true };
}

// --- guardedFetch --------------------------------------------------------------------------------

export interface GuardedInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array | URLSearchParams;
  /** Caller cancellation. */
  signal?: AbortSignal;
  /** Overall deadline in ms; overrides settings.network.timeout_ms. */
  timeoutMs?: number;
  /** Decoded body cap in bytes; overrides settings.network.max_response_bytes. */
  maxBytes?: number;
  /** Extra header names (any case) that carry credentials and must not cross an origin change. */
  credentialHeaders?: string[];
  /** Explicit local probe: loopback targets pass without an allow_private entry. Nothing else does. */
  allowLoopback?: boolean;
  /** `manual` hands a 3xx back to the caller unfollowed (the MCP SDK applies its own redirect policy and calls again). */
  redirect?: "follow" | "manual";
}

export interface GuardedResponse {
  readonly status: number;
  readonly statusText: string;
  readonly ok: boolean;
  readonly headers: Headers;
  /** The URL of the final response (after redirects). */
  readonly url: string;
  readonly redirected: boolean;
  text(): Promise<string>;
  json(): Promise<any>;
  /** The decoded body as bytes (file downloads), already bounded by the response cap. */
  bytes(): Promise<Uint8Array>;
}

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);
const BODY_HEADERS = new Set(["content-type", "content-length", "content-encoding", "content-language", "content-location"]);
const CREDENTIAL_NAME = /(token|secret|passw|credential|signature|api[-_]?key|auth)/i;

function isCredentialHeader(name: string, extra: Set<string>): boolean {
  const lower = name.toLowerCase();
  return extra.has(lower) || lower === "cookie" || CREDENTIAL_NAME.test(lower);
}

function parseUrl(input: string | URL): URL {
  try {
    return input instanceof URL ? new URL(input.href) : new URL(String(input));
  } catch {
    throw new NetGuardError("invalid_url", "the URL could not be parsed");
  }
}

/** origin + path without the query string, safe to put in an error message. */
const where = (u: URL) => `${u.origin}${u.pathname}`;

async function readBody(resp: TransportResponse, max: number, signal: AbortSignal): Promise<Buffer> {
  const declared = Number(resp.headers.get("content-length"));
  if (!resp.headers.get("content-encoding") && Number.isFinite(declared) && declared > max) {
    resp.destroy();
    throw new NetGuardError("too_large", `response is ${declared} bytes, over the ${max} byte limit (settings.network.max_response_bytes)`);
  }
  if (!resp.body) return Buffer.alloc(0);
  const onAbort = () => resp.destroy();
  signal.addEventListener("abort", onAbort, { once: true });
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for await (const chunk of resp.body) {
      total += chunk.byteLength;
      if (total > max) {
        resp.destroy();
        throw new NetGuardError("too_large", `response body passed the ${max} byte limit (settings.network.max_response_bytes)`);
      }
      chunks.push(Buffer.from(chunk));
    }
  } catch (e) {
    resp.destroy();
    throw e;
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
  return Buffer.concat(chunks, total);
}

/**
 * The only way the gateway makes an outbound HTTP request. Resolves to a small fetch-like response;
 * rejects with {@link NetGuardError} for every refusal, or with the transport's own error (connection
 * refused, TLS failure) for network problems.
 */
export async function guardedFetch(input: string | URL, init: GuardedInit = {}, network?: NetworkSource): Promise<GuardedResponse> {
  const eff = effective(network, init);
  const ctrl = new AbortController();
  const timer = setTimeout(
    () => ctrl.abort(new NetGuardError("timeout", `request timed out after ${eff.timeoutMs} ms (settings.network.timeout_ms)`)),
    eff.timeoutMs,
  );
  const onCaller = () => ctrl.abort(new NetGuardError("aborted", "request aborted by the caller"));
  if (init.signal) {
    if (init.signal.aborted) onCaller();
    else init.signal.addEventListener("abort", onCaller, { once: true });
  }
  try {
    return (await run(parseUrl(input), init, eff, ctrl.signal, false)) as GuardedResponse;
  } catch (e) {
    if (ctrl.signal.aborted) {
      const r = ctrl.signal.reason;
      throw r instanceof Error ? r : new NetGuardError("aborted", "request aborted");
    }
    throw e;
  } finally {
    clearTimeout(timer);
    init.signal?.removeEventListener("abort", onCaller);
  }
}

/** What the streaming path hands back: the response head, and the still-open body for the caller to read. */
interface StreamedResponse extends GuardedResponse {
  raw: TransportResponse;
}

/**
 * One guarded request with redirects. `stream` false reads and caps the whole body (guardedFetch). `stream` true
 * returns as soon as the head arrives and leaves the body open (guardedMcpFetch): the caller owns reading it and
 * cancelling it, and the abort signal still destroys the connection.
 */
async function run(first: URL, init: GuardedInit, eff: Effective, signal: AbortSignal, stream: boolean): Promise<GuardedResponse | StreamedResponse> {
  let url = first;
  let method = (init.method ?? "GET").toUpperCase();
  let body = init.body;
  let headers: Record<string, string> = { ...(init.headers ?? {}) };
  const extraCred = new Set((init.credentialHeaders ?? []).map((h) => h.toLowerCase()));
  let redirected = false;

  for (let hop = 0; ; hop++) {
    let addresses: ResolvedAddress[];
    try {
      addresses = await authorize(url, eff, init.allowLoopback === true, signal);
    } catch (e) {
      if (hop > 0 && e instanceof NetGuardError) throw new NetGuardError(e.code, `redirect to ${where(url)} refused: ${e.message}`);
      throw e;
    }

    const resp = await transport({ url, method, headers, body, addresses, signal });
    const location = resp.headers.get("location");
    if (REDIRECT_STATUS.has(resp.status) && location && init.redirect !== "manual") {
      resp.destroy();
      if (hop >= MAX_REDIRECTS) throw new NetGuardError("redirect_limit", `more than ${MAX_REDIRECTS} redirects, giving up at ${where(url)}`);
      let next: URL;
      try {
        next = new URL(location, url);
      } catch {
        throw new NetGuardError("invalid_url", `redirect from ${where(url)} has an unparseable Location`);
      }
      if (url.protocol === "https:" && next.protocol === "http:") {
        throw new NetGuardError("redirect_blocked", `redirect from ${where(url)} downgrades https to http`);
      }
      const cross = next.origin !== url.origin;
      const toGet = resp.status === 303 ? method !== "GET" && method !== "HEAD" : (resp.status === 301 || resp.status === 302) && method === "POST";
      if (toGet) {
        method = "GET";
        body = undefined;
        headers = Object.fromEntries(Object.entries(headers).filter(([k]) => !BODY_HEADERS.has(k.toLowerCase())));
      } else if (body !== undefined && cross) {
        throw new NetGuardError(
          "redirect_blocked",
          `a ${resp.status} redirect from ${where(url)} would re-send the request body to ${next.origin}`,
        );
      }
      if (cross) {
        headers = Object.fromEntries(Object.entries(headers).filter(([k]) => !isCredentialHeader(k, extraCred)));
      }
      url = next;
      redirected = true;
      continue;
    }

    // HEAD, 204 and 304 carry no body even when Content-Length describes the entity: never size-check them.
    const bodyless = method === "HEAD" || resp.status === 204 || resp.status === 304;
    if (stream) {
      if (bodyless) resp.destroy();
      const head: StreamedResponse = {
        status: resp.status,
        statusText: resp.statusText,
        ok: resp.status >= 200 && resp.status < 300,
        headers: resp.headers,
        url: url.href,
        redirected,
        text: async () => "",
        json: async () => ({}),
        // A streamed head carries no buffered body: the caller reads `raw` itself (the MCP transport). No file download uses it.
        bytes: async () => new Uint8Array(0),
        raw: bodyless ? { ...resp, body: null } : resp,
      };
      return head;
    }
    let bytes: Buffer;
    if (bodyless) {
      resp.destroy();
      bytes = Buffer.alloc(0);
    } else {
      bytes = await readBody(resp, eff.maxBytes, signal);
    }
    const status = resp.status;
    const finalUrl = url.href;
    return {
      status,
      statusText: resp.statusText,
      ok: status >= 200 && status < 300,
      headers: resp.headers,
      url: finalUrl,
      redirected,
      text: async () => new TextDecoder().decode(bytes),
      json: async () => JSON.parse(new TextDecoder().decode(bytes)),
      bytes: async () => new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength),
    };
  }
}

// --- guardedMcpFetch -----------------------------------------------------------------------------------------------

/** The fetch shape the MCP SDK's HTTP transport takes (`StreamableHTTPClientTransportOptions.fetch`). */
export type McpFetch = (input: string | URL, init?: RequestInit) => Promise<Response>;

/** The body shapes the SDK transport sends (a JSON string) plus the byte forms; anything else is a caller bug. */
function mcpBody(body: RequestInit["body"] | undefined): string | Uint8Array | URLSearchParams | undefined {
  if (body === undefined || body === null) return undefined;
  if (typeof body === "string" || body instanceof Uint8Array || body instanceof URLSearchParams) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  throw new TypeError("guardedMcpFetch: unsupported request body type");
}

/**
 * A fetch for the MCP SDK's Streamable HTTP client, so a `source: remote` upstream is held to the same rules as
 * every other outbound request (private, loopback and cloud-metadata targets refused unless the exact host is in
 * `settings.network.allow_private`; the connection pinned to the validated address; every redirect hop checked).
 *
 * It differs from {@link guardedFetch} in one way that matters: the response is STREAMED. An MCP reply can be a
 * server-sent event stream that stays open for the whole session, so there is no body cap and no overall
 * deadline. The deadline (`settings.network.timeout_ms`) covers resolution, connect and response headers; after
 * that the body flows until it ends, the caller aborts (the SDK's signal) or the consumer cancels it. Aborting
 * errors the body stream with the abort reason, which the SDK recognises as its own abort.
 *
 * `redirect: "manual"` (what SDK 1.32 asks for) returns the 3xx unfollowed so the SDK can apply its same-origin
 * policy and call again; without it the guard follows up to MAX_REDIRECTS itself, revalidating each hop.
 * `accept-encoding` defaults to identity so an event stream is never held back by a decompressor's buffering.
 */
export function guardedMcpFetch(network?: NetworkSource): McpFetch {
  return async (input, init = {}) => {
    const eff = effective(network, {});
    const ctrl = new AbortController();
    const caller = init.signal ?? undefined;
    const onCaller = () => ctrl.abort(caller?.reason instanceof Error ? caller.reason : new NetGuardError("aborted", "request aborted by the caller"));
    const detach = () => caller?.removeEventListener("abort", onCaller);
    if (caller) {
      if (caller.aborted) onCaller();
      else caller.addEventListener("abort", onCaller, { once: true });
    }
    const timer = setTimeout(
      () => ctrl.abort(new NetGuardError("timeout", `no response headers after ${eff.timeoutMs} ms (settings.network.timeout_ms)`)),
      eff.timeoutMs,
    );
    const headers = Object.fromEntries(new Headers(init.headers).entries());
    if (!Object.keys(headers).some((h) => h.toLowerCase() === "accept-encoding")) headers["accept-encoding"] = "identity";
    let head: StreamedResponse;
    try {
      head = (await run(
        parseUrl(input),
        { method: init.method, headers, body: mcpBody(init.body), redirect: init.redirect === "manual" ? "manual" : "follow" },
        eff,
        ctrl.signal,
        true,
      )) as StreamedResponse;
    } catch (e) {
      detach();
      if (ctrl.signal.aborted) {
        const r = ctrl.signal.reason;
        throw r instanceof Error ? r : new NetGuardError("aborted", "request aborted");
      }
      throw e;
    } finally {
      clearTimeout(timer);
    }

    const { raw } = head;
    const nullBody = raw.body === null || head.status === 204 || head.status === 205 || head.status === 304;
    let body: ReadableStream<Uint8Array> | null = null;
    if (!nullBody) {
      const it = (raw.body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator]();
      let finished = false;
      const end = () => {
        if (finished) return;
        finished = true;
        detach();
      };
      const reasonOf = (): unknown => (ctrl.signal.reason instanceof Error ? ctrl.signal.reason : new NetGuardError("aborted", "request aborted"));
      body = new ReadableStream<Uint8Array>({
        async pull(controller) {
          try {
            const next = await it.next();
            if (next.done) {
              end();
              controller.close();
              return;
            }
            controller.enqueue(Uint8Array.from(next.value));
          } catch (e) {
            end();
            controller.error(ctrl.signal.aborted ? reasonOf() : e);
          }
        },
        cancel() {
          end();
          raw.destroy();
        },
      });
    } else {
      detach();
      raw.destroy();
    }
    let statusText = head.statusText;
    if (!/^[\t\x20-\x7e\x80-\xff]*$/.test(statusText)) statusText = "";
    return new Response(body, { status: head.status, statusText, headers: head.headers });
  };
}
