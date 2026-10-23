/**
 * The stdio bridge (design 3.12): `switchboard bridge --client <id>`.
 *
 * Every MCP client can launch a stdio command, so one shared HTTP gateway serves them all. The bridge
 * reads newline-delimited JSON-RPC on stdin, POSTs each message to the gateway with the client's bearer
 * key, and writes every JSON-RPC message the gateway returns (plain JSON or an SSE stream) to stdout, one
 * per line. The key comes from SWITCHBOARD_KEY, then `--key-file`, then the client key store
 * (clientkeys.ts), so no token has to sit in a client's config file.
 *
 * Contract:
 *   - stdout carries JSON-RPC lines and nothing else; every diagnostic goes to stderr.
 *   - A request that fails (HTTP error, gateway down, empty answer) gets a JSON-RPC error for its own id,
 *     never a crash. A notification produces no output: it expects 202, anything else is a stderr note.
 *   - Messages are handled concurrently; each answer is written with one write call, so lines never
 *     interleave. When stdin closes the bridge waits for the answers still in flight, then exits 0.
 *   - The token is never logged, echoed or put in an error message.
 *
 * Plain `node:http(s)` instead of `fetch`: no hidden 5 minute header/body timeouts on a slow tool call,
 * no redirect following, and the key is only ever sent to the exact URL given.
 */

import http from "node:http";
import https from "node:https";
import { readFileSync } from "node:fs";
import { StringDecoder } from "node:string_decoder";
import { clientKeyPath, isValidClientId, readClientKey } from "./clientkeys.js";

export const DEFAULT_BRIDGE_URL = "http://127.0.0.1:8088/mcp";

/** Where a 2026-07-28 style request states its protocol version (in params._meta). */
const META_VERSION_KEY = "io.modelcontextprotocol/protocolVersion";
/** From this protocol version on (SEP-2243), every request and notification names its method in a header. */
const HEADER_ERA = "2026-07-28";
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
/** SEP-2243: only these requests also carry Mcp-Name, mirrored from the named params field. */
const NAME_FIELD = new Map([
  ["tools/call", "name"],
  ["prompts/get", "name"],
  ["resources/read", "uri"],
]);
const ACCEPT = "application/json, text/event-stream";
const TOKEN_RE = /^[\x21-\x7e]+$/;
/** Visible ASCII with no leading or trailing space: safe as a plain header value. */
const PLAIN_HEADER_RE = /^[\x21-\x7e]([\x20-\x7e]*[\x21-\x7e])?$/;
const ERR_BRIDGE = -32000;
const ERR_PARSE = -32700;
const ERR_INVALID_REQUEST = -32600;

type JsonObject = Record<string, unknown>;
type RpcId = string | number | null;

export interface BridgeOptions {
  /** The registered client this bridge speaks for. */
  clientId: string;
  /** The gateway's /mcp endpoint. Defaults to DEFAULT_BRIDGE_URL. */
  url?: string;
  /** A plain-text file holding the bearer token. */
  keyFile?: string;
  env?: NodeJS.ProcessEnv;
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
}

const isObject = (v: unknown): v is JsonObject => typeof v === "object" && v !== null && !Array.isArray(v);
const isRequest = (m: JsonObject): boolean => typeof m.method === "string" && m.id !== undefined && m.id !== null;
const isResponse = (m: JsonObject): boolean => m.method === undefined && m.id !== undefined && m.id !== null && ("result" in m || "error" in m);
const idKey = (id: unknown): string => `${typeof id}:${String(id)}`;

/** Incremental text/event-stream decoder: feed text, get the data payload of each completed message event. */
class SseDecoder {
  private buf = "";
  private event = "";
  private data: string[] = [];

  push(text: string): string[] {
    this.buf += text;
    // A trailing CR may be the first half of CRLF: keep it for the next chunk.
    const hold = this.buf.endsWith("\r") ? 1 : 0;
    const parts = this.buf.slice(0, this.buf.length - hold).split(/\r\n|\r|\n/);
    this.buf = parts.pop()! + this.buf.slice(this.buf.length - hold);
    const out: string[] = [];
    for (const line of parts) {
      if (line === "") {
        if (this.data.length > 0 && (this.event === "" || this.event === "message")) out.push(this.data.join("\n"));
        this.data = [];
        this.event = "";
        continue;
      }
      if (line.startsWith(":")) continue;
      const i = line.indexOf(":");
      const field = i === -1 ? line : line.slice(0, i);
      let value = i === -1 ? "" : line.slice(i + 1);
      if (value.startsWith(" ")) value = value.slice(1);
      if (field === "data") this.data.push(value);
      else if (field === "event") this.event = value;
    }
    return out;
  }

  /** The stream ended: terminate a held CR. An event without its blank line is dropped, as the spec says. */
  end(): string[] {
    return this.push("\n");
  }
}

function post(target: URL, headers: Record<string, string>, body: string): Promise<http.IncomingMessage> {
  return new Promise((resolve, reject) => {
    const lib = target.protocol === "https:" ? https : http;
    // agent: false, a fresh connection per message: no stale keep-alive socket can be reused after the
    // gateway closed it, and nothing here keeps the process alive.
    const req = lib.request(target, { method: "POST", agent: false, headers: { ...headers, "Content-Length": String(Buffer.byteLength(body)) } }, resolve);
    req.once("error", reject);
    req.end(body);
  });
}

/** Read a response body; keeps at most `cap` bytes but always drains the rest. Never throws. */
async function readText(res: http.IncomingMessage, cap = Infinity): Promise<string> {
  const parts: Buffer[] = [];
  let n = 0;
  try {
    for await (const chunk of res) {
      const b = chunk as Buffer;
      if (n < cap) {
        parts.push(b.subarray(0, cap - n));
        n += b.length;
      }
    }
  } catch {
    /* a body cut short is handled by whoever parses it */
  }
  return Buffer.concat(parts).toString("utf8");
}

function errCode(err: unknown): string | undefined {
  const e = err as { code?: unknown; errors?: unknown[]; cause?: unknown } | null;
  if (typeof e?.code === "string") return e.code;
  for (const sub of Array.isArray(e?.errors) ? e.errors : []) {
    const c = errCode(sub);
    if (c) return c;
  }
  return e?.cause ? errCode(e.cause) : undefined;
}

function bodyDetail(text: string): string {
  try {
    const j = JSON.parse(text) as { error?: unknown; message?: unknown };
    if (typeof j.error === "string") return j.error;
    if (isObject(j.error) && typeof j.error.message === "string") return j.error.message;
    if (typeof j.message === "string") return j.message;
  } catch {
    /* not JSON */
  }
  if (/^\s*</.test(text)) return "";
  return text.replace(/\s+/g, " ").trim().slice(0, 200);
}

/** A header value that is always legal: plain when it can be, else the `=?base64?...?=` form SEP-2243 uses. */
function headerValue(v: string): string {
  const sentinel = v.startsWith("=?base64?") && v.endsWith("?=");
  return PLAIN_HEADER_RE.test(v) && !sentinel ? v : `=?base64?${Buffer.from(v, "utf8").toString("base64")}?=`;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "[::1]" || hostname.startsWith("127.");
}

class KeyError extends Error {}

function resolveKey(opts: { clientId: string; keyFile?: string; env: NodeJS.ProcessEnv }): { key: string; source: string } {
  const accept = (raw: string, source: string) => {
    const key = raw.replace(/^\uFEFF/, "").trim();
    if (!TOKEN_RE.test(key)) throw new KeyError(`the key from ${source} is empty or contains whitespace or non-ASCII characters`);
    return { key, source };
  };
  const fromEnv = (opts.env.SWITCHBOARD_KEY ?? "").trim();
  if (fromEnv) return accept(fromEnv, "SWITCHBOARD_KEY");
  if (opts.keyFile) {
    let text: string;
    try {
      text = readFileSync(opts.keyFile, "utf8");
    } catch (err) {
      throw new KeyError(`cannot read --key-file ${opts.keyFile} (${errCode(err) ?? "read error"})`);
    }
    return accept(text, "--key-file");
  }
  let stored: string | null;
  try {
    stored = readClientKey(opts.clientId);
  } catch (err) {
    throw new KeyError(err instanceof Error ? err.message : "cannot read the stored client key");
  }
  if (stored !== null) return { key: stored, source: "the client key store" };
  throw new KeyError(
    `no key for client '${opts.clientId}'. Set SWITCHBOARD_KEY, pass --key-file <path>, or register the client with ` +
      `\`switchboard client add ${opts.clientId}\` (it stores the key at ${clientKeyPath(opts.clientId)}).`,
  );
}

/** Run the bridge until stdin closes. Resolves with the process exit code (0 clean, 2 bad arguments). */
export async function runBridge(opts: BridgeOptions): Promise<number> {
  const env = opts.env ?? process.env;
  const input = opts.input ?? process.stdin;
  const output = opts.output ?? process.stdout;
  const errOut = opts.stderr ?? process.stderr;
  let secret = "";
  const scrub = (s: string) => (secret ? s.split(secret).join("[redacted]") : s);
  const diag = (m: string) => void errOut.write(`switchboard bridge: ${scrub(m)}\n`);

  if (!isValidClientId(opts.clientId)) {
    diag("invalid client id: use 1 to 64 characters from a-z, 0-9, '-' and '_', starting with a letter or digit");
    return 2;
  }
  const clientId = opts.clientId;
  let target: URL;
  try {
    target = new URL(opts.url ?? DEFAULT_BRIDGE_URL);
  } catch {
    diag("invalid --url: expected an absolute http or https URL");
    return 2;
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    diag("invalid --url: the scheme must be http or https");
    return 2;
  }
  if (target.username || target.password) {
    diag("invalid --url: it must not contain credentials; the key is sent as a bearer header");
    return 2;
  }
  const shownUrl = `${target.protocol}//${target.host}${target.pathname}`;
  if (target.protocol === "http:" && !isLoopbackHost(target.hostname)) {
    diag(`warning: ${shownUrl} is plain http to a non-loopback host; the key travels unencrypted`);
  }

  let key = "";
  let keySource = "";
  let keyError: string | null = null;
  try {
    ({ key, source: keySource } = resolveKey({ clientId, keyFile: opts.keyFile, env }));
    secret = key;
  } catch (err) {
    keyError = err instanceof Error ? err.message : "cannot resolve the key";
    diag(keyError);
  }

  let outputBroken = false;
  output.on("error", () => {
    outputBroken = true;
  });
  const writeMessage = (m: unknown) => {
    if (!outputBroken) output.write(JSON.stringify(m) + "\n");
  };
  const errorFor = (id: RpcId, message: string, code = ERR_BRIDGE) => ({ jsonrpc: "2.0", id, error: { code, message: scrub(message) } });

  let protocolVersion: string | undefined;

  const failureText = (status: number, text: string): string => {
    const detail = bodyDetail(text);
    const suffix = detail ? `: ${detail}` : "";
    if (status === 401) {
      return (
        `Switchboard rejected the key (HTTP 401): the key is invalid or client '${clientId}' is not registered ` +
        `(key from ${keySource}). Register or re-issue it with \`switchboard client add ${clientId}\`.`
      );
    }
    if (status === 403) return `Switchboard refused the request (HTTP 403${suffix}). Check that ${shownUrl} is a host the gateway allows and that client '${clientId}' may use it.`;
    if (status === 404) return `No MCP endpoint at ${shownUrl} (HTTP 404). The URL must point at the gateway's /mcp route.`;
    return `Gateway error at ${shownUrl}: HTTP ${status}${suffix}`;
  };
  const networkText = (err: unknown): string => {
    const code = errCode(err);
    if (code === "ECONNREFUSED") return `Switchboard gateway is not running at ${shownUrl}. Start it with \`switchboard serve\` (or \`switchboard dashboard\`), then retry.`;
    return `Cannot reach the Switchboard gateway at ${shownUrl}: ${code ?? "network error"}.`;
  };

  async function handleLine(line: string): Promise<void> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      diag("dropped a stdin line that is not valid JSON");
      writeMessage(errorFor(null, "Parse error: the line is not valid JSON", ERR_PARSE));
      return;
    }
    const messages = Array.isArray(parsed) ? parsed : [parsed];
    if (messages.length === 0 || !messages.every(isObject)) {
      writeMessage(errorFor(null, "Invalid Request: expected a JSON-RPC message or a non-empty batch of them", ERR_INVALID_REQUEST));
      return;
    }
    const objs = messages as JsonObject[];
    const pending: RpcId[] = objs.filter(isRequest).map((m) => m.id as RpcId);
    const failAll = (message: string) => {
      if (pending.length === 0) diag(message);
      for (const id of pending) writeMessage(errorFor(id, message));
    };
    if (keyError) return failAll(keyError);

    const single = objs.length === 1 ? objs[0] : undefined;
    const isInit = objs.some((m) => m.method === "initialize");
    if (isInit) protocolVersion = undefined;
    const meta = single && isObject(single.params) && isObject(single.params._meta) ? single.params._meta[META_VERSION_KEY] : undefined;
    if (typeof meta === "string" && meta) protocolVersion = meta;

    const headers: Record<string, string> = { Authorization: `Bearer ${key}`, "Content-Type": "application/json", Accept: ACCEPT };
    if (protocolVersion && !isInit) {
      headers["MCP-Protocol-Version"] = protocolVersion;
      if (single && typeof single.method === "string" && DATE_RE.test(protocolVersion) && protocolVersion >= HEADER_ERA) {
        headers["Mcp-Method"] = single.method;
        const field = NAME_FIELD.get(single.method);
        const name = field && isObject(single.params) ? single.params[field] : undefined;
        if (typeof name === "string") headers["Mcp-Name"] = headerValue(name);
      }
    }

    let res: http.IncomingMessage;
    try {
      res = await post(target, headers, line);
    } catch (err) {
      return failAll(networkText(err));
    }
    const status = res.statusCode ?? 0;
    if (status < 200 || status >= 300) return failAll(failureText(status, await readText(res, 65536)));
    if (pending.length === 0) {
      // Notifications and client replies: 202, no output. Drain whatever else comes back.
      await readText(res, 0);
      if (status !== 202) diag(`expected HTTP 202 for a notification, got ${status}`);
      return;
    }

    const answered = new Set<string>();
    const forward = (m: unknown) => {
      if (isObject(m)) {
        if (isResponse(m)) answered.add(idKey(m.id));
        if (isInit && isResponse(m) && isObject(m.result) && typeof m.result.protocolVersion === "string") protocolVersion = m.result.protocolVersion;
      }
      writeMessage(m);
    };
    const forwardJson = (text: string) => {
      let value: unknown;
      try {
        value = JSON.parse(text);
      } catch {
        diag("dropped a gateway message that is not valid JSON");
        return;
      }
      for (const m of Array.isArray(value) ? value : [value]) forward(m);
    };

    const ctype = String(res.headers["content-type"] ?? "").toLowerCase();
    let streamError: unknown;
    if (ctype.includes("text/event-stream")) {
      const sse = new SseDecoder();
      const decoder = new StringDecoder("utf8");
      try {
        for await (const chunk of res) for (const data of sse.push(decoder.write(chunk as Buffer))) forwardJson(data);
        for (const data of sse.push(decoder.end())) forwardJson(data);
        for (const data of sse.end()) forwardJson(data);
      } catch (err) {
        streamError = err;
      }
    } else if (ctype.includes("application/json")) {
      const text = await readText(res);
      if (text.trim()) forwardJson(text);
    } else if ((await readText(res, 65536)).trim() !== "") {
      return failAll(`Gateway at ${shownUrl} answered HTTP ${status} with an unexpected content type '${ctype || "none"}'`);
    }
    for (const id of pending) {
      if (answered.has(idKey(id))) continue;
      writeMessage(
        errorFor(
          id,
          streamError
            ? `The connection to ${shownUrl} broke before request ${String(id)} was answered (${errCode(streamError) ?? "network error"}).`
            : `Gateway returned no response for request ${String(id)} (HTTP ${status}).`,
        ),
      );
    }
  }

  const inflight = new Set<Promise<void>>();
  const dispatch = (line: string) => {
    const p: Promise<void> = handleLine(line)
      .catch((err) => diag(`internal error while relaying a message: ${err instanceof Error ? err.message : String(err)}`))
      .finally(() => inflight.delete(p));
    inflight.add(p);
  };

  await new Promise<void>((resolve) => {
    const decoder = new StringDecoder("utf8");
    let pieces: string[] = [];
    let first = true;
    let done = false;
    const emit = (raw: string) => {
      let line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
      if (first) {
        line = line.replace(/^\uFEFF/, "");
        first = false;
      }
      if (line.trim() !== "") dispatch(line);
    };
    const finish = () => {
      if (done) return;
      done = true;
      const rest = pieces.join("") + decoder.end();
      pieces = [];
      if (rest !== "") emit(rest);
      resolve();
    };
    input.on("data", (chunk: Buffer | string) => {
      const text = typeof chunk === "string" ? chunk : decoder.write(chunk);
      let start = 0;
      for (;;) {
        const nl = text.indexOf("\n", start);
        if (nl === -1) {
          if (start < text.length) pieces.push(text.slice(start));
          return;
        }
        pieces.push(text.slice(start, nl));
        const line = pieces.join("");
        pieces = [];
        emit(line);
        start = nl + 1;
      }
    });
    input.on("end", finish);
    input.on("close", finish);
    input.on("error", finish);
  });

  while (inflight.size > 0) await Promise.allSettled([...inflight]);
  if (!outputBroken) await new Promise<void>((r) => output.write("", () => r()));
  return 0;
}
