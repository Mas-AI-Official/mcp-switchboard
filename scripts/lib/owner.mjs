// Shared by the oracles that drive a gateway's admin API in this process. Signing in is the one step the design
// puts behind the gateway's own owner-presence check (3.2, 3.15): the oracle asks the control API for a login code
// the way `switchboard dashboard login` does, then redeems it. Nothing here can mint a code without the gateway
// (the old oracles wrote login-codes/ files, which the gateway no longer reads).
//
// Presence stays under the oracle's control and is NEVER real: a gateway built with an injected presence provider
// uses it; a gateway with the default provider sees SWITCHBOARD_INSECURE_APPROVAL=1 (presence "none"), which this
// helper sets only for the duration of the request that needs it.
import http from "node:http";

/** Raw loopback HTTP that never rejects: a failure is status 0. */
export function loopback(port, method, path, { headers = {}, body, host } = {}) {
  return new Promise((resolve) => {
    const h = { Host: host ?? `127.0.0.1:${port}`, ...headers };
    for (const k of Object.keys(h)) if (h[k] === undefined) delete h[k];
    let data;
    if (body !== undefined) {
      data = typeof body === "string" ? body : JSON.stringify(body);
      h["Content-Length"] = Buffer.byteLength(data);
      if (!Object.keys(h).some((k) => k.toLowerCase() === "content-type")) h["Content-Type"] = "application/json";
    }
    const req = http.request({ host: "127.0.0.1", port, method, path, headers: h, agent: false }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", (err) => resolve({ status: 0, headers: {}, body: "", error: String(err.message) }));
    req.setTimeout(30_000, () => req.destroy(new Error(`timeout ${method} ${path}`)));
    if (data !== undefined) req.write(data);
    req.end();
  });
}

const jsonOf = (r) => {
  try {
    return JSON.parse(r.body);
  } catch {
    return {};
  }
};

/** The control token of the gateway started in this process (read from the isolated SWITCHBOARD_HOME). */
export async function controlHeaders() {
  const { readControlKey } = await import(new URL("../../dist/controlkey.js", import.meta.url).href);
  return { authorization: `Bearer ${readControlKey()}` };
}

/** Ask the gateway to mint a login code (its presence check runs first). `code` is null when it refused. */
export async function mintLoginCode(port, { host } = {}) {
  const prev = process.env.SWITCHBOARD_INSECURE_APPROVAL;
  process.env.SWITCHBOARD_INSECURE_APPROVAL = "1";
  try {
    const r = await loopback(port, "POST", "/api/control/login", { headers: await controlHeaders(), body: {}, host });
    return { status: r.status, code: typeof jsonOf(r).expires_in === "number" ? jsonOf(r).code : null, response: r };
  } finally {
    if (prev === undefined) delete process.env.SWITCHBOARD_INSECURE_APPROVAL;
    else process.env.SWITCHBOARD_INSECURE_APPROVAL = prev;
  }
}

/** Sign the owner in. `hdr` carries the session header, `hdrC` the session and CSRF headers (mutating calls). */
export async function ownerSession(port, { host, code } = {}) {
  const minted = code === undefined ? await mintLoginCode(port, { host }) : { code };
  const exchange = await loopback(port, "POST", "/api/session", { body: { code: minted.code }, host });
  const b = jsonOf(exchange);
  const sid = typeof b.session === "string" ? b.session : "";
  const csrf = typeof b.csrf === "string" ? b.csrf : "";
  return {
    status: exchange.status,
    sid,
    csrf,
    body: b,
    response: exchange,
    setCookie: exchange.headers["set-cookie"],
    hdr: sid ? { "x-switchboard-session": sid } : {},
    hdrC: sid ? { "x-switchboard-session": sid, "x-switchboard-csrf": csrf } : {},
  };
}
