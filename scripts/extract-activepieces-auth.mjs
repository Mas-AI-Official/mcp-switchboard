#!/usr/bin/env node
/**
 * Static extractor: Activepieces community pieces -> candidate Switchboard ProviderDefs ("seeds").
 *
 *   node scripts/extract-activepieces-auth.mjs --checkout <dir> --out src/connectors/providers/seed [--commit <sha>] [--dry-run]
 *
 * `--checkout` is a (sparse, shallow) clone of github.com/activepieces/activepieces holding LICENSE and
 * packages/pieces/community/<piece>/{package.json,src}. The extractor treats that tree as untrusted DATA:
 *
 *   - it only PARSES the TypeScript (ts.createSourceFile, no Program, no type checker, no module loading),
 *     so no piece code ever runs, and it never follows an import out of the piece's own `src` directory;
 *   - it reads each piece's auth definition (PieceAuth.OAuth2 authUrl, tokenUrl, scope, pkce, extra,
 *     grantType, authorizationMethod, props; PieceAuth.SecretText; PieceAuth.BasicAuth; PieceAuth.CustomAuth
 *     props) with a small constant evaluator (string literals, templates, same-module and relative-import
 *     consts, arrays, objects, spreads). Anything it cannot resolve statically is left out and counted;
 *   - it copies FACTS only: URLs, scope names, field names, a product name. Never a description, a label
 *     or a line of code. Every string it writes comes from this script's own templates or from those facts.
 *
 * What a seed is: a ProviderDef plus `source` and `verification: "unverified_seed"`. A seed enables the
 * Connect flow and nothing more; it is never counted as working (see src/connectors/providers.ts). Values the
 * source does not state (client authentication placement, the scope separator, redirect kind, refresh
 * rotation, how an API key is injected) are ASSUMED and said so in the seed's notes. `api_hosts` are
 * candidates harvested from URL literals in the piece, or the token host when a piece has none.
 *
 * Output is deterministic: no timestamps, sorted keys' insertion order, stable ordering of files and hosts.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import ts from "typescript";

export const EXTRACTOR_VERSION = 1;
const REPO_URL = "https://github.com/activepieces/activepieces";

// ── secret-shaped strings: nothing that looks like one is ever written ────────────────────────────────
export const SECRET_SHAPES = [
  /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bAIza[0-9A-Za-z_-]{30,}/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
  /\b[A-Fa-f0-9]{32,}\b/,
  /(?<![A-Za-z0-9+/=_-])(?=[A-Za-z0-9+/=_-]*[0-9])(?=[A-Za-z0-9+/=_-]*[a-z])(?=[A-Za-z0-9+/=_-]*[A-Z])[A-Za-z0-9+/=_-]{40,}(?![A-Za-z0-9+/=_-])/,
];
export const looksSecret = (s) => SECRET_SHAPES.some((re) => re.test(String(s)));

const UNRES = Symbol("unresolved");
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
/** A plain evaluated object (not an auth call, a property call, an enum member, a template or a namespace). */
const isPlain = (v) => isObj(v) && v.$auth === undefined && v.$prop === undefined && v.$enum === undefined && v.$tmpl === undefined && v.$ns === undefined && v.$external === undefined;

// ── module index: top-level consts, imports, exports of one TypeScript file ────────────────────────────
class PieceProject {
  constructor(srcDir) {
    this.srcDir = resolve(srcDir);
    this.mods = new Map();
  }
  load(file) {
    const key = resolve(file);
    if (this.mods.has(key)) return this.mods.get(key);
    let mod = null;
    if (key.startsWith(this.srcDir + sep) && existsSync(key)) {
      const text = readFileSync(key, "utf8");
      mod = new Module(this, key, ts.createSourceFile(key, text, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS));
    }
    this.mods.set(key, mod);
    return mod;
  }
  /** A relative import specifier to a file INSIDE this piece's src, or null (never follows `..` out of it). */
  resolveFile(fromFile, spec) {
    if (!spec.startsWith(".")) return null;
    const base = resolve(dirname(fromFile), spec);
    for (const c of [base, `${base}.ts`, `${base}.tsx`, join(base, "index.ts")]) {
      if (c.startsWith(this.srcDir + sep) && existsSync(c) && statSync(c).isFile()) return c;
    }
    return null;
  }
}

const hasExport = (node) => (ts.canHaveModifiers(node) ? ts.getModifiers(node) ?? [] : []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword);

class Module {
  constructor(project, file, sf) {
    this.project = project;
    this.file = file;
    this.sf = sf;
    this.consts = new Map(); // name -> initializer expression
    this.imports = new Map(); // local -> { file, name } | { file, ns: true }
    this.exportsLocal = new Map(); // exported name -> local name
    this.reexports = []; // { file, from, as }
    this.starExports = [];
    for (const st of sf.statements) {
      if (ts.isVariableStatement(st)) {
        for (const d of st.declarationList.declarations) {
          if (ts.isIdentifier(d.name) && d.initializer) {
            this.consts.set(d.name.text, d.initializer);
            if (hasExport(st)) this.exportsLocal.set(d.name.text, d.name.text);
          }
        }
      } else if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier)) {
        const target = project.resolveFile(file, st.moduleSpecifier.text);
        const clause = st.importClause;
        if (!target || !clause) continue;
        if (clause.name) this.imports.set(clause.name.text, { file: target, name: "default" });
        const nb = clause.namedBindings;
        if (nb && ts.isNamedImports(nb)) for (const el of nb.elements) this.imports.set(el.name.text, { file: target, name: (el.propertyName ?? el.name).text });
        else if (nb && ts.isNamespaceImport(nb)) this.imports.set(nb.name.text, { file: target, ns: true });
      } else if (ts.isExportDeclaration(st)) {
        const spec = st.moduleSpecifier && ts.isStringLiteral(st.moduleSpecifier) ? st.moduleSpecifier.text : undefined;
        const target = spec ? project.resolveFile(file, spec) : undefined;
        if (spec && !target) continue;
        if (!st.exportClause) {
          if (target) this.starExports.push(target);
        } else if (ts.isNamedExports(st.exportClause)) {
          for (const el of st.exportClause.elements) {
            if (target) this.reexports.push({ file: target, from: (el.propertyName ?? el.name).text, as: el.name.text });
            else this.exportsLocal.set(el.name.text, (el.propertyName ?? el.name).text);
          }
        }
      } else if (ts.isExportAssignment(st)) {
        this.consts.set("default", st.expression);
        this.exportsLocal.set("default", "default");
      }
    }
  }
}

/** The binding (expression + its module) a module exports under `name`, following re-exports. */
function getExport(project, file, name, seen = new Set()) {
  const key = `${file}::${name}`;
  if (seen.has(key)) return null;
  seen.add(key);
  const mod = project.load(file);
  if (!mod) return null;
  if (mod.exportsLocal.has(name)) {
    const local = mod.exportsLocal.get(name);
    const node = mod.consts.get(local);
    if (node) return { node, mod };
    const imp = mod.imports.get(local);
    if (imp && !imp.ns) return getExport(project, imp.file, imp.name, seen);
  }
  for (const re of mod.reexports) if (re.as === name) return getExport(project, re.file, re.from, seen);
  for (const star of mod.starExports) {
    const r = getExport(project, star, name, seen);
    if (r) return r;
  }
  return null;
}

// ── the constant evaluator ────────────────────────────────────────────────────────────────────────────
const tmpl = (text) => ({ $tmpl: text });
const strOf = (v) => (typeof v === "string" ? v : v && typeof v === "object" && typeof v.$tmpl === "string" ? v.$tmpl : undefined);
const placeholderName = (e) => (ts.isPropertyAccessExpression(e) ? e.name.text : ts.isIdentifier(e) ? e.text : "x");

function propName(p, mod, st) {
  const n = p.name;
  if (ts.isIdentifier(n) || ts.isStringLiteral(n) || ts.isNumericLiteral(n)) return n.text;
  if (ts.isComputedPropertyName(n)) {
    const v = ev(n.expression, mod, st);
    return typeof v === "string" ? v : undefined;
  }
  return undefined;
}

function ev(node, mod, st = { depth: 0, stack: new Set() }) {
  if (!node || st.depth > 40) return UNRES;
  const next = { depth: st.depth + 1, stack: st.stack };
  const K = ts.SyntaxKind;
  switch (node.kind) {
    case K.StringLiteral:
    case K.NoSubstitutionTemplateLiteral:
      return node.text;
    case K.NumericLiteral:
      return Number(node.text);
    case K.TrueKeyword:
      return true;
    case K.FalseKeyword:
      return false;
    case K.NullKeyword:
      return null;
    case K.ParenthesizedExpression:
    case K.AsExpression:
    case K.SatisfiesExpression:
    case K.NonNullExpression:
    case K.TypeAssertionExpression:
      return ev(node.expression, mod, next);
    case K.ArrowFunction:
    case K.FunctionExpression: {
      // `() => 'https://api.example.com'`: a constant thunk. Anything with real logic stays unresolved.
      const b = node.body;
      if (!ts.isBlock(b)) return ev(b, mod, next);
      const ret = b.statements.length === 1 && ts.isReturnStatement(b.statements[0]) ? b.statements[0].expression : undefined;
      return ret ? ev(ret, mod, next) : UNRES;
    }
    case K.TemplateExpression: {
      let text = node.head.text;
      let dynamic = false;
      for (const span of node.templateSpans) {
        const v = ev(span.expression, mod, next);
        const s = strOf(v);
        if (typeof v === "string") text += v;
        else if (s !== undefined) {
          text += s;
          dynamic = true;
        } else {
          text += `{${placeholderName(span.expression)}}`;
          dynamic = true;
        }
        text += span.literal.text;
      }
      return dynamic ? tmpl(text) : text;
    }
    case K.BinaryExpression: {
      if (node.operatorToken.kind !== K.PlusToken) return UNRES;
      const l = ev(node.left, mod, next);
      const r = ev(node.right, mod, next);
      const ls = strOf(l);
      const rs = strOf(r);
      if (ls === undefined || rs === undefined) return UNRES;
      return typeof l === "string" && typeof r === "string" ? ls + rs : tmpl(ls + rs);
    }
    case K.ArrayLiteralExpression: {
      const out = [];
      for (const el of node.elements) {
        if (ts.isSpreadElement(el)) {
          const v = ev(el.expression, mod, next);
          if (Array.isArray(v)) out.push(...v);
          else out.push(UNRES);
        } else out.push(ev(el, mod, next));
      }
      return out;
    }
    case K.ObjectLiteralExpression: {
      const out = Object.create(null);
      for (const p of node.properties) {
        if (ts.isPropertyAssignment(p)) {
          const name = propName(p, mod, next);
          if (name !== undefined) out[name] = ev(p.initializer, mod, next);
        } else if (ts.isShorthandPropertyAssignment(p)) {
          out[p.name.text] = ev(p.name, mod, next);
        } else if (ts.isSpreadAssignment(p)) {
          const v = ev(p.expression, mod, next);
          if (isPlain(v)) Object.assign(out, v);
        }
      }
      return out;
    }
    case K.Identifier:
      return resolveIdentifier(node.text, mod, next);
    case K.PropertyAccessExpression: {
      const obj = ev(node.expression, mod, next);
      if (isObj(obj) && obj.$ns) {
        const b = getExport(mod.project, obj.$ns, node.name.text);
        return b ? evBinding(b, `${obj.$ns}::${node.name.text}`, next) : UNRES;
      }
      if (isObj(obj) && obj.$external) return { $enum: obj.$external, member: node.name.text };
      if (isPlain(obj) && Object.hasOwn(obj, node.name.text)) return obj[node.name.text];
      return UNRES;
    }
    case K.ElementAccessExpression: {
      const obj = ev(node.expression, mod, next);
      const key = ev(node.argumentExpression, mod, next);
      if (isObj(obj) && (typeof key === "string" || typeof key === "number") && Object.hasOwn(obj, String(key))) return obj[String(key)];
      if (Array.isArray(obj) && typeof key === "number") return obj[key] ?? UNRES;
      return UNRES;
    }
    case K.CallExpression: {
      const c = node.expression;
      if (ts.isPropertyAccessExpression(c) && ts.isIdentifier(c.expression)) {
        if (c.expression.text === "PieceAuth") return { $auth: c.name.text, node, mod };
        if (c.expression.text === "Property") return { $prop: c.name.text, node, mod };
      }
      if (ts.isPropertyAccessExpression(c) && c.name.text === "join") {
        const arr = ev(c.expression, mod, next);
        const sep = node.arguments[0] ? ev(node.arguments[0], mod, next) : ",";
        if (Array.isArray(arr) && typeof sep === "string" && arr.every((x) => typeof x === "string")) return arr.join(sep);
      }
      return UNRES;
    }
    default:
      return UNRES;
  }
}

function evBinding(b, key, st) {
  if (st.stack.has(key)) return UNRES;
  st.stack.add(key);
  try {
    return ev(b.node, b.mod, st);
  } finally {
    st.stack.delete(key);
  }
}

function resolveIdentifier(name, mod, st) {
  if (mod.consts.has(name)) return evBinding({ node: mod.consts.get(name), mod }, `${mod.file}::${name}`, st);
  const imp = mod.imports.get(name);
  if (imp) {
    if (imp.ns) return { $ns: imp.file };
    const b = getExport(mod.project, imp.file, imp.name);
    return b ? evBinding(b, `${b.mod.file}::${imp.name}`, st) : UNRES;
  }
  // An import from a package (an enum such as OAuth2GrantType) or a global: only its member names are facts.
  return { $external: name };
}

// ── auth facts ────────────────────────────────────────────────────────────────────────────────────────
const SAFE_URL_PARAM_DROP = /client[_-]?(id|secret|key)|secret|token|password|api[_-]?key|apikey|code|state|signature/i;
const SCOPE_OK = /^[A-Za-z0-9_:./+*@%-]{1,200}$/;
const FIELD_KIND_SKIP = new Set(["MarkDown"]);

const snake = (s) =>
  s
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase();

function enumMember(v) {
  if (v && typeof v === "object" && typeof v.member === "string") return v.member.toLowerCase();
  if (typeof v === "string") return v.toLowerCase();
  return undefined;
}

function argOf(call) {
  const a = call.node.arguments[0];
  if (!a) return Object.create(null);
  const v = ev(a, call.mod);
  return isObj(v) ? v : Object.create(null);
}

function fieldsFrom(propsVal, counters) {
  const out = [];
  if (!isObj(propsVal)) return out;
  for (const [key, v] of Object.entries(propsVal)) {
    const kind = isObj(v) ? v.$prop ?? v.$auth : undefined;
    if (!kind) {
      counters.unresolved_props++;
      continue;
    }
    if (FIELD_KIND_SKIP.has(kind)) continue;
    const name = snake(key);
    if (!/^[a-z][a-z0-9_]*$/.test(name)) {
      counters.unresolved_props++;
      continue;
    }
    out.push({ name, required: argOf(v).required !== false, secret: kind === "SecretText" });
  }
  return out;
}

function cleanScopes(v) {
  // One array element may hold several scopes ("a b c"); split on whitespace and commas.
  const raw = Array.isArray(v) ? v : [v];
  const list = [];
  let dropped = 0;
  for (const el of raw) {
    if (typeof el === "string") list.push(...el.split(/[\s,]+/));
    else if (el !== undefined) dropped++;
  }
  const out = [];
  for (const s of list) {
    const t = s.trim();
    if (!t) continue;
    if (!SCOPE_OK.test(t) || looksSecret(t)) {
      dropped++;
      continue;
    }
    if (!out.includes(t)) out.push(t);
  }
  return { scopes: out, dropped };
}

function cleanExtra(v) {
  const out = {};
  if (!isObj(v)) return out;
  for (const [k, val] of Object.entries(v)) {
    if (typeof val !== "string") continue;
    if (!/^[A-Za-z0-9_.-]{1,40}$/.test(k) || SAFE_URL_PARAM_DROP.test(k)) continue;
    if (!/^[A-Za-z0-9_:./ +,@=-]{0,200}$/.test(val) || looksSecret(val)) continue;
    out[k] = val;
  }
  return out;
}

/** An absolute https URL with credentials and secret-like query parameters removed, or null. */
export function cleanUrl(value) {
  if (typeof value !== "string") return null;
  if (!/^https:\/\/[^\s{}]+$/i.test(value)) return null;
  let u;
  try {
    u = new URL(value);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.username || u.password) return null;
  for (const k of [...u.searchParams.keys()]) if (SAFE_URL_PARAM_DROP.test(k)) u.searchParams.delete(k);
  if (looksSecret(u.pathname) || looksSecret(u.search)) return null;
  u.hash = "";
  return u.toString();
}

function authFacts(call, counters) {
  const arg = argOf(call);
  switch (call.$auth) {
    case "OAuth2": {
      const authUrl = strOf(arg.authUrl);
      const tokenUrl = strOf(arg.tokenUrl);
      const { scopes, dropped } = cleanScopes(arg.scope);
      return {
        kind: "oauth2",
        authUrl,
        tokenUrl,
        authUrlDynamic: authUrl !== undefined && typeof arg.authUrl !== "string",
        tokenUrlDynamic: tokenUrl !== undefined && typeof arg.tokenUrl !== "string",
        scopes,
        scopesDropped: dropped,
        pkce: arg.pkce === true,
        extra: cleanExtra(arg.extra),
        grantType: enumMember(arg.grantType),
        authorizationMethod: enumMember(arg.authorizationMethod),
        fields: fieldsFrom(arg.props, counters),
      };
    }
    case "SecretText":
      return { kind: "secret_text" };
    case "BasicAuth":
      return { kind: "basic" };
    case "CustomAuth":
      return { kind: "custom", fields: fieldsFrom(arg.props, counters) };
    case "OIDC":
      return { kind: "oidc" };
    case "None":
      return { kind: "none" };
    default:
      return { kind: "unknown", name: call.$auth };
  }
}

// ── piece scan ────────────────────────────────────────────────────────────────────────────────────────
function walk(node, fn) {
  fn(node);
  ts.forEachChild(node, (c) => walk(c, fn));
}

function listSrcFiles(dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "__tests__" || e.name === "node_modules") continue;
      listSrcFiles(p, out);
    } else if (/\.tsx?$/.test(e.name) && !/\.(spec|test)\.tsx?$/.test(e.name) && !e.name.endsWith(".d.ts")) out.push(p);
  }
  return out;
}

function findCreatePiece(mod) {
  let found;
  walk(mod.sf, (n) => {
    if (!found && ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "createPiece") found = n;
  });
  return found;
}

function objectProp(objNode, name) {
  if (!objNode || !ts.isObjectLiteralExpression(objNode)) return undefined;
  for (const p of objNode.properties) {
    if (ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) && p.name.text === name) return p.initializer;
    if (ts.isShorthandPropertyAssignment(p) && p.name.text === name) return p.name;
  }
  return undefined;
}

function flattenAuth(v, out = [], seen = new Set()) {
  if (Array.isArray(v)) {
    for (const x of v) flattenAuth(x, out, seen);
  } else if (isObj(v) && v.$auth && !seen.has(v.node)) {
    seen.add(v.node);
    out.push(v);
  }
  return out;
}

/** Top-level PieceAuth calls anywhere in src (never the ones nested inside another auth's props). */
function scanAuths(project, files) {
  const out = [];
  for (const f of files) {
    const mod = project.load(f);
    if (!mod) continue;
    const visit = (n) => {
      if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ts.isIdentifier(n.expression.expression) && n.expression.expression.text === "PieceAuth") {
        out.push({ $auth: n.expression.name.text, node: n, mod });
        return;
      }
      ts.forEachChild(n, visit);
    };
    visit(mod.sf);
  }
  return out;
}

const HOST_PROPS = new Set(["url", "baseurl", "apiurl", "endpoint", "host", "apiendpoint", "baseuri", "serverurl", "apihost", "apibaseurl", "baseendpoint", "rooturl", "resturl"]);
const HOST_VAR = /(^|[_-])(url|uri|host|endpoint|domain)$|(url|uri|host|endpoint)$/i;
const HOST_VAR_DROP = /auth|token|redirect|logo|icon|image|docs?|webhook|callback|login|signin|avatar|thumb|cdn|proxy|oauth|privacy|terms|help|support|website/i;
/** Placeholder, sample and image hosts: never an API host. */
const HOST_FIRST_LABEL_DROP = /^(example|test|testing|demo|sample|mycompany|yourcompany|your-?company|acme|company|subdomain|yourdomain|your-?subdomain|domain|i\d*|img\d*|images?|thumbs?|static|cdn\d*|assets?|media)$/;
const HOST_DROP = [/(^|\.)activepieces\.(com|dev)$/i, /^localhost$/i, /^\d{1,3}(\.\d{1,3}){3}$/, /(^|\.)example\.(com|org|net)$/i, /(^|\.)(w3|schema)\.org$/i];

/** Turn a URL (possibly with {placeholders}) into an api_hosts entry, or null. */
export function hostEntry(text) {
  const m = /^https:\/\/([^/?#\s]+)/i.exec(text);
  if (!m) return null;
  let host = m[1].toLowerCase();
  if (host.includes("@") || host.includes(":")) host = host.split("@").pop().split(":")[0];
  if (!host) return null;
  let entry = host;
  if (host.includes("{")) {
    const labels = host.split(".");
    let last = -1;
    labels.forEach((l, i) => {
      if (l.includes("{")) last = i;
    });
    const rest = labels.slice(last + 1);
    if (rest.length < 2) return null;
    entry = `*.${rest.join(".")}`;
  }
  if (!/^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(entry)) return null;
  const bare = entry.replace(/^\*\./, "");
  if (HOST_DROP.some((re) => re.test(bare)) || bare.includes("activepieces")) return null;
  if (!entry.startsWith("*.") && HOST_FIRST_LABEL_DROP.test(bare.split(".")[0])) return null;
  return entry;
}

/** A host covered by a wildcard that is also in the list adds nothing: keep the wildcard. */
function dedupeHosts(list) {
  const wild = list.filter((h) => h.startsWith("*.")).map((h) => h.slice(1));
  return list.filter((h) => h.startsWith("*.") || !wild.some((w) => h.endsWith(w) && h.length > w.length));
}

function harvestHosts(project, files) {
  const counts = new Map();
  const add = (v) => {
    const s = strOf(v);
    if (s === undefined || !/^https:\/\//i.test(s)) return;
    const h = hostEntry(s);
    if (h) counts.set(h, (counts.get(h) ?? 0) + 1);
  };
  for (const f of files) {
    const mod = project.load(f);
    if (!mod) continue;
    walk(mod.sf, (n) => {
      if (ts.isPropertyAssignment(n)) {
        const name = (ts.isIdentifier(n.name) || ts.isStringLiteral(n.name) ? n.name.text : "").toLowerCase();
        if (HOST_PROPS.has(name)) add(ev(n.initializer, mod));
      } else if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
        const name = n.name.text;
        if (HOST_VAR.test(name) && !HOST_VAR_DROP.test(name)) add(ev(n.initializer, mod));
      }
    });
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).map(([h]) => h);
}

const HOST_LABEL_DROP = new Set(["www", "docs", "doc", "developer", "developers", "dev", "help", "support", "blog", "community", "status", "learn", "cdn", "static", "assets", "img", "images", "media", "download", "downloads", "marketplace", "store", "forum", "forums", "accounts", "login", "auth", "id", "sso", "signin", "signup", "mail", "email"]);
const GENERIC_PIECE_TOKENS = new Set(["cloud", "data", "center", "api", "bot", "online", "pages", "business", "enterprise", "ai"]);
const PROSE_KEYS = new Set(["description", "displayname", "markdown", "placeholder", "label", "title", "text", "message", "content", "summary", "error", "logourl", "docsurl", "homepageurl"]);

/**
 * Second signal, used only when the first found nothing: an https string literal in the source whose host
 * carries the vendor's own name (a token of the piece folder name), outside descriptions and markdown.
 * Region maps and base-URL helpers show up this way. Hosts that read as documentation or sign-in pages
 * (first label www, docs, login, ...) are never taken.
 */
function harvestVendorLiterals(project, files, piece) {
  const tokens = piece.split("-").filter((t) => t.length >= 4 && !GENERIC_PIECE_TOKENS.has(t));
  const whole = piece.replace(/-/g, "");
  if (whole.length >= 4) tokens.push(whole);
  if (!tokens.length) return [];
  const counts = new Map();
  for (const f of files) {
    const mod = project.load(f);
    if (!mod) continue;
    const visit = (n) => {
      if (ts.isPropertyAssignment(n)) {
        const nm = (ts.isIdentifier(n.name) || ts.isStringLiteral(n.name) ? n.name.text : "").toLowerCase();
        if (PROSE_KEYS.has(nm)) return;
      }
      if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && n.expression.name.text === "MarkDown") return;
      if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) || ts.isTemplateExpression(n)) {
        const text = ts.isTemplateExpression(n) ? n.head.text : n.text;
        const m = /^https:\/\/([A-Za-z0-9.-]+)(?:[/?#:]|$)/.exec(text);
        if (m) {
          const host = m[1].toLowerCase();
          const first = host.split(".")[0];
          if (!HOST_LABEL_DROP.has(first) && tokens.some((t) => host.includes(t))) {
            const h = hostEntry(`https://${host}`);
            if (h) counts.set(h, (counts.get(h) ?? 0) + 1);
          }
        }
        if (ts.isTemplateExpression(n)) n.templateSpans.forEach((sp) => visit(sp.expression));
        return;
      }
      ts.forEachChild(n, visit);
    };
    visit(mod.sf);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).map(([h]) => h);
}

const pretty = (slug) => slug.split("-").map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w)).join(" ");

/** One piece -> facts (never throws: a piece that cannot be read is reported, not fatal). */
export function extractPiece(communityDir, piece) {
  const dir = join(communityDir, piece);
  const srcDir = join(dir, "src");
  const counters = { unresolved_props: 0 };
  const facts = { piece, displayName: undefined, categories: [], auths: [], via: "createPiece", hosts: [], counters, license: undefined, problem: undefined };
  try {
    const pkgPath = join(dir, "package.json");
    if (existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
        if (typeof pkg.license === "string") facts.license = pkg.license;
      } catch {
        /* an unreadable package.json is not fatal */
      }
    }
    const project = new PieceProject(srcDir);
    const files = listSrcFiles(srcDir);
    const index = project.load(join(srcDir, "index.ts"));
    if (!index) {
      facts.problem = "no_index";
      return facts;
    }
    const cp = findCreatePiece(index);
    if (cp && cp.arguments[0] && ts.isObjectLiteralExpression(cp.arguments[0])) {
      const obj = cp.arguments[0];
      const dn = objectProp(obj, "displayName");
      const name = dn ? strOf(ev(dn, index)) : undefined;
      if (typeof name === "string" && name.trim()) facts.displayName = name.trim();
      const cats = objectProp(obj, "categories");
      const cv = cats ? ev(cats, index) : [];
      if (Array.isArray(cv)) for (const c of cv) if (isObj(c) && typeof c.member === "string") facts.categories.push(c.member.toLowerCase().replace(/_/g, "-"));
      const authNode = objectProp(obj, "auth");
      let calls = [];
      if (authNode) {
        const av = ev(authNode, index);
        calls = flattenAuth(av);
        const unresolved = av === UNRES || (Array.isArray(av) && av.some((x) => x === UNRES));
        if (unresolved || (calls.length === 0 && !(isObj(av) && av.$external) && av !== undefined)) {
          const scanned = scanAuths(project, files);
          if (scanned.length) {
            facts.via = "scan";
            calls = scanned;
          }
        }
      }
      facts.auths = calls.map((c) => authFacts(c, counters));
    } else {
      const scanned = scanAuths(project, files);
      facts.via = "scan";
      facts.auths = scanned.map((c) => authFacts(c, counters));
      if (!scanned.length) facts.problem = "no_create_piece";
    }
    facts.hosts = harvestHosts(project, files);
    facts.hostBasis = "harvested";
    if (!facts.hosts.length) {
      facts.hosts = harvestVendorLiterals(project, files, piece);
      if (facts.hosts.length) facts.hostBasis = "vendor_literal";
    }
  } catch (err) {
    facts.problem = `error: ${err instanceof Error ? err.message : String(err)}`.slice(0, 200);
  }
  return facts;
}

// ── facts -> ProviderDef ──────────────────────────────────────────────────────────────────────────────
const clean = (s) => String(s).replace(/[\u2013\u2014]/g, "-").replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();

/** A slug that satisfies ^[a-z][a-z0-9-]{0,31}$, derived deterministically from a piece folder name. */
export function pieceSlug(piece) {
  let s = piece.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/-+/g, "-").replace(/^-+|-+$/g, "");
  if (!/^[a-z]/.test(s)) s = `p-${s}`;
  if (s.length > 32) {
    const parts = s.split("-");
    let acc = "";
    for (const p of parts) {
      const cand = acc ? `${acc}-${p}` : p;
      if (cand.length > 32) break;
      acc = cand;
    }
    s = acc || s.slice(0, 32);
  }
  return s.replace(/-+$/, "");
}

const BODY = "body";

function fieldList(fields) {
  return fields.map((f) => ({ name: f.name, required: f.required, secret: f.secret }));
}

const oauthFields = () => [
  { name: "client_id", label: "OAuth client ID", required: true, secret: false },
  { name: "client_secret", label: "OAuth client secret", required: true, secret: true },
];

/** Build the AuthDef list of one piece. Returns { defs, skipped, assumptions }. */
function buildAuths(facts) {
  const defs = [];
  const skipped = [];
  const assume = new Set();
  const used = new Set();
  const idFor = (base) => {
    let id = base;
    for (let i = 2; used.has(id); i++) id = `${base}_${i}`;
    used.add(id);
    return id;
  };
  for (const a of facts.auths) {
    if (a.kind === "none") {
      skipped.push({ kind: "none", reason: "no_auth" });
    } else if (a.kind === "oidc") {
      skipped.push({ kind: "oidc", reason: "oidc_not_representable" });
    } else if (a.kind === "unknown") {
      skipped.push({ kind: a.name, reason: "unknown_auth_kind" });
    } else if (a.kind === "secret_text") {
      defs.push({
        id: idFor("api_key"),
        mode: "api_key",
        label: "API key",
        inject: { in: "header", name: "Authorization", template: "Bearer {token}" },
        fields: { auth_config_creation: [], connected_account_initiation: [{ name: "api_key", required: true, secret: true }] },
      });
      assume.add("injection");
    } else if (a.kind === "basic") {
      defs.push({
        id: idFor("basic"),
        mode: "basic",
        label: "Username and password",
        inject: { in: "header", name: "Authorization", template: "Basic {basic}" },
        fields: {
          auth_config_creation: [],
          connected_account_initiation: [
            { name: "username", required: true, secret: false },
            { name: "password", required: true, secret: true },
          ],
        },
      });
    } else if (a.kind === "custom") {
      if (!a.fields.length) {
        skipped.push({ kind: "custom", reason: "custom_fields_unresolved" });
        continue;
      }
      defs.push({
        id: idFor("custom"),
        mode: "custom",
        label: "Custom credentials",
        inject: { in: "header", name: "Authorization", template: "Bearer {token}" },
        fields: { auth_config_creation: [], connected_account_initiation: fieldList(a.fields) },
      });
    } else if (a.kind === "oauth2") {
      const grant = a.grantType ?? "authorization_code";
      const wantCode = grant === "authorization_code" || grant.startsWith("both");
      const wantCc = grant === "client_credentials" || grant.startsWith("both");
      const tokenUrl = cleanUrl(a.tokenUrl);
      const authorizeUrl = cleanUrl(a.authUrl);
      const base = () => ({
        token_url: tokenUrl,
        pkce: a.pkce ? "required" : "unsupported",
        client_auth: a.authorizationMethod === "header" ? "basic" : BODY,
        client_secret_at_exchange: "always",
        scope_separator: " ",
        default_scopes: a.scopes,
        scope_catalog: [],
        ...(Object.keys(a.extra).length ? { extra_auth_params: a.extra } : {}),
        redirect: "loopback",
        accept_json: true,
      });
      if (!tokenUrl) {
        skipped.push({ kind: "oauth2", reason: "oauth2_url_not_static" });
        continue;
      }
      if (a.authorizationMethod === undefined) assume.add("client_auth");
      assume.add("scope_separator");
      assume.add("redirect");
      assume.add("refresh");
      assume.add("injection");
      const inject = { in: "header", name: "Authorization", template: "Bearer {token}" };
      const initiation = fieldList(a.fields);
      if (wantCode) {
        if (!authorizeUrl) {
          skipped.push({ kind: "oauth2", reason: "oauth2_url_not_static" });
        } else {
          const o = base();
          o.authorize_url = authorizeUrl;
          o.refresh = { kind: "refresh_token", rotates: false };
          defs.push({
            id: idFor("oauth2"),
            mode: "oauth2",
            label: "OAuth 2.0",
            oauth2: orderOAuth(o),
            inject,
            fields: { auth_config_creation: oauthFields(), connected_account_initiation: initiation },
          });
        }
      }
      if (wantCc) {
        const o = base();
        o.pkce = "unsupported";
        o.refresh = { kind: "none", rotates: false };
        defs.push({
          id: idFor("oauth2_cc"),
          mode: "oauth2_cc",
          label: "OAuth 2.0 client credentials",
          oauth2: orderOAuth(o),
          inject,
          fields: { auth_config_creation: oauthFields(), connected_account_initiation: initiation },
        });
      }
    }
  }
  // The first definition is the default; rebuild it so `default` sits next to `label` in the file.
  if (defs.length) {
    const { id, mode, label, ...rest } = defs[0];
    defs[0] = { id, mode, label, default: true, ...rest };
  }
  return { defs, skipped, assume };
}

/** Stable key order for an oauth2 block, so files diff cleanly. */
function orderOAuth(o) {
  const order = ["authorize_url", "token_url", "pkce", "client_auth", "client_secret_at_exchange", "scope_separator", "default_scopes", "scope_catalog", "extra_auth_params", "redirect", "accept_json", "refresh"];
  const out = {};
  for (const k of order) if (o[k] !== undefined) out[k] = o[k];
  return out;
}

const origin = (u) => {
  try {
    return `${new URL(u).protocol}//${new URL(u).host}/`;
  } catch {
    return null;
  }
};

const ASSUMPTION_TEXT = {
  client_auth: "client authentication in the request body",
  scope_separator: "a space between scopes",
  redirect: "an http loopback redirect is accepted",
  refresh: "refresh tokens that do not rotate",
  injection: "the credential sent as Authorization: Bearer",
};

export function buildSeed(facts, ctx) {
  const { defs, skipped, assume } = buildAuths(facts);
  if (!defs.length) return { skip: { reason: skipped[0]?.reason ?? facts.problem ?? "no_auth" }, skippedAuths: skipped };
  let hosts = dedupeHosts(facts.hosts).slice(0, 12);
  let basis = facts.hostBasis ?? "harvested";
  if (!hosts.length) {
    const t = defs.map((d) => d.oauth2?.token_url).find(Boolean);
    const h = t ? hostEntry(t) : null;
    if (h) {
      hosts = [h];
      basis = "token_host_fallback";
    }
  }
  if (!hosts.length) return { skip: { reason: "no_api_host" }, skippedAuths: skipped };
  const slug = ctx.slug;
  const firstOAuth = defs.find((d) => d.mode === "oauth2") ?? defs.find((d) => d.oauth2);
  const consoleUrl = (firstOAuth && origin(firstOAuth.oauth2.authorize_url ?? firstOAuth.oauth2.token_url)) ?? `https://${hosts[0].replace(/^\*\./, "")}/`;
  const hasOAuth = defs.some((d) => d.mode === "oauth2");
  const hasCc = defs.some((d) => d.mode === "oauth2_cc");
  const hasKey = defs.some((d) => d.mode === "api_key" || d.mode === "bearer");
  const hasBasic = defs.some((d) => d.mode === "basic");
  const hasCustom = defs.some((d) => d.mode === "custom");
  const steps = [
    "Unverified seed: this definition was derived from another project's published auth settings and has not been tested against the provider. Read the provider's own developer documentation first.",
  ];
  if (hasOAuth || hasCc) {
    steps.push("Create an OAuth app in the provider's developer console and register the redirect URI below (client credentials flows need no redirect).");
    steps.push(`Store the client id and secret: switchboard vault set ${slug}_client_id and switchboard vault set ${slug}_client_secret`);
    steps.push(`Register them: switchboard authconfig add ${slug} --client-id-ref ${slug}_client_id --client-secret-ref ${slug}_client_secret`);
    steps.push(`Connect: switchboard connect ${slug} --account <label>`);
  }
  if (hasKey) {
    steps.push("Create an API key or token in the provider's account settings.");
    steps.push(`Connect: switchboard connect ${slug} --auth api_key --token-stdin`);
  }
  if (hasBasic) {
    steps.push("Use the account's username and password, or an application password if the provider offers one.");
    steps.push(`Connect: switchboard connect ${slug} --auth basic --field username=<ref> --field password=<ref>`);
  }
  if (hasCustom) steps.push("The 'custom' authentication of this provider takes several credential fields. This build does not drive custom authentication yet, so Connect is unavailable for that one.");
  const notes = [
    `SEED, unverified. Facts (URLs, scope names, field names, a product name) were read from the Activepieces community piece '${ctx.piece}' at commit ${ctx.commit.slice(0, 12)} (MIT; see NOTICE). Nothing here was tested against the provider and it never counts as working.`,
  ];
  const assumed = [...assume].map((k) => ASSUMPTION_TEXT[k]).filter(Boolean);
  if (assumed.length) notes.push(`ASSUMED, not stated by the source: ${assumed.join("; ")}. UNVERIFIED.`);
  notes.push(
    basis === "token_host_fallback"
      ? "The source names no API host; api_hosts holds only the token host as a placeholder. Replace it with the provider's real API host before using the credential."
      : basis === "vendor_literal"
        ? "api_hosts are candidates: https literals in the piece source whose host carries the vendor's name (region maps, base URL helpers). Review them before relying on them: they decide where a credential may be sent."
        : "api_hosts are candidates harvested from request URL settings in the piece source. Review them before relying on them: they decide where a credential may be sent.",
  );
  if (facts.auths.some((a) => a.kind === "oauth2" && a.scopes.length === 0)) notes.push("The source lists no default scopes: pass --scopes at connect time.");
  const def = {
    $schema: "../../schemas/provider.schema.json",
    slug,
    name: clean(facts.displayName ?? pretty(ctx.piece)).slice(0, 80) || pretty(ctx.piece),
    categories: facts.categories.length ? [...new Set(facts.categories)].map((c) => c.slice(0, 40)) : ["uncategorized"],
    api_hosts: hosts,
    docs_url: `${REPO_URL}/tree/${ctx.commit}/packages/pieces/community/${ctx.piece}/src`,
    owner_setup: {
      console_url: consoleUrl,
      steps,
      redirect_uris: hasOAuth ? ["{loopback_redirect}"] : [],
      notes,
    },
    auth: defs,
    provenance: {
      derived_from: [`activepieces/activepieces@${ctx.commit} packages/pieces/community/${ctx.piece}/src`],
      license: "MIT",
      attribution: `${ctx.copyright} (MIT Expat). Facts only: URLs, scope names, field names. See NOTICE.`,
    },
    source: { activepieces_commit: ctx.commit, piece: ctx.piece },
    verification: "unverified_seed",
  };
  return { def, skippedAuths: skipped, basis };
}

// ── license gate ──────────────────────────────────────────────────────────────────────────────────────
export function checkLicense(checkout) {
  const file = join(checkout, "LICENSE");
  if (!existsSync(file)) throw new Error("LICENSE is missing from the checkout");
  const text = readFileSync(file, "utf8");
  const copyright = /^Copyright \(c\)[^\n]*$/m.exec(text)?.[0]?.trim();
  const mit = /MIT Expat/i.test(text) && /Permission is hereby granted, free of charge/.test(text);
  const eePaths = [...text.matchAll(/"(packages\/[^"]+)"/g)].map((m) => m[1]);
  const communityOutsideEe = !eePaths.some((p) => "packages/pieces/community/".startsWith(p) || "packages/pieces/community".startsWith(p.replace(/\/$/, "")));
  if (!copyright || !mit || !communityOutsideEe) {
    throw new Error(`LICENSE check failed: copyright=${Boolean(copyright)} mit=${mit} communityOutsideEe=${communityOutsideEe}`);
  }
  return { file: "LICENSE", copyright, mit, ee_paths: eePaths, community_outside_ee: communityOutsideEe };
}

function gitHead(checkout) {
  const r = spawnSync("git", ["-C", checkout, "rev-parse", "HEAD"], { encoding: "utf8" });
  const sha = String(r.stdout ?? "").trim();
  return /^[0-9a-f]{40}$/.test(sha) ? sha : null;
}

// ── the whole run ─────────────────────────────────────────────────────────────────────────────────────
export function extractCheckout({ checkout, commit }) {
  const license = checkLicense(checkout);
  const communityDir = join(checkout, "packages", "pieces", "community");
  if (!existsSync(communityDir)) throw new Error(`no packages/pieces/community in ${checkout}`);
  const sha = commit ?? gitHead(checkout);
  if (!sha || !/^[0-9a-f]{40}$/.test(sha)) throw new Error("pass --commit <40 hex> (the checkout has no readable git HEAD)");
  const pieces = readdirSync(communityDir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort();
  const seeds = new Map();
  const skippedPieces = [];
  const skippedAuths = [];
  const renamed = [];
  const usedSlugs = new Set();
  const basisCounts = { harvested: 0, vendor_literal: 0, token_host_fallback: 0 };
  const via = { createPiece: 0, scan: 0 };
  const flags = { pieces_with_unresolved_props: 0, scopes_dropped: 0, pieces_with_non_mit_package_license: [] };
  for (const piece of pieces) {
    const facts = extractPiece(communityDir, piece);
    if (facts.license && !/^MIT$/i.test(facts.license)) flags.pieces_with_non_mit_package_license.push({ piece, license: facts.license });
    if (facts.counters.unresolved_props) flags.pieces_with_unresolved_props++;
    flags.scopes_dropped += facts.auths.reduce((n, a) => n + (a.scopesDropped ?? 0), 0);
    if (facts.license && !/^MIT$/i.test(facts.license)) {
      skippedPieces.push({ piece, reason: "non_mit_package_license" });
      continue;
    }
    let slug = pieceSlug(piece);
    if (slug !== piece) renamed.push({ piece, slug });
    for (let i = 2; usedSlugs.has(slug); i++) slug = `${pieceSlug(piece).slice(0, 29)}-${i}`;
    const r = facts.problem && !facts.auths.length ? { skip: { reason: facts.problem.startsWith("error") ? "extract_error" : facts.problem } } : buildSeed(facts, { slug, piece, commit: sha, copyright: license.copyright });
    for (const s of r.skippedAuths ?? []) skippedAuths.push({ piece, ...s });
    if (r.skip) {
      skippedPieces.push({ piece, reason: r.skip.reason });
      continue;
    }
    usedSlugs.add(slug);
    seeds.set(slug, r.def);
    basisCounts[r.basis]++;
    via[facts.via]++;
  }
  const byMode = {};
  const providersByMode = {};
  for (const def of seeds.values()) {
    const modes = new Set();
    for (const a of def.auth) {
      byMode[a.mode] = (byMode[a.mode] ?? 0) + 1;
      modes.add(a.mode);
    }
    for (const m of modes) providersByMode[m] = (providersByMode[m] ?? 0) + 1;
  }
  const sortObj = (o) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => (a < b ? -1 : 1)));
  const reasons = {};
  for (const s of skippedPieces) reasons[s.reason] = (reasons[s.reason] ?? 0) + 1;
  const skippedAuthReasons = {};
  for (const s of skippedAuths) skippedAuthReasons[`${s.kind}:${s.reason}`] = (skippedAuthReasons[`${s.kind}:${s.reason}`] ?? 0) + 1;
  const connectable = new Set(["oauth2", "oauth2_cc", "api_key", "bearer", "basic"]);
  const connectableProviders = [...seeds.values()].filter((d) => d.auth.some((a) => connectable.has(a.mode))).length;
  const manifest = {
    generated_by: "scripts/extract-activepieces-auth.mjs",
    extractor_version: EXTRACTOR_VERSION,
    source: { repository: REPO_URL, commit: sha, license: "MIT", license_file: license.file, copyright: license.copyright, community_outside_ee: license.community_outside_ee },
    pieces_scanned: pieces.length,
    seeds: seeds.size,
    auth_definitions: Object.values(byMode).reduce((a, b) => a + b, 0),
    auth_definitions_by_mode: sortObj(byMode),
    providers_by_mode: sortObj(providersByMode),
    providers_that_can_start_connect: connectableProviders,
    api_hosts_basis: basisCounts,
    auth_found_via: via,
    skipped_pieces: { total: skippedPieces.length, reasons: sortObj(reasons), pieces: skippedPieces },
    skipped_auth_definitions: { total: skippedAuths.length, reasons: sortObj(skippedAuthReasons) },
    slugs_changed: renamed,
    data_quality: { pieces_with_unresolved_props: flags.pieces_with_unresolved_props, scopes_dropped_as_unsafe: flags.scopes_dropped, pieces_with_non_mit_package_license: flags.pieces_with_non_mit_package_license },
  };
  return { seeds, manifest };
}

export function writeSeeds(outDir, { seeds, manifest }) {
  mkdirSync(outDir, { recursive: true });
  for (const f of readdirSync(outDir)) if (f.endsWith(".json")) rmSync(join(outDir, f));
  for (const [slug, def] of [...seeds.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    writeFileSync(join(outDir, `${slug}.json`), `${JSON.stringify(def, null, 2)}\n`);
  }
  writeFileSync(join(outDir, "_manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
}

// ── CLI ───────────────────────────────────────────────────────────────────────────────────────────────
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const args = process.argv.slice(2);
  const arg = (name) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const checkout = arg("--checkout");
  const out = arg("--out");
  if (!checkout || (!out && !args.includes("--dry-run"))) {
    console.error("usage: node scripts/extract-activepieces-auth.mjs --checkout <dir> --out <seed dir> [--commit <sha>] [--dry-run]");
    process.exit(2);
  }
  try {
    const result = extractCheckout({ checkout: resolve(checkout), commit: arg("--commit") });
    if (!args.includes("--dry-run")) writeSeeds(resolve(out), result);
    const m = result.manifest;
    console.log(`commit ${m.source.commit}  license ${m.source.license} (${m.source.copyright})`);
    console.log(`pieces scanned ${m.pieces_scanned}; seeds ${m.seeds}; auth definitions ${m.auth_definitions}`);
    console.log(`auth definitions by mode: ${JSON.stringify(m.auth_definitions_by_mode)}`);
    console.log(`providers by mode:        ${JSON.stringify(m.providers_by_mode)}`);
    console.log(`providers that can start Connect in this build: ${m.providers_that_can_start_connect}`);
    console.log(`api_hosts basis: ${JSON.stringify(m.api_hosts_basis)}; auth found via ${JSON.stringify(m.auth_found_via)}`);
    console.log(`skipped pieces ${m.skipped_pieces.total}: ${JSON.stringify(m.skipped_pieces.reasons)}`);
    console.log(`skipped auth definitions ${m.skipped_auth_definitions.total}: ${JSON.stringify(m.skipped_auth_definitions.reasons)}`);
    console.log(`slugs changed ${m.slugs_changed.length}; data quality ${JSON.stringify(m.data_quality)}`);
    if (args.includes("--dry-run")) console.log("dry run: nothing written");
  } catch (err) {
    console.error(`extract-activepieces-auth: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}
