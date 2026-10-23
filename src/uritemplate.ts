/**
 * Does a client URI fit an RFC 6570 URI template that an UPSTREAM declared?
 *
 * Used only to find which server declared a template for a URI nobody listed (router.readResource); the
 * match never reaches a second server. The template is chosen by the upstream and the URI by the client,
 * so neither may decide how long the match takes. 0.1.x compiled the template to a backtracking RegExp:
 * `mem://{a}{b}{c}{d}{e}{f}{g}x` against a URI of `axaxax...b` took n^6.5, minutes for 100 characters,
 * with the whole single-threaded gateway blocked. No RegExp is built here. The template is compiled to a
 * small NFA (Thompson construction) and the URI is run through it once, tracking the SET of live states:
 * O(URI length x template states), whatever the template looks like.
 *
 * Bounds, all fail-closed (an out-of-bounds input is a non-match, never an error):
 *   MAX_TEMPLATE_LEN  longer templates are not matched
 *   MAX_URI_LEN       longer URIs are not matched
 *   StepBudget        a counter of NFA state visits shared by every template tried for one read, so
 *                     a server that declares hundreds of hostile templates cannot add the cost up
 *
 * Semantics are those of the old compiler, exactly (an oracle compares them on random inputs): a
 * variable expression is classified by its first character and must match at least one character;
 * an operator form this does not model is a single path segment, so an odd template fails closed.
 *   {x} {,}        one or more of [^/?#]
 *   {+x} {#x}      one or more of any character but a line terminator
 *   {/x}           one or more groups of "/" then one or more of [^/?#]
 *   {.x}           one or more groups of "." then one or more of [^/?#.]
 *   {;x}           one or more groups of ";" then one or more of [^/?#;]
 *   {?x} {&x}      optionally "?" or "&" then any run of [^#]
 */

/** URIs longer than this are never matched (a cost guard on the client-chosen side). */
export const MAX_URI_LEN = 8192;
/** Templates longer than this are never matched (a cost guard on the upstream-chosen side). */
export const MAX_TEMPLATE_LEN = 512;
/** NFA state visits one resource read may spend across all templates; about 20 to 40 ms of work. */
export const DEFAULT_STEP_BUDGET = 4_000_000;

export interface StepBudget {
  /** Remaining state visits. Decremented as templates are run; at zero or below every match is false. */
  steps: number;
}

// NFA state types.
const T_CHAR = 0; // consume exactly the code unit `arg`
const T_CLASS = 1; // consume one code unit that satisfies class `arg`
const T_SPLIT = 2; // epsilon to `out1` and `out2`
const T_MATCH = 3;

// Character classes (code unit predicates).
const C_SEG = 0; // [^/?#]
const C_ANY = 1; // .   (not \n \r U+2028 U+2029)
const C_SEG_NODOT = 2; // [^/?#.]
const C_SEG_NOSEMI = 3; // [^/?#;]
const C_NOT_HASH = 4; // [^#]
const C_QUERY_START = 5; // [?&]

function inClass(cls: number, c: number): boolean {
  switch (cls) {
    case C_SEG:
      return c !== 47 && c !== 63 && c !== 35;
    case C_ANY:
      return c !== 10 && c !== 13 && c !== 0x2028 && c !== 0x2029;
    case C_SEG_NODOT:
      return c !== 47 && c !== 63 && c !== 35 && c !== 46;
    case C_SEG_NOSEMI:
      return c !== 47 && c !== 63 && c !== 35 && c !== 59;
    case C_NOT_HASH:
      return c !== 35;
    default:
      return c === 63 || c === 38;
  }
}

interface Nfa {
  type: Int32Array;
  arg: Int32Array;
  out1: Int32Array;
  out2: Int32Array;
  count: number;
  start: number;
}

type Item = { lit: string } | { op: string };

/** Split a template into literal runs and variable expressions (same tokenisation as the old compiler). */
function tokenize(template: string): Item[] {
  const items: Item[] = [];
  let last = 0;
  for (const m of template.matchAll(/\{([^}]*)\}/g)) {
    const at = m.index ?? 0;
    if (at > last) items.push({ lit: template.slice(last, at) });
    items.push({ op: (m[1] ?? "")[0] ?? "" });
    last = at + m[0].length;
  }
  if (last < template.length) items.push({ lit: template.slice(last) });
  return items;
}

/** Compile back to front: each item is built knowing the state that follows it. */
function compile(template: string): Nfa {
  const items = tokenize(template);
  const cap = 4 * template.length + 2; // a variable expression needs at most 4 states for at least 3 characters
  const nfa: Nfa = { type: new Int32Array(cap), arg: new Int32Array(cap), out1: new Int32Array(cap), out2: new Int32Array(cap), count: 0, start: 0 };
  const add = (type: number, arg: number, out1: number, out2 = -1): number => {
    const i = nfa.count++;
    nfa.type[i] = type;
    nfa.arg[i] = arg;
    nfa.out1[i] = out1;
    nfa.out2[i] = out2;
    return i;
  };

  /** `X+` where X is a class: returns the entry state. */
  const plus = (cls: number, next: number): number => {
    const loop = add(T_SPLIT, 0, -1, next);
    const c = add(T_CLASS, cls, loop);
    nfa.out1[loop] = c;
    return c;
  };
  /** `(?:LEAD X+)+`: returns the entry state. */
  const groups = (lead: number, cls: number, next: number): number => {
    const again = add(T_SPLIT, 0, -1, next); // after a group: another group, or leave
    const body = plus(cls, again); // X+ then back to `again`
    const s = add(T_CHAR, lead, body);
    nfa.out1[again] = s;
    return s;
  };

  let next = add(T_MATCH, 0, -1);
  for (let k = items.length - 1; k >= 0; k--) {
    const it = items[k]!;
    if ("lit" in it) {
      for (let i = it.lit.length - 1; i >= 0; i--) next = add(T_CHAR, it.lit.charCodeAt(i), next);
      continue;
    }
    switch (it.op) {
      case "+":
      case "#":
        next = plus(C_ANY, next);
        break;
      case "/":
        next = groups(47, C_SEG, next);
        break;
      case ".":
        next = groups(46, C_SEG_NODOT, next);
        break;
      case ";":
        next = groups(59, C_SEG_NOSEMI, next);
        break;
      case "?":
      case "&": {
        // (?:[?&][^#]*)? : leave at once, or take the lead and then any run of non-#
        const run = add(T_SPLIT, 0, -1, next);
        const body = add(T_CLASS, C_NOT_HASH, run);
        nfa.out1[run] = body;
        const lead = add(T_CLASS, C_QUERY_START, run);
        next = add(T_SPLIT, 0, lead, next);
        break;
      }
      default:
        next = plus(C_SEG, next);
    }
  }
  nfa.start = next;
  return nfa;
}

/**
 * True when `uri` is an expansion of `template`. Never throws; anything out of bounds (non-string input,
 * over-long template or URI, spent budget) is false. `budget` is shared by the caller across templates.
 */
export function templateMatches(template: string, uri: string, budget: StepBudget = { steps: DEFAULT_STEP_BUDGET }): boolean {
  if (typeof template !== "string" || typeof uri !== "string") return false;
  if (template.length > MAX_TEMPLATE_LEN || uri.length > MAX_URI_LEN) return false;
  if (budget.steps <= 0) return false;
  budget.steps -= template.length + 8; // compiling is work too: a server may declare a great many templates
  if (budget.steps <= 0) {
    budget.steps = 0;
    return false;
  }

  const nfa = compile(template);
  const n = nfa.count;
  const mark = new Int32Array(n);
  let gen = 0;
  let cur = new Int32Array(n);
  let nxt = new Int32Array(n);
  let curLen = 0;
  let nxtLen = 0;
  const stack = new Int32Array(2 * n + 2);

  /** Add `s` and everything reachable from it by epsilon moves to the list being built. */
  const closure = (s: number, into: Int32Array, len: number): number => {
    let sp = 0;
    stack[sp++] = s;
    while (sp > 0) {
      const t = stack[--sp]!;
      if (mark[t] === gen) continue;
      mark[t] = gen;
      if (nfa.type[t] === T_SPLIT) {
        stack[sp++] = nfa.out2[t]!;
        stack[sp++] = nfa.out1[t]!;
      } else {
        into[len++] = t;
      }
    }
    return len;
  };

  gen++;
  curLen = closure(nfa.start, cur, 0);
  for (let i = 0; i < uri.length; i++) {
    if (curLen === 0) return false;
    budget.steps -= curLen + 1;
    if (budget.steps < 0) {
      budget.steps = 0;
      return false;
    }
    const c = uri.charCodeAt(i);
    gen++;
    nxtLen = 0;
    for (let k = 0; k < curLen; k++) {
      const s = cur[k]!;
      const t = nfa.type[s];
      if ((t === T_CHAR && nfa.arg[s] === c) || (t === T_CLASS && inClass(nfa.arg[s]!, c))) {
        nxtLen = closure(nfa.out1[s]!, nxt, nxtLen);
      }
    }
    const swap = cur;
    cur = nxt;
    nxt = swap;
    curLen = nxtLen;
  }
  for (let k = 0; k < curLen; k++) if (nfa.type[cur[k]!] === T_MATCH) return true;
  return false;
}
