/**
 * search-index.ts — a dependency-free BM25F ranker over the aggregated tool surface.
 *
 * Why BM25F and not the old additive keyword scorer: once a dozen MCP servers are mounted,
 * a flat "+3 if the name contains the token, +1 if the description does" score has no notion
 * of how *rare* a term is (every tool mentions "get"/"list"/"id"), no *saturation* (ten
 * occurrences of "issue" shouldn't bury one precise match), and no *length normalization*
 * (a verbose description shouldn't out-rank a tight one just by having more words to hit).
 * BM25F — Okapi BM25 generalized to weighted fields — fixes all three while preserving the
 * per-field weighting that makes a name match beat a description mention. It is the ranking
 * function behind Lucene/Elasticsearch and remains the strongest classical (term-based)
 * baseline. Crucially it is pure arithmetic: zero dependencies, zero native code, which the
 * project's hard no-native-deps rule requires (a learned/embedding ranker would drag in
 * onnxruntime — a native module — so it lives only in a documented fork).
 *
 * Reference: Robertson & Zaragoza, "The Probabilistic Relevance Framework: BM25 and Beyond"
 * (2009), §3 (BM25) and §4.4 (BM25F field combination).
 */

/** Split on any run of non-alphanumerics and lowercase — `GitHub__create_issue` → [github, create, issue]. */
const NON_WORD = /[^a-z0-9]+/;

export function tokenize(text: string): string[] {
  if (!text) return [];
  return text.toLowerCase().split(NON_WORD).filter(Boolean);
}

export interface RankField {
  /** Stable key (e.g. "name") used to pool length-normalization across all documents. */
  key: string;
  /** Raw field text; tokenized internally. */
  text: string;
  /** Field importance multiplier — a name hit should outweigh a description hit. */
  weight: number;
  /** Per-field length-normalization strength b ∈ [0,1] (0 = none, 1 = full). Prose wants ~0.75; keyword fields want 0. */
  b?: number;
}

export interface RankDoc {
  /** Caller-stable identifier returned in the results (e.g. the exposed tool name). */
  id: string;
  fields: RankField[];
  /** Multiplicative relevance boost for operator-flagged tools (`important`); default 1. */
  boost?: number;
  /** Caller-computed exact match (e.g. tool name === query) — sorts above all non-exact hits. */
  exact?: boolean;
}

export interface RankResult {
  id: string;
  score: number;
  exact: boolean;
}

export interface RankOptions {
  /** TF saturation: higher rewards repeats more before flattening. BM25 default 1.5. */
  k1?: number;
  /** Default per-field length normalization when a field omits its own `b`. */
  b?: number;
  /** Cap on results returned (after sorting). */
  limit?: number;
}

const DEFAULT_K1 = 1.5;
const DEFAULT_B = 0.75;

interface FieldStats {
  tf: Map<string, number>;
  len: number;
  weight: number;
  b: number;
}

/**
 * Rank documents against a free-text query with BM25F.
 *
 * Returns only documents that positively match ≥1 query term (or are flagged `exact`), sorted
 * exact-first then by descending score, capped at `limit`. An empty/whitespace query, or an
 * empty corpus, returns `[]` — the caller is expected to fall back to an unranked slice.
 *
 * Algorithm (per query term t, per document d):
 *   1. IDF(t)  = ln(1 + (N − n_t + 0.5) / (n_t + 0.5))     // Lucene's always-positive form
 *   2. tf̃(t,d) = Σ_fields  w_f · tf(t, d_f) / (1 − b_f + b_f · |d_f| / avgdl_f)   // BM25F field combine
 *   3. add IDF(t) · tf̃ / (k1 + tf̃)                          // single saturation over the combined tf
 * then multiply the document's summed score by its `boost`. Length normalization is applied
 * *per field before* the field sum (so a short name and a long description normalize against
 * their own field's average), and saturation is applied *once over the combined* weighted tf —
 * this is the standard BM25F formulation, not a per-field BM25 sum (which would double-count
 * saturation and let a flood of one field dominate).
 */
export function rankBm25(docs: RankDoc[], query: string, opts: RankOptions = {}): RankResult[] {
  const qTerms = [...new Set(tokenize(query))];
  if (qTerms.length === 0 || docs.length === 0) return [];

  const k1 = opts.k1 ?? DEFAULT_K1;
  const defaultB = opts.b ?? DEFAULT_B;
  const N = docs.length;
  const qSet = new Set(qTerms);

  // Pass 1: tokenize every field once, accumulate per-field length totals (for avgdl), and the
  // document-frequency of each query term (a term counts once per document, in any field).
  const fieldKeys = new Set<string>();
  const lenSum = new Map<string, number>();
  const perDoc: FieldStats[][] = new Array(N);
  const df = new Map<string, number>();

  for (let i = 0; i < N; i++) {
    const stats: FieldStats[] = [];
    const termsInDoc = new Set<string>();
    for (const f of docs[i].fields) {
      const toks = tokenize(f.text);
      const tf = new Map<string, number>();
      for (const t of toks) {
        const prev = tf.get(t);
        if (prev === undefined) {
          tf.set(t, 1);
          if (qSet.has(t)) termsInDoc.add(t);
        } else {
          tf.set(t, prev + 1);
        }
      }
      stats.push({ tf, len: toks.length, weight: f.weight, b: f.b ?? defaultB });
      fieldKeys.add(f.key);
      lenSum.set(f.key, (lenSum.get(f.key) ?? 0) + toks.length);
    }
    for (const t of termsInDoc) df.set(t, (df.get(t) ?? 0) + 1);
    perDoc[i] = stats;
    // Track each field's key positionally so avgdl lookups align (fields are emitted in a stable order).
  }

  // avgdl per field key, treating every document as carrying every field (missing → length 0).
  const avgdl = new Map<string, number>();
  for (const key of fieldKeys) avgdl.set(key, (lenSum.get(key) ?? 0) / N);

  // IDF per query term.
  const idf = new Map<string, number>();
  for (const t of qTerms) {
    const n = df.get(t) ?? 0;
    idf.set(t, Math.log(1 + (N - n + 0.5) / (n + 0.5)));
  }

  // Pass 2: score each document.
  const results: RankResult[] = [];
  for (let i = 0; i < N; i++) {
    const doc = docs[i];
    const stats = perDoc[i];
    let score = 0;
    for (const t of qTerms) {
      const w = idf.get(t);
      if (!w) continue;
      let weightedTf = 0;
      for (let fi = 0; fi < doc.fields.length; fi++) {
        const fs = stats[fi];
        const tf = fs.tf.get(t);
        if (!tf) continue;
        const key = doc.fields[fi].key;
        const avg = avgdl.get(key) || 1;
        const norm = 1 - fs.b + fs.b * (fs.len / avg);
        weightedTf += (fs.weight * tf) / (norm > 0 ? norm : 1);
      }
      if (weightedTf > 0) score += w * (weightedTf / (k1 + weightedTf));
    }
    score *= doc.boost ?? 1;
    const exact = doc.exact === true;
    if (score > 0 || exact) results.push({ id: doc.id, score, exact });
  }

  // Exact matches first; then by descending score; ties keep input order (stable sort in Node).
  results.sort((a, b) => (a.exact !== b.exact ? (a.exact ? -1 : 1) : b.score - a.score));
  return typeof opts.limit === "number" ? results.slice(0, Math.max(0, opts.limit)) : results;
}
