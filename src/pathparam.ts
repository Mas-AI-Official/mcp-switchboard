/**
 * Path parameters for generated HTTP tools (http-tool and app2mcp).
 *
 * `encodeURIComponent` keeps every `/` out of a value, but it leaves `.` alone, and a URL parser treats a
 * path segment that is only dots as navigation: `/items/{id}` with id `..` becomes `/` once the request URL
 * is built, so a caller who may only read one item can reach the parent path. Writing the dots as `%2E` does
 * not help, because the WHATWG URL parser also collapses `%2e%2e` (checked by the hardening oracle).
 * The only safe answer is to refuse such a value before a request exists.
 */

/** A readable reason when `value` must not be written into a URL path segment, else undefined. */
export function pathParamProblem(value: string): string | undefined {
  if (value === "." || value === "..") {
    return `the value '${value}' is a dot segment that would move the request out of the declared path`;
  }
  return undefined;
}

/** A path segment that a URL parser reads as navigation: `.`, `..` or their `%2e` spellings. */
const DOT_SEGMENT = /^(?:\.|%2e){1,2}$/i;

/**
 * The same refusal on the FILLED path (the part after the host). Catches two substituted values that only
 * form a dot segment together (`{a}{b}` with `.` and `.`) and a template that carries one itself.
 */
export function dotSegmentProblem(filledPath: string): string | undefined {
  const path = filledPath.split(/[?#]/, 1)[0] ?? "";
  for (const segment of path.split("/")) {
    if (DOT_SEGMENT.test(segment)) return `the path contains the dot segment '${segment}'`;
  }
  return undefined;
}

/** The path of an absolute http(s) URL string, before any substitution is parsed (no normalisation). */
export function rawPathOf(url: string): string {
  const m = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*([^?#]*)/i.exec(url);
  return m ? (m[1] ?? "") : "";
}
