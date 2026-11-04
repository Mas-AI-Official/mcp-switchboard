/**
 * Package strings for stdio upstreams started through a package runner (`npx`, and `uvx` for PyPI).
 *
 * The package string is handed to the runner on its command line (`npx -y <package>`). A string that starts
 * with '-' is read as an option (`--call=...` runs a shell command), whitespace splits it into extra
 * arguments, and a URL, path or git spec makes the runner fetch and run code from somewhere that is not the
 * registry the operator pinned and aged. So a package is a NAME, optionally with `@version`, and nothing else.
 *
 * Pinning is separate from validity: a floating name (`pkg`, `pkg@latest`, `pkg@^1.2.0`) is still valid, because
 * existing configs have them and must keep mounting, but it gets a loud warning (startup log and `doctor`),
 * and a NEW mount (dashboard or catalog add) must carry an exact version.
 */

const NPM_PART = "[A-Za-z0-9][A-Za-z0-9._~-]*";
const NPM_NAME = new RegExp(`^(?:@${NPM_PART}/)?${NPM_PART}$`);
const NPM_NAME_MAX = 214;
/** A version, dist-tag or simple range (`1.2.3`, `latest`, `^1.2.0`): no whitespace, never a leading '-'. */
const NPM_VERSION_OR_TAG = /^[A-Za-z0-9^~<>=*][A-Za-z0-9._+~^<>=|*-]*$/;
const VERSION_MAX = 128;
/** Exact semver: major.minor.patch, optional pre-release and build metadata. */
const EXACT_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z][0-9A-Za-z.-]*)?$/;

export interface NpmSpec {
  name: string;
  version?: string;
}

/** Split `name`, `name@version`, `@scope/name` or `@scope/name@version`. The version separator is the first '@' after position 0. */
function splitNpm(spec: string): NpmSpec {
  const at = spec.indexOf("@", 1);
  return at === -1 ? { name: spec } : { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

/** A readable reason when `spec` is not an acceptable npm package string, else null. */
export function checkNpmSpec(spec: unknown): string | null {
  if (typeof spec !== "string" || spec.length === 0) return "the package string is empty";
  if (/\s/.test(spec)) return "the package string contains whitespace";
  if (spec.startsWith("-")) return "the package string starts with '-': npx would read it as an option, not as a package name";
  const { name, version } = splitNpm(spec);
  if (name.length > NPM_NAME_MAX || !NPM_NAME.test(name)) {
    return `'${name.slice(0, 60)}' is not a valid npm package name (letters, digits, '.', '_', '~' and '-', optionally scoped as @scope/name; URLs, paths and git specs are not accepted)`;
  }
  if (version !== undefined && (version.length > VERSION_MAX || !NPM_VERSION_OR_TAG.test(version))) {
    return `'${version.slice(0, 40)}' is not a valid version or dist-tag (letters, digits and . _ + ~ ^ < > = | * -, no spaces, not starting with '-')`;
  }
  return null;
}

/** True when `spec` is valid AND names one exact version (`name@1.2.3`). */
export function isPinnedNpmSpec(spec: unknown): boolean {
  if (checkNpmSpec(spec) !== null) return false;
  const { version } = splitNpm(spec as string);
  return version !== undefined && EXACT_VERSION.test(version);
}

/** True when `version` is an exact semver (what a new mount must carry). */
export function isExactNpmVersion(version: unknown): boolean {
  return typeof version === "string" && version.length <= VERSION_MAX && EXACT_VERSION.test(version);
}

/** The package name without its version; an unparseable spec is returned unchanged. */
export function npmPackageName(spec: string): string {
  return splitNpm(spec).name;
}

// --- PyPI (uvx) -------------------------------------------------------------------------------------------------

const PYPI_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const PYPI_VERSION = /^[0-9][A-Za-z0-9.+!_-]*$/;

function splitPypi(spec: string): { name: string; version?: string } {
  const m = /^([^=@]*)(?:==|@)(.*)$/.exec(spec);
  return m ? { name: m[1] ?? "", version: m[2] ?? "" } : { name: spec };
}

/** A readable reason when `spec` is not an acceptable PyPI package string (`name`, `name==1.2.3` or `name@1.2.3`), else null. */
export function checkPypiSpec(spec: unknown): string | null {
  if (typeof spec !== "string" || spec.length === 0) return "the package string is empty";
  if (/\s/.test(spec)) return "the package string contains whitespace";
  if (spec.startsWith("-")) return "the package string starts with '-': the runner would read it as an option, not as a package name";
  const { name, version } = splitPypi(spec);
  if (name.length > 214 || !PYPI_NAME.test(name)) return `'${name.slice(0, 60)}' is not a valid PyPI package name (letters, digits, '.', '_' and '-'; URLs, paths and version ranges are not accepted)`;
  if (version !== undefined && (version.length > VERSION_MAX || !PYPI_VERSION.test(version))) return `'${version.slice(0, 40)}' is not a valid exact version`;
  return null;
}

/** True when `spec` is valid AND carries an exact `==` (or `@`) version. */
export function isPinnedPypiSpec(spec: unknown): boolean {
  return checkPypiSpec(spec) === null && splitPypi(spec as string).version !== undefined;
}

// --- warnings ---------------------------------------------------------------------------------------------------

/** The slice of a server config the warning reads. */
interface PackageServer {
  id: string;
  source: string;
  package?: string;
  enabled?: boolean;
}

/** One loud warning per npx server whose package is not pinned to an exact version. */
export function unpinnedPackageWarnings(servers: readonly PackageServer[], opts: { enabledOnly?: boolean } = {}): string[] {
  const out: string[] = [];
  for (const s of servers) {
    if (s.source !== "npx" || typeof s.package !== "string") continue;
    if (opts.enabledOnly && s.enabled === false) continue;
    if (checkNpmSpec(s.package) !== null || isPinnedNpmSpec(s.package)) continue; // an invalid string is refused elsewhere
    out.push(
      `server '${s.id}' runs npx package '${s.package}' without an exact version: every start fetches whatever is newest on the registry (supply-chain risk). Pin it, for example '${npmPackageName(s.package)}@x.y.z'.`,
    );
  }
  return out;
}
