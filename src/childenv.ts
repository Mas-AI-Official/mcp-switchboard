/**
 * Environment for stdio upstream children (design vNext 3.6).
 *
 * 0.1.0 handed every stdio upstream a copy of the gateway's whole environment, so one npm package
 * launched through `npx` could read every provider key the operator had in a shell. Now a child gets
 * only:
 *   1. the MCP SDK's safe default environment (PATH, HOME or the Windows equivalents, ...);
 *   2. a small per-platform allowlist of variables a child process needs to run at all;
 *   3. the server's own `env` and `credentials` (resolved by the registry, layered on top);
 *   4. names the operator lists in `env_passthrough`.
 * Nothing else crosses. A passthrough name that looks like a secret is refused unless it is ALSO listed
 * in `env_passthrough_secrets`, so handing a key through is always a deliberate, visible act (the
 * supported route for a secret is `credentials` with a `${vault:..}` reference).
 */

import { getDefaultEnvironment } from "@modelcontextprotocol/client/stdio";

/** Windows variables a child needs beyond the SDK defaults (design 3.6, verbatim). */
export const WINDOWS_ENV_ALLOWLIST: readonly string[] = [
  "SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA",
  "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
  "NPM_CONFIG_CACHE", "NODE_EXTRA_CA_CERTS",
];

/** POSIX counterpart: the SDK already covers HOME, LOGNAME, PATH, SHELL, TERM and USER. */
export const POSIX_ENV_ALLOWLIST: readonly string[] = ["TMPDIR", "LANG", "LC_ALL", "NPM_CONFIG_CACHE", "NODE_EXTRA_CA_CERTS"];

/**
 * The names the SDK's default environment may contribute, pinned to the SDK 1.x lists the closed world was designed
 * against. SDK 2.x widened its Windows defaults (PROGRAMW6432 among others); a dependency upgrade must not widen
 * what a child sees, so anything the SDK returns outside these names is dropped.
 */
const SDK_DEFAULT_NAMES: Readonly<Record<"win32" | "posix", ReadonlySet<string>>> = {
  win32: new Set([
    "APPDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH", "PROCESSOR_ARCHITECTURE", "SYSTEMDRIVE", "SYSTEMROOT",
    "TEMP", "USERNAME", "USERPROFILE", "PROGRAMFILES",
  ]),
  posix: new Set(["HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER"]),
};

const SECRET_WORDS: ReadonlySet<string> = new Set([
  "key", "keys", "token", "tokens", "secret", "secrets", "password", "passwords", "passwd", "passphrase", "credential",
  "credentials", "cookie", "cookies", "session", "bearer", "auth", "authorization", "jwt", "signature", "apikey", "privatekey",
]);
const SECRET_GLUED = /apikey|secret|token|password|passwd|credential|privatekey|passphrase/i;

/** Does this variable NAME look like it carries a secret? Token based, so `KEYBOARD_LAYOUT` is not one. */
export function isSecretEnvName(name: string): boolean {
  if (SECRET_GLUED.test(name)) return true;
  return name
    .replace(/(\p{Ll}|\p{N})(\p{Lu})/gu, "$1 $2")
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean)
    .some((t) => SECRET_WORDS.has(t.toLowerCase()));
}

/** A readable reason when `env_passthrough` / `env_passthrough_secrets` is inconsistent, else undefined. */
export function passthroughProblem(passthrough: readonly string[] = [], secrets: readonly string[] = []): string | undefined {
  const acked = new Set(secrets.map((n) => n.toUpperCase()));
  const listed = new Set(passthrough.map((n) => n.toUpperCase()));
  for (const name of passthrough) {
    if (isSecretEnvName(name) && !acked.has(name.toUpperCase())) {
      return `env_passthrough '${name}' looks like a secret: also list it in env_passthrough_secrets to pass it on purpose, or inject it with credentials: \${vault:NAME}`;
    }
  }
  for (const name of secrets) {
    if (!listed.has(name.toUpperCase())) {
      return `env_passthrough_secrets '${name}' must also be listed in env_passthrough`;
    }
  }
  return undefined;
}

/** A function body from a bash export (`()...`) is never a value to forward; the SDK skips them too. */
const forwardable = (v: string | undefined): v is string => typeof v === "string" && !v.startsWith("()");

/**
 * SDK default environment plus the platform allowlist, read from the gateway's own environment.
 * Names are written in the allowlist's spelling; Windows looks them up case-insensitively.
 */
export function baseChildEnv(platform: NodeJS.Platform = process.platform): Record<string, string> {
  const pinned = SDK_DEFAULT_NAMES[platform === "win32" ? "win32" : "posix"];
  const env: Record<string, string> = {};
  for (const [name, v] of Object.entries(getDefaultEnvironment())) if (pinned.has(name.toUpperCase())) env[name] = v;
  for (const name of platform === "win32" ? WINDOWS_ENV_ALLOWLIST : POSIX_ENV_ALLOWLIST) {
    const v = process.env[name];
    if (forwardable(v)) env[name] = v;
  }
  return env;
}

/**
 * The SDK's stdio transport spreads its own default environment under the env it is given, so a default name left out
 * of `env` would still reach the child. Each such name is masked with undefined (Node's spawn skips undefined values),
 * so the child sees exactly `env`.
 */
export function exactChildEnv(env: Record<string, string>): Record<string, string> {
  const have = new Set(Object.keys(env).map((k) => k.toUpperCase()));
  const masked: Record<string, string | undefined> = { ...env };
  for (const name of Object.keys(getDefaultEnvironment())) if (!have.has(name.toUpperCase())) masked[name] = undefined;
  return masked as Record<string, string>;
}

/**
 * The operator's `env_passthrough` names, read from the gateway's own environment. Throws when a name
 * looks like a secret and is not acknowledged in `env_passthrough_secrets`; a listed name the gateway
 * does not have is simply absent from the child.
 */
export function passthroughEnv(
  serverId: string,
  passthrough: readonly string[] = [],
  secrets: readonly string[] = [],
): Record<string, string> {
  const problem = passthroughProblem(passthrough, secrets);
  if (problem) throw new Error(`server '${serverId}': ${problem}`);
  const env: Record<string, string> = {};
  for (const name of passthrough) {
    const v = process.env[name];
    if (forwardable(v)) env[name] = v;
  }
  return env;
}
