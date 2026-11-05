/**
 * Where the policy (5.1) and the per-user state (audit log, ledger, idempotency
 * store, automatic kill-switch trips) live.
 */
import { homedir } from "node:os";
import { posix, win32 } from "node:path";

export interface PathOptions {
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  home?: string;
}

const SERVER_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export function assertServerName(server: string): void {
  if (!SERVER_NAME.test(server)) throw new Error(`Invalid server name ${JSON.stringify(server)} (expected ${SERVER_NAME}).`);
}

function pathLib(platform: NodeJS.Platform) {
  return platform === "win32" ? win32 : posix;
}

export const DEFAULT_PROGRAM_DATA = "C:\\ProgramData";

/**
 * Windows ProgramData from the environment. A blank or non drive-absolute value
 * (which would resolve against the working folder), or one holding a control
 * character or line separator, falls back to C:\ProgramData. The protection check
 * verifies owners, so a redirected value cannot make a user-owned folder count as
 * protected.
 */
export function programDataDir(env: NodeJS.ProcessEnv): string {
  const raw = (env.ProgramData ?? "").trim() || (env.PROGRAMDATA ?? "").trim();
  if (!/^[A-Za-z]:[\\/]/.test(raw)) return DEFAULT_PROGRAM_DATA;
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x2028 || c === 0x2029) return DEFAULT_PROGRAM_DATA;
  }
  return raw;
}

/** The directory holding every server's policy folder, and whether it is the test override. */
export function policyRoot(opts: PathOptions = {}): { root: string; override: boolean } {
  const platform = opts.platform ?? process.platform;
  const env = opts.env ?? process.env;
  const override = (env.NST_MCP_POLICY_DIR ?? "").trim();
  if (override) return { root: pathLib(platform).resolve(override), override: true };
  if (platform === "win32") {
    return { root: win32.join(programDataDir(env), "NightSquawk", "mcp"), override: false };
  }
  return { root: "/etc/nightsquawk-mcp", override: false };
}

export function policyPath(server: string, opts: PathOptions = {}): string {
  assertServerName(server);
  const platform = opts.platform ?? process.platform;
  return pathLib(platform).join(policyRoot(opts).root, server, "policy.json");
}

/** Manual kill-switch markers (7.8): one per server, and one for every server. */
export function killMarkers(server: string, opts: PathOptions = {}): { server: string; all: string } {
  assertServerName(server);
  const platform = opts.platform ?? process.platform;
  const { root } = policyRoot(opts);
  const p = pathLib(platform);
  return { server: p.join(root, server, "KILL"), all: p.join(root, "KILL") };
}

/** Per-user state folder for one server. */
export function stateDir(server: string, opts: PathOptions = {}): string {
  assertServerName(server);
  const platform = opts.platform ?? process.platform;
  const env = opts.env ?? process.env;
  const p = pathLib(platform);
  const override = (env.NST_MCP_STATE_DIR ?? "").trim();
  if (override) return p.join(p.resolve(override), server);
  const home = opts.home ?? homedir();
  if (platform === "win32") {
    const local = (env.LOCALAPPDATA ?? "").trim() || win32.join(home, "AppData", "Local");
    return win32.join(local, "NightSquawk", "mcp", server);
  }
  const xdg = (env.XDG_STATE_HOME ?? "").trim() || posix.join(home, ".local", "state");
  return posix.join(xdg, "nightsquawk-mcp", server);
}
