/**
 * Where a server's policy, kill markers and state live, resolved exactly as the
 * guard resolves them (same env, platform and home).
 */
import { readdirSync } from "node:fs";
import { posix, win32 } from "node:path";
import { assertServerName, killMarkers, policyPath, policyRoot, stateDir, type PathOptions } from "../guard/paths.js";
import { CliError, EXIT, type CliIo } from "./io.js";

export function pathOptions(io: CliIo): PathOptions {
  return { platform: io.platform, env: io.env, home: io.home };
}

export function pathLib(platform: NodeJS.Platform): typeof posix {
  return platform === "win32" ? win32 : posix;
}

/** The guard's default env prefix (GuardOptions.envPrefix). */
export function defaultEnvPrefix(server: string): string {
  return server.toUpperCase().replace(/[^A-Z0-9]/g, "_");
}

export function isServerName(name: string): boolean {
  try {
    assertServerName(name);
    return true;
  } catch {
    return false;
  }
}

export function requireServer(name: string | undefined, command: string): string {
  if (!name) throw new CliError(`${command} needs a server name, e.g. mcp-guard ${command} column.`, EXIT.usage);
  if (!isServerName(name)) {
    throw new CliError(`Invalid server name ${JSON.stringify(name)}: lowercase letters, digits, _ or -, starting with a letter or digit, at most 64 characters.`, EXIT.usage);
  }
  return name;
}

export interface ServerContext {
  server: string;
  envPrefix: string;
  /** The policy file this command reads: --file, else where the guard reads it. */
  policyPath: string;
  /** Where the server's guard reads its policy. */
  standardPolicyPath: string;
  /** The policy root, and whether it is the NST_MCP_POLICY_DIR test override. */
  root: string;
  override: boolean;
  markers: { server: string; all: string };
  stateDir: string;
}

export function serverContext(server: string, io: CliIo, opts: { file?: string } = {}): ServerContext {
  const po = pathOptions(io);
  const { root, override } = policyRoot(po);
  const standard = policyPath(server, po);
  return {
    server,
    envPrefix: defaultEnvPrefix(server),
    policyPath: opts.file ? pathLib(io.platform).resolve(io.cwd, opts.file) : standard,
    standardPolicyPath: standard,
    root,
    override,
    markers: killMarkers(server, po),
    stateDir: stateDir(server, po),
  };
}

/** The folder that holds every server's state folder. `_watch` lives here too; it can never be a server name. */
export function stateRoot(io: CliIo): string {
  return pathLib(io.platform).dirname(stateDir("watch-probe", pathOptions(io)));
}

function serverDirs(dir: string): string[] {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory() && isServerName(d.name))
      .map((d) => d.name)
      .sort();
  } catch {
    return [];
  }
}

export interface KnownServers {
  root: string;
  override: boolean;
  stateRoot: string;
  /** Servers with a folder under the policy root. */
  policy: string[];
  /** Servers with a state folder for the user running the CLI. */
  state: string[];
  all: string[];
}

export function knownServers(io: CliIo): KnownServers {
  const { root, override } = policyRoot(pathOptions(io));
  const sr = stateRoot(io);
  const policy = serverDirs(root);
  const state = serverDirs(sr);
  return { root, override, stateRoot: sr, policy, state, all: [...new Set([...policy, ...state])].sort() };
}

/** A timestamp safe in a file name on every platform. */
export function fileStamp(d: Date): string {
  return d.toISOString().replace(/[:.]/g, "-");
}
