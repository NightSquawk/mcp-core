/**
 * `mcp-guard init <server>`: a starting policy with reads on and everything else off.
 *
 * mcp-guard never writes the protected policy folder itself and never asks to be
 * run with sudo. It prints the commands for an admin to read and run, so nothing
 * the agent's user can change (this package included) ever runs as admin. With
 * the NST_MCP_POLICY_DIR test override it writes the file directly.
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { posix, win32 } from "node:path";
import { basePolicySchema } from "../guard/policy.js";
import { DEFAULT_PROGRAM_DATA, programDataDir } from "../guard/paths.js";
import { requireServer, serverContext } from "./context.js";
import { CliError, EXIT, rootWarning, type CliIo, type Outcome } from "./io.js";
import { adminCommands, psHereString, psQuote, renderAdmin, shHereDoc, shQuote, type AdminCommands } from "./shell.js";

export interface InitArgs {
  server?: string;
  force?: boolean;
  print?: boolean;
}

/**
 * Windows: take over a chain of folders, top first, one at a time (Set-AdminFolder, in shell.ts):
 * each is made if it is missing, Administrators own it, the entries anyone else added are dropped,
 * and the result is checked before the next one. Every folder from the first one `protect` picks
 * stops inheriting. The folders above it get the entries Windows gives ProgramData itself
 * (-UsersMayCreate), set on each folder rather than inherited, so Users may still add to them; the
 * check allows that there and nowhere else.
 */
export function windowsFolderCommands(chain: readonly string[], protect: (dir: string) => boolean): string[] {
  const first = chain.findIndex(protect);
  return chain.map((dir, i) => `Set-AdminFolder ${psQuote(dir)}${protect(dir) ? " -Protect" : first > i ? " -UsersMayCreate" : ""}`);
}

export function starterPolicy(server: string): Record<string, unknown> {
  return { version: 1, server, groups: { read: true, change: false, critical: false, spend: false }, environment: { allow_live: false } };
}

export function starterPolicyText(server: string): string {
  const policy = starterPolicy(server);
  basePolicySchema.parse(policy); // the starter must always load
  return `${JSON.stringify(policy, null, 2)}\n`;
}

/** Root-owned folders (0755) and file (0644), written through sudo tee. */
export function posixPolicyCommands(root: string, server: string, text: string, fileName = "policy.json"): string[] {
  const dir = posix.join(root, server);
  const file = posix.join(dir, fileName);
  return [
    `sudo install -d -m 0755 -o 0 -g 0 ${shQuote(root)} ${shQuote(dir)}`,
    `sudo chown 0:0 ${shQuote(root)} ${shQuote(dir)}`,
    `sudo chmod 0755 ${shQuote(root)} ${shQuote(dir)}`,
    shHereDoc(`sudo tee ${shQuote(file)} > /dev/null`, text),
    `sudo chown 0:0 ${shQuote(file)}`,
    `sudo chmod 0644 ${shQuote(file)}`,
  ];
}

/**
 * Administrators own NightSquawk, the policy root, the server's folder and the file (the protection
 * check reads each owner). The policy root stops inheriting from ProgramData (where Users may create
 * folders), and the folder and file below it inherit only SYSTEM and Administrators full control
 * plus Users read. NightSquawk gets the entries Windows gives ProgramData itself, so other software
 * can keep its own folders there; they are set on it rather than inherited, because ProgramData's
 * CREATOR OWNER entry can give the account that made it full control of it. The folders are taken
 * over before the file is written, so nobody else can change them in between. adminCommands()
 * makes this one block, which stops at the first step that fails.
 */
export function windowsPolicyCommands(root: string, server: string, text: string, fileName = "policy.json"): string[] {
  const parent = win32.dirname(root);
  const dir = win32.join(root, server);
  const file = win32.join(dir, fileName);
  return [
    ...windowsFolderCommands([parent, root, dir], (d) => d === root),
    psHereString("policy", text),
    `Write-NewFile ${psQuote(file)} $policy`,
    `Set-AdminFile ${psQuote(file)}`,
    `icacls ${psQuote(file)}`,
  ];
}

/** The commands that write one file into a server's folder under the policy root (policy.json, harness-<client>.json). */
export function policyFileCommands(platform: NodeJS.Platform, root: string, server: string, text: string, fileName = "policy.json"): string[] {
  return platform === "win32" ? windowsPolicyCommands(root, server, text, fileName) : posixPolicyCommands(root, server, text, fileName);
}

export function policyCommands(platform: NodeJS.Platform, root: string, server: string, text: string): AdminCommands {
  return adminCommands(platform, policyFileCommands(platform, root, server, text));
}

export function initCommand(args: InitArgs, io: CliIo): Outcome {
  const server = requireServer(args.server, "init");
  const ctx = serverContext(server, io);
  const text = starterPolicyText(server);
  const policy = starterPolicy(server);
  if (args.print) return { code: EXIT.ok, data: { server, policy }, text: [text.trimEnd()] };

  const path = ctx.standardPolicyPath;
  const exists = existsSync(path);
  if (exists && !args.force) {
    throw new CliError(`${path} already exists; mcp-guard status ${server} shows it. --force replaces it with the read-only starter.`, EXIT.fail, { path });
  }

  if (ctx.override) {
    const lib = io.platform === "win32" ? win32 : posix;
    mkdirSync(lib.dirname(path), { recursive: true });
    writeFileSync(path, text, { mode: 0o644 });
    return {
      code: EXIT.ok,
      data: { server, path, written: true, replaced: exists, override: true, policy },
      text: [
        `Wrote ${path}${exists ? " (replaced)" : ""}.`,
        "NST_MCP_POLICY_DIR is set, so this policy is for tests only: it never counts as protected, and critical and spend stay off outside sandbox mode.",
      ],
    };
  }

  const admin = policyCommands(io.platform, ctx.root, server, text);
  const warnings = [...rootWarning(io)];
  if (io.platform === "win32" && programDataDir(io.env).toLowerCase() !== DEFAULT_PROGRAM_DATA.toLowerCase()) {
    warnings.push(`ProgramData is ${programDataDir(io.env)}, not ${DEFAULT_PROGRAM_DATA}. Every folder above the policy must be admin-owned for it to count as protected.`);
  }
  const edit =
    io.platform === "win32"
      ? `Edit it later from an elevated editor, then run mcp-guard status ${server} as the agent's user.`
      : `Edit it later with sudoedit ${shQuote(path)} (your editor runs as you, the file is written as root), then run mcp-guard status ${server} as the agent's user.`;
  return {
    code: EXIT.admin,
    data: { server, path, written: false, replaces: exists, admin, warnings, policy },
    text: [
      ...warnings,
      ...renderAdmin(admin, `mcp-guard does not write ${ctx.root} itself. This policy enables reads only; read the commands first.`),
      edit,
    ],
  };
}
