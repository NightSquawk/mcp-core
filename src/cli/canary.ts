/**
 * `mcp-guard canary add <server> [<id>...]`: adds decoy records (canaries) to a
 * server's policy.
 *
 * The policy lists only salted hashes (`sha256:` of `<salt>:<id>`, the guard's
 * canaryHash), and the salt is the server's NST_MCP_CANARY_SALT, so this command
 * needs the same salt in its own environment. With no ids as arguments it reads
 * them from stdin, one per line, which keeps them out of shell history. The ids
 * and the salt are never printed.
 *
 * Like init, mcp-guard writes the policy itself only under the NST_MCP_POLICY_DIR
 * test override. Otherwise it prints the admin commands that install the updated
 * file. Keys the base schema does not know (a server's own) are kept as they are.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { posix, win32 } from "node:path";
import { CANARY_SALT_ENV, canaryHash } from "../guard/canaries.js";
import { basePolicySchema } from "../guard/policy.js";
import { requireServer, serverContext } from "./context.js";
import { policyCommands } from "./init.js";
import { CliError, EXIT, rootWarning, type CliIo, type Outcome } from "./io.js";
import { renderAdmin, shQuote } from "./shell.js";
import { loadPolicyForCli, stripUnknownKeys } from "./snapshot.js";

export interface CanaryArgs {
  action?: string;
  server?: string;
  ids: string[];
  /** Read the current policy from this file instead of where the guard reads it. */
  file?: string;
  /** Print the hashes only. */
  print?: boolean;
}

/** One id per line. Surrounding spaces and blank lines are dropped. */
export function parseIds(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
}

async function readIds(args: CanaryArgs, io: CliIo): Promise<string[]> {
  if (args.ids.length) return args.ids.map((id) => id.trim()).filter(Boolean);
  if (io.interactive) io.err("Type the decoy ids, one per line, then Ctrl-D (Ctrl-Z and Enter on Windows):");
  return parseIds(await io.readStdin());
}

export async function canaryCommand(args: CanaryArgs, io: CliIo): Promise<Outcome> {
  if (args.action !== "add") {
    throw new CliError(
      args.action === undefined ? "canary needs an action: mcp-guard canary add <server> [<id>...]." : `Unknown canary action ${JSON.stringify(args.action)}: the only one is add.`,
      EXIT.usage
    );
  }
  const server = requireServer(args.server, "canary add");
  const ids = [...new Set(await readIds(args, io))];
  if (!ids.length) throw new CliError("No decoy ids given: pass them as arguments, or one per line on stdin.", EXIT.usage);

  const salt = io.env[CANARY_SALT_ENV];
  if (!salt) {
    throw new CliError(`Set ${CANARY_SALT_ENV} to the salt in the server's environment first: a hash matches only with the same salt.`, EXIT.fail);
  }
  const hashes = ids.map((id) => canaryHash(id, salt));
  if (args.print) return { code: EXIT.ok, data: { server, hashes }, text: hashes };

  const ctx = serverContext(server, io, { file: args.file });
  const { loaded } = loadPolicyForCli(ctx, io);
  if (loaded.error) throw new CliError(`${loaded.error} Fix it first (mcp-guard status ${server} shows the problem).`, EXIT.fail, { path: loaded.path });
  if (loaded.source !== "file") {
    throw new CliError(`No policy at ${loaded.path}. mcp-guard init ${server} writes a starting one; add the canaries to it after that.`, EXIT.fail, { path: loaded.path });
  }

  // The file loaded cleanly, so it is a JSON object. Edit the raw object, so the server's own keys stay.
  const text = readFileSync(loaded.path, "utf8");
  const raw = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text) as Record<string, unknown>;
  const canaries = (raw.canaries ?? {}) as Record<string, unknown>;
  const existing = Array.isArray(canaries.hashes) ? (canaries.hashes as string[]) : [];
  const added = hashes.filter((h) => !existing.includes(h));
  const target = ctx.standardPolicyPath;
  const warnings = [
    ...(ids.length > added.length ? [`${ids.length - added.length} of the ids ${ids.length - added.length === 1 ? "is" : "are"} already in the policy.`] : []),
  ];
  if (!added.length) {
    return { code: EXIT.ok, data: { server, path: loaded.path, added: 0, hashes: [] }, text: [`Every id given is already a canary in ${loaded.path}; nothing to change.`] };
  }

  raw.canaries = { ...canaries, hashes: [...existing, ...added] };
  const check = basePolicySchema.safeParse(stripUnknownKeys(basePolicySchema, raw, []));
  if (!check.success) {
    const issues = check.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ");
    throw new CliError(`The updated policy would not load: ${issues}`, EXIT.fail);
  }
  const updated = `${JSON.stringify(raw, null, 2)}\n`;
  const count = `${added.length} canar${added.length === 1 ? "y" : "ies"}`;
  const saltNote = `The server needs ${CANARY_SALT_ENV} set to the same salt: while canaries are listed and it is unset, every call but reads is refused (canary_salt_missing).`;

  if (ctx.override) {
    mkdirSync((io.platform === "win32" ? win32 : posix).dirname(target), { recursive: true });
    writeFileSync(target, updated, { mode: 0o644 });
    return {
      code: EXIT.ok,
      data: { server, path: target, written: true, added: added.length, hashes: added, override: true, warnings },
      text: [...warnings, `Added ${count} to ${target}.`, "NST_MCP_POLICY_DIR is set, so this policy is for tests only and never counts as protected.", saltNote],
    };
  }

  const admin = policyCommands(io.platform, ctx.root, server, updated);
  const all = [...rootWarning(io), ...warnings];
  const intro =
    `mcp-guard does not write ${ctx.root} itself. These commands rewrite ${target} with ${count} added ` +
    `(${loaded.path === target ? "the rest of the policy unchanged" : `starting from ${loaded.path}`}); read them first.`;
  const after =
    io.platform === "win32"
      ? `Then run mcp-guard status ${server} as the agent's user.`
      : `Then run mcp-guard status ${server} as the agent's user. To remove a canary later, delete its hash with sudoedit ${shQuote(target)}.`;
  return {
    code: EXIT.admin,
    data: { server, path: target, written: false, added: added.length, hashes: added, admin, warnings: all },
    text: [...all, ...renderAdmin(admin, intro), saltNote, after],
  };
}
