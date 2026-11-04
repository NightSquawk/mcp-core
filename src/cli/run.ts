/**
 * Argument parsing and dispatch. Exit codes: 0 ok, 1 failed or refused,
 * 2 usage error, 3 an admin has to run the printed commands.
 */
import { parseArgs } from "node:util";
import { GUARD_VERSION } from "../guard/version.js";
import { canaryCommand } from "./canary.js";
import { harnessCommand } from "./harness.js";
import { hookCommand } from "./hook.js";
import { initCommand } from "./init.js";
import { CliError, EXIT, type CliIo, type Outcome } from "./io.js";
import { cancelCommand, killCommand, resetCommand, unkillCommand } from "./kill.js";
import { manifestCommand } from "./manifest.js";
import { isMode } from "./snapshot.js";
import { statusCommand } from "./status.js";
import { verifyCommand } from "./verify.js";
import { watchCommand } from "./watch.js";

type OptionSpec = { type: "string" | "boolean"; short?: string; multiple?: boolean };
type Value = string | boolean | Array<string | boolean> | undefined;
type Values = Record<string, Value>;

interface Command {
  usage: string;
  summary: string;
  options: Record<string, OptionSpec>;
  /** How many positionals it takes at most. */
  positionals: number;
  run(values: Values, positionals: string[], io: CliIo): Outcome | Promise<Outcome>;
}

const str = (v: Value): string | undefined => (typeof v === "string" ? v : undefined);
const bool = (v: Value): boolean => v === true;
const list = (v: Value): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : typeof v === "string" ? [v] : []);
const many: OptionSpec = { type: "string", multiple: true };

const VERIFY_ONLY = ["strict", "file", "manifest", "package", "tiers", "operations"] as const;
const WATCH_ONLY = ["project", "baseline", "accept"] as const;

export const COMMANDS: Readonly<Record<string, Command>> = Object.freeze({
  status: {
    usage: "status [<server>] [--file <policy.json>] [--mode live|sandbox|none]",
    summary: "What the guard would enable for a server, and why each group is off. Without a server: the servers found. Never writes.",
    options: { file: { type: "string" }, mode: { type: "string" } },
    positionals: 1,
    run: (v, p, io) => {
      const mode = str(v.mode);
      if (mode !== undefined && !isMode(mode)) throw new CliError("--mode is live, sandbox or none.", EXIT.usage);
      if (str(v.file) && !p[0]) throw new CliError("--file needs a server name too.", EXIT.usage);
      return statusCommand({ server: p[0], file: str(v.file), mode }, io);
    },
  },
  init: {
    usage: "init <server> [--force] [--print]",
    summary: "A starting policy (reads only). Prints the admin commands that install it; --print prints only the policy.",
    options: { force: { type: "boolean" }, print: { type: "boolean" } },
    positionals: 1,
    run: (v, p, io) => initCommand({ server: p[0], force: bool(v.force), print: bool(v.print) }, io),
  },
  canary: {
    usage: "canary add <server> [<id>...] [--file <policy.json>] [--print]",
    summary:
      "Add decoy records to a server's policy as salted hashes (needs the server's NST_MCP_CANARY_SALT). Ids from the arguments, or one per line on stdin. Prints the admin commands; --print prints only the hashes.",
    options: { file: { type: "string" }, print: { type: "boolean" } },
    positionals: Number.POSITIVE_INFINITY,
    run: (v, p, io) => canaryCommand({ action: p[0], server: p[1], ids: p.slice(2), file: str(v.file), print: bool(v.print) }, io),
  },
  kill: {
    usage: "kill <server>|--all [--note <text>] [--soft]",
    summary: "Stop every group but read. Writes the admin marker, or prints the commands; --soft trips your own state instead (instant, but clearable by anything running as you).",
    options: { all: { type: "boolean" }, note: { type: "string" }, soft: { type: "boolean" } },
    positionals: 1,
    run: (v, p, io) => killCommand({ server: p[0], all: bool(v.all), note: str(v.note), soft: bool(v.soft) }, io),
  },
  unkill: {
    usage: "unkill <server>|--all",
    summary: "Remove the manual kill marker. Asks you to type the server name (or all) at a terminal.",
    options: { all: { type: "boolean" } },
    positionals: 1,
    run: (v, p, io) => unkillCommand({ server: p[0], all: bool(v.all) }, io),
  },
  reset: {
    usage: "reset <server>",
    summary: "Clear automatic kill-switch trips, and move an unreadable idempotency store aside. Asks for confirmation at a terminal.",
    options: {},
    positionals: 1,
    run: (_v, p, io) => resetCommand({ server: p[0] }, io),
  },
  cancel: {
    usage: "cancel <key> [--server <server>]",
    summary: "Mark a pending or unknown call failed so a retry can run it. Cancels nothing at the provider. Asks for confirmation at a terminal.",
    options: { server: { type: "string" } },
    positionals: 1,
    run: (v, p, io) => cancelCommand({ key: p[0], server: str(v.server) }, io),
  },
  manifest: {
    usage: "manifest [--manifest <file> | --package <dir>]",
    summary: "Check a guard manifest (default ./dist/guard-manifest.json).",
    options: { manifest: { type: "string" }, package: { type: "string" } },
    positionals: 0,
    run: (v, _p, io) => manifestCommand({ manifest: str(v.manifest), package: str(v.package) }, io),
  },
  verify: {
    usage:
      "verify <server> [--strict] [--file <policy.json>] [--manifest <file> | --package <dir>] [--tiers <tiers.json> --operations <openapi.json>]\n" +
      "       mcp-guard verify --watch [--project <dir>]... [--baseline <file>] [--accept]",
    summary:
      "Pass/warn/fail checks of one install; exits 1 on any failure. --strict fails an unprotected policy. --watch: has any client's MCP, hook or permission config changed since the baseline? (one check, for a timer)",
    options: {
      strict: { type: "boolean" },
      file: { type: "string" },
      manifest: { type: "string" },
      package: { type: "string" },
      tiers: { type: "string" },
      operations: { type: "string" },
      watch: { type: "boolean" },
      project: many,
      baseline: { type: "string" },
      accept: { type: "boolean" },
    },
    positionals: 1,
    run: (v, p, io) => {
      if (bool(v.watch)) {
        if (p[0]) throw new CliError("--watch checks every client's config, not one server: drop the server name.", EXIT.usage);
        const extra = VERIFY_ONLY.filter((k) => v[k] !== undefined);
        if (extra.length) throw new CliError(`--watch does not take ${extra.map((k) => `--${k}`).join(", ")}.`, EXIT.usage);
        return watchCommand({ projects: list(v.project), baseline: str(v.baseline), accept: bool(v.accept) }, io);
      }
      const extra = WATCH_ONLY.filter((k) => v[k] !== undefined);
      if (extra.length) throw new CliError(`${extra.map((k) => `--${k}`).join(", ")} go${extra.length === 1 ? "es" : ""} with --watch.`, EXIT.usage);
      return verifyCommand(
        {
          server: p[0],
          strict: bool(v.strict),
          file: str(v.file),
          manifest: str(v.manifest),
          package: str(v.package),
          tiers: str(v.tiers),
          operations: str(v.operations),
        },
        io
      );
    },
  },
  harness: {
    usage:
      "harness <server> --claude|--codex|--cursor [--name <name in client config>]... [--allow-critical] [--allow-spend] [--manifest <file> | --package <dir>]\n" +
      "       Claude: [--hook [--taint-from <tool>]... | --hook --no-taint] [--sandbox [--deny-read <pattern>]... [--deny-write <pattern>]... [--allow-domain <domain>]...]\n" +
      "               [--mcp-command <JSON list: the server's command and args>]...\n" +
      "       Cursor: [--others ask|allow]; Claude --hook and Cursor: [--hook-script <mcp-guard dist/cli/index.js>]",
    summary:
      "Client rules from a server's guard manifest: read runs, change asks, critical and spend are denied. Prints admin commands and fragments to merge; writes nothing.",
    options: {
      claude: { type: "boolean" },
      codex: { type: "boolean" },
      cursor: { type: "boolean" },
      name: many,
      "allow-critical": { type: "boolean" },
      "allow-spend": { type: "boolean" },
      hook: { type: "boolean" },
      "no-taint": { type: "boolean" },
      "taint-from": many,
      sandbox: { type: "boolean" },
      "deny-read": many,
      "deny-write": many,
      "allow-domain": many,
      "mcp-command": many,
      others: { type: "string" },
      "hook-script": { type: "string" },
      manifest: { type: "string" },
      package: { type: "string" },
    },
    positionals: 1,
    run: (v, p, io) =>
      harnessCommand(
        {
          server: p[0],
          claude: bool(v.claude),
          codex: bool(v.codex),
          cursor: bool(v.cursor),
          names: list(v.name),
          allowCritical: bool(v["allow-critical"]),
          allowSpend: bool(v["allow-spend"]),
          hook: bool(v.hook),
          noTaint: bool(v["no-taint"]),
          taintFrom: list(v["taint-from"]),
          sandbox: bool(v.sandbox),
          denyRead: list(v["deny-read"]),
          denyWrite: list(v["deny-write"]),
          allowDomain: list(v["allow-domain"]),
          mcpCommand: list(v["mcp-command"]),
          others: str(v.others),
          hookScript: str(v["hook-script"]),
          manifest: str(v.manifest),
          package: str(v.package),
        },
        io
      ),
  },
  hook: {
    usage: "hook claude <server> | hook cursor [<server>] [--others ask|allow]",
    summary:
      "The permission hook harness installs. The client runs it with the request on stdin; it denies tools the harness rules deny, and for Claude also marks sessions that read outside text. Not for you to run.",
    options: { others: { type: "string" } },
    positionals: 2,
    run: (v, p, io) => hookCommand({ client: p[0], server: p[1], others: str(v.others), json: bool(v.json) }, io),
  },
});

export function usage(): string {
  const width = Math.max(...Object.keys(COMMANDS).map((c) => c.length));
  return [
    `mcp-guard ${GUARD_VERSION}: inspect and operate the NightSquawk MCP guard.`,
    "",
    "Commands:",
    ...Object.entries(COMMANDS).map(([name, c]) => `  ${name.padEnd(width)}  ${c.summary}`),
    "",
    "Every command takes --json. Exit codes: 0 ok, 1 failed or refused, 2 usage error, 3 an admin has to run the printed commands.",
    "mcp-guard <command> --help shows a command's options.",
  ].join("\n");
}

function print(io: CliIo, json: boolean, outcome: Outcome): number {
  if (json) io.out(JSON.stringify({ ok: outcome.code === EXIT.ok, code: outcome.code, ...outcome.data }, null, 2));
  else for (const line of outcome.text) io.out(line);
  return outcome.code;
}

export async function run(argv: readonly string[], io: CliIo): Promise<number> {
  const [name, ...rest] = argv;
  if (name === undefined || name === "help" || name === "--help" || name === "-h") {
    io.out(usage());
    return EXIT.ok;
  }
  if (name === "--version" || name === "version") {
    io.out(GUARD_VERSION);
    return EXIT.ok;
  }
  const command = Object.prototype.hasOwnProperty.call(COMMANDS, name) ? COMMANDS[name] : undefined;
  if (!command) {
    io.err(`mcp-guard: unknown command ${JSON.stringify(name)}. mcp-guard help lists them.`);
    return EXIT.usage;
  }
  let values: Values;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: [...rest],
      options: { json: { type: "boolean" }, help: { type: "boolean", short: "h" }, ...command.options },
      allowPositionals: true,
      strict: true,
    }) as { values: Values; positionals: string[] });
  } catch (e) {
    io.err(`mcp-guard: ${(e as Error).message}\nusage: mcp-guard ${command.usage}`);
    return EXIT.usage;
  }
  if (values.help === true) {
    io.out(`usage: mcp-guard ${command.usage}\n\n${command.summary}\n\nEvery command takes --json.`);
    return EXIT.ok;
  }
  const json = values.json === true;
  if (positionals.length > command.positionals) {
    io.err(`mcp-guard: unexpected argument ${JSON.stringify(positionals[command.positionals])}\nusage: mcp-guard ${command.usage}`);
    return EXIT.usage;
  }
  try {
    return print(io, json, await command.run(values, positionals, io));
  } catch (e) {
    const err = e instanceof CliError ? e : null;
    const code = err?.code ?? EXIT.fail;
    const message = e instanceof Error ? e.message : String(e);
    if (json) io.out(JSON.stringify({ ok: false, code, error: message, ...(err?.data ?? {}) }, null, 2));
    else io.err(`mcp-guard: ${message}${code === EXIT.usage ? `\nusage: mcp-guard ${command.usage}` : ""}`);
    return code;
  }
}
