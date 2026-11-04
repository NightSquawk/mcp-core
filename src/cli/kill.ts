/**
 * The stop and recovery commands: kill, unkill, reset and cancel.
 *
 * - `kill` writes the manual marker next to the policy (admin rights in a
 *   protected install; mcp-guard prints the commands when it cannot write).
 *   `kill --soft` trips the user's own state instead: instant, but anything
 *   running as that user can clear it.
 * - `unkill`, `reset` and `cancel` undo a stop or reopen a call, so each asks a
 *   person at a terminal to type a confirmation first.
 * - reset, cancel and soft kills leave an alert line in the server's audit log.
 */
import { copyFileSync, existsSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { AuditLog, type AuditEntry } from "../guard/audit.js";
import { IdempotencyStateError, IdempotencyStore, type IdemEntry } from "../guard/idempotency.js";
import { KillSwitch } from "../guard/kill-switch.js";
import { readJsonFile } from "../guard/lock.js";
import { hasUnsafePathChar } from "../guard/protection.js";
import { GUARD_VERSION } from "../guard/version.js";
import { fileStamp, knownServers, pathLib, requireServer, serverContext, type ServerContext } from "./context.js";
import { CliError, confirmTyped, EXIT, needsAdmin, rootWarning, type CliIo, type Outcome } from "./io.js";
import { adminCommands, psQuote, renderAdmin, shQuote } from "./shell.js";
import { keySuffix } from "./snapshot.js";

/** The kill marker's note is read back as at most 300 characters (KillSwitch.state). */
export const NOTE_MAX = 300;
/** cancel needs at least this much of a key. */
export const MIN_KEY_PART = 8;

export interface KillArgs {
  server?: string;
  all?: boolean;
  note?: string;
  soft?: boolean;
}

function target(args: { server?: string; all?: boolean }, command: string, io: CliIo): { ctx: ServerContext | null; marker: string; label: string; root: string } {
  if (args.all && args.server) throw new CliError(`${command}: give a server or --all, not both.`, EXIT.usage);
  if (args.all) {
    const known = knownServers(io);
    return { ctx: null, marker: pathLib(io.platform).join(known.root, "KILL"), label: "every server", root: known.root };
  }
  const server = requireServer(args.server, command);
  const ctx = serverContext(server, io);
  return { ctx, marker: ctx.markers.server, label: server, root: ctx.root };
}

/** Write an alert line to a server's audit log. Failure is reported, never thrown. */
export function cliAlert(io: CliIo, ctx: ServerContext, command: string, note: string, extra: Partial<AuditEntry> = {}): string | null {
  try {
    new AuditLog(ctx.stateDir, ctx.server, { clock: io.clock }).append({
      server: ctx.server,
      version: "cli",
      guard: GUARD_VERSION,
      session: `cli:${io.pid}`,
      tool: "mcp-guard",
      operation: `cli.${command}`,
      tier: "unknown",
      group: null,
      mode: "none",
      decision: "alert",
      alert: `cli_${command}`,
      dry_run: false,
      note,
      ...extra,
    });
    return null;
  } catch (e) {
    return `Could not write the audit line for ${ctx.server}: ${(e as Error).message}`;
  }
}

function checkNote(note: string | undefined): string | undefined {
  if (note === undefined) return undefined;
  const n = note.trim();
  if (!n) return undefined;
  if (hasUnsafePathChar(n)) throw new CliError("--note must be one line without control characters.", EXIT.usage);
  if (n.length > NOTE_MAX) throw new CliError(`--note is limited to ${NOTE_MAX} characters.`, EXIT.usage);
  return n;
}

function markerCommands(io: CliIo, marker: string, content: string, dirMissing: boolean) {
  const lib = pathLib(io.platform);
  const dir = lib.dirname(marker);
  const line = content.trimEnd();
  if (io.platform === "win32") {
    return adminCommands(io.platform, [
      ...(dirMissing ? [`New-Item -ItemType Directory -Force -Path ${psQuote(dir)} | Out-Null`] : []),
      `[System.IO.File]::WriteAllText(${psQuote(marker)}, ${psQuote(line)})`,
    ]);
  }
  return adminCommands(io.platform, [
    ...(dirMissing ? [`sudo install -d -m 0755 -o 0 -g 0 ${shQuote(dir)}`] : []),
    `printf '%s\\n' ${shQuote(line)} | sudo tee ${shQuote(marker)} > /dev/null`,
    `sudo chmod 0644 ${shQuote(marker)}`,
  ]);
}

function softKill(args: KillArgs, io: CliIo, note: string | undefined): Outcome {
  if (args.all && args.server) throw new CliError("kill: give a server or --all, not both.", EXIT.usage);
  const servers = args.all ? knownServers(io).all : [requireServer(args.server, "kill")];
  if (!servers.length) throw new CliError("No servers found under the policy root or your state root.");
  const reason = `mcp-guard kill --soft${note ? `: ${note}` : ""}`;
  const warnings: string[] = [];
  const tripped: string[] = [];
  for (const s of servers) {
    const ctx = serverContext(s, io);
    mkdirSync(ctx.stateDir, { recursive: true, mode: 0o700 });
    new KillSwitch({ markers: ctx.markers, stateDir: ctx.stateDir, clock: io.clock }).trip("all", reason);
    tripped.push(s);
    const w = cliAlert(io, ctx, "kill_soft", reason);
    if (w) warnings.push(w);
  }
  return {
    code: EXIT.ok,
    data: { soft: true, servers: tripped, reason, warnings },
    text: [
      `Soft kill: every group but read is stopped for ${tripped.join(", ")}, from the next call on.`,
      "It lives in your own state folder, so anything running as you can clear it (mcp-guard reset). For a stop the agent's user cannot undo, an admin sets the marker: mcp-guard kill without --soft.",
      ...warnings,
    ],
  };
}

export function killCommand(args: KillArgs, io: CliIo): Outcome {
  const note = checkNote(args.note);
  if (args.soft) return softKill(args, io, note);
  const t = target(args, "kill", io);
  const content = `${note ?? "Stopped with mcp-guard kill."} (${io.clock().toISOString()})\n`;
  const lib = pathLib(io.platform);
  try {
    if (t.ctx?.override || (!t.ctx && knownServers(io).override)) mkdirSync(lib.dirname(t.marker), { recursive: true });
    writeFileSync(t.marker, content, { mode: 0o644 });
  } catch (e) {
    if (!needsAdmin(e)) throw e;
    const admin = markerCommands(io, t.marker, content, !existsSync(lib.dirname(t.marker)));
    const soft = args.all ? "mcp-guard kill --soft --all" : `mcp-guard kill --soft ${t.label}`;
    return {
      code: EXIT.admin,
      data: { marker: t.marker, written: false, admin },
      text: [
        ...rootWarning(io),
        ...renderAdmin(admin, `You cannot write ${t.marker} (that takes admin rights in a protected install).`),
        `Until an admin runs them, ${soft} stops it from your account (an agent running as you can undo that).`,
      ],
    };
  }
  return {
    code: EXIT.ok,
    data: { marker: t.marker, written: true, scope: args.all ? "all" : t.label },
    text: [`Kill switch set for ${t.label}: ${t.marker}`, "Every group but read stops from the next call on; no restart needed. mcp-guard unkill clears it."],
  };
}

export async function unkillCommand(args: { server?: string; all?: boolean }, io: CliIo): Promise<Outcome> {
  const t = target(args, "unkill", io);
  if (!existsSync(t.marker)) {
    return { code: EXIT.ok, data: { marker: t.marker, removed: false, was_set: false }, text: [`The kill switch for ${t.label} is not set (${t.marker}).`] };
  }
  await confirmTyped(io, `This lets calls run again for ${t.label} (removes ${t.marker}).`, args.all ? "all" : t.label);
  try {
    unlinkSync(t.marker);
  } catch (e) {
    if (!needsAdmin(e) || !existsSync(t.marker)) throw e;
    const admin = adminCommands(io.platform, [io.platform === "win32" ? `Remove-Item -LiteralPath ${psQuote(t.marker)} -Force` : `sudo rm -f -- ${shQuote(t.marker)}`]);
    return {
      code: EXIT.admin,
      data: { marker: t.marker, removed: false, admin },
      text: [...rootWarning(io), ...renderAdmin(admin, `You cannot remove ${t.marker} (that takes admin rights in a protected install).`)],
    };
  }
  return {
    code: EXIT.ok,
    data: { marker: t.marker, removed: true },
    text: [`Kill switch cleared for ${t.label}. Automatic trips (mcp-guard status) are separate: mcp-guard reset clears those.`],
  };
}

function moveAsideCommand(io: CliIo, file: string, to: string): string {
  return io.platform === "win32" ? `Move-Item -LiteralPath ${psQuote(file)} -Destination ${psQuote(to)}` : `mv -- ${shQuote(file)} ${shQuote(to)}`;
}

export async function resetCommand(args: { server?: string }, io: CliIo): Promise<Outcome> {
  const server = requireServer(args.server, "reset");
  const ctx = serverContext(server, io);
  const ks = new KillSwitch({ markers: ctx.markers, stateDir: ctx.stateDir, clock: io.clock });
  let killCorrupt = false;
  try {
    readJsonFile(ks.file, { trips: [] });
  } catch {
    killCorrupt = true;
  }
  const trips = killCorrupt ? [] : ks.state().trips;
  const store = new IdempotencyStore(ctx.stateDir, { clock: io.clock });
  let idemBroken: IdempotencyStateError | null = null;
  try {
    store.entries();
  } catch (e) {
    if (!(e instanceof IdempotencyStateError)) throw e;
    idemBroken = e;
  }
  const stamp = fileStamp(io.clock());
  const broken = new AuditLog(ctx.stateDir, server).verifyAll().filter((c) => !c.ok);
  const auditAdvice = broken.flatMap((b) => [
    `The audit chain in ${b.file} is broken at line ${b.brokenAt} (${b.reason}). The server trips again at its next start while that file is in place.`,
    `  After you have inspected it: ${moveAsideCommand(io, b.file, `${b.file}.broken-${stamp}`)}`,
  ]);
  const manual = ks.state().manual;
  const manualNote = manual.server || manual.all ? [`The manual kill switch is set too (${manual.all ? manual.markers.all : manual.markers.server}); reset does not clear it (mcp-guard unkill).`] : [];

  if (!trips.length && !killCorrupt && !idemBroken) {
    return { code: EXIT.ok, data: { server, cleared: 0, broken_audit: broken.map((b) => b.file) }, text: [`Nothing to reset for ${server}.`, ...auditAdvice, ...manualNote] };
  }

  const plan: string[] = [];
  for (const t of trips) plan.push(`clear the automatic trip (${t.scope}) from ${t.at}: ${t.reason}`);
  if (killCorrupt) plan.push(`replace the unreadable ${ks.file} (a copy is kept as ${ks.file}.corrupt-${stamp})`);
  if (idemBroken) {
    plan.push(
      `move the unreadable idempotency store aside to ${idemBroken.file}.corrupt-${stamp}. Every call it recorded can then run again if retried: check the provider for each before retrying anything.`
    );
  }
  await confirmTyped(io, [`mcp-guard reset ${server} will:`, ...plan.map((p) => `  - ${p}`)].join("\n"), server);

  if (killCorrupt) copyFileSync(ks.file, `${ks.file}.corrupt-${stamp}`);
  const cleared = ks.reset();
  let movedTo: string | null = null;
  if (idemBroken) {
    movedTo = `${idemBroken.file}.corrupt-${stamp}`;
    renameSync(idemBroken.file, movedTo);
  }
  const note = `cleared ${cleared} trip(s)${killCorrupt ? "; replaced an unreadable kill.json" : ""}${movedTo ? `; moved the idempotency store aside to ${movedTo}` : ""}`;
  const warning = cliAlert(io, ctx, "reset", note);
  return {
    code: EXIT.ok,
    data: { server, cleared, kill_file_replaced: killCorrupt, idempotency_moved_to: movedTo, broken_audit: broken.map((b) => b.file), ...(warning ? { warning } : {}) },
    text: [`Reset ${server}: ${note}.`, ...auditAdvice, ...manualNote, ...(warning ? [warning] : [])],
  };
}

export interface CancelArgs {
  key?: string;
  server?: string;
}

export async function cancelCommand(args: CancelArgs, io: CliIo): Promise<Outcome> {
  const needle = (args.key ?? "").trim();
  if (needle.length < MIN_KEY_PART) throw new CliError(`cancel needs at least ${MIN_KEY_PART} characters of the idempotency key (mcp-guard status <server> lists open entries).`, EXIT.usage);
  const servers = args.server ? [requireServer(args.server, "cancel")] : knownServers(io).state;
  const matches: Array<{ ctx: ServerContext; entry: IdemEntry; store: IdempotencyStore }> = [];
  const unreadable: string[] = [];
  for (const s of servers) {
    const ctx = serverContext(s, io);
    const store = new IdempotencyStore(ctx.stateDir, { clock: io.clock });
    let entries: IdemEntry[];
    try {
      entries = store.entries();
    } catch (e) {
      if (!(e instanceof IdempotencyStateError)) throw e;
      unreadable.push(`${s}: ${e.message}`);
      continue;
    }
    for (const entry of entries) if (entry.key.startsWith(needle) || entry.key.endsWith(needle)) matches.push({ ctx, entry, store });
  }
  const unreadableNote = unreadable.length ? ` Unreadable stores: ${unreadable.join(" ")}` : "";
  if (!matches.length) throw new CliError(`No idempotency entry matches ${JSON.stringify(needle)}.${unreadableNote}`);
  if (matches.length > 1) {
    const list = matches.map((m) => `${m.ctx.server} ...${keySuffix(m.entry.key)} (${m.entry.status})`).join(", ");
    throw new CliError(`${matches.length} entries match ${JSON.stringify(needle)}: ${list}. Give more of the key.`);
  }
  const { ctx, entry, store } = matches[0];
  const where = `${ctx.server} ${entry.operation} ...${keySuffix(entry.key)} (created ${entry.created_at})`;
  const data = { server: ctx.server, key: entry.key, operation: entry.operation, status: entry.status };
  if (entry.status === "done") throw new CliError(`${where} completed. Cancelling it would let the same request run a second time.`, EXIT.fail, data);
  if (entry.status === "in_flight") {
    throw new CliError(`${where} is running right now (pid ${entry.pid}). Wait for it to finish; if its process died it shows as unknown after five minutes.`, EXIT.fail, data);
  }
  if (entry.status === "failed") {
    return { code: EXIT.ok, data: { ...data, changed: false }, text: [`${where} already failed (or was cancelled): a retry runs it again. Nothing to do.`] };
  }

  let expected: string;
  let what: string;
  if (entry.status === "pending") {
    const p = entry.result?.pending ?? {};
    expected = p.ref ?? "cancelled";
    what = [
      `${where} is waiting for approval${p.ref ? ` (reference ${p.ref}${p.status ? `, ${p.status}` : ""})` : ""}${p.url ? ` at ${p.url}` : ""}.`,
      "Cancel it at the provider or approval system first: this only lets a retry run, it cancels nothing there.",
      p.ref ? `To confirm it is cancelled there, type its reference.` : `To confirm it is cancelled there, type "cancelled".`,
    ].join("\n");
  } else {
    expected = keySuffix(entry.key);
    what = [
      `${where} has an unknown outcome: the call may have run at the provider.`,
      `Check the provider for ${entry.operation} around ${entry.created_at} first. If it did run, do not cancel: a retry would run it twice.`,
      "To mark it failed so a retry runs it, type the last 12 characters of the key.",
    ].join("\n");
  }
  await confirmTyped(io, what, expected);
  const changed = store.cancel(entry.key);
  if (!changed) throw new CliError(`${where} changed while you were confirming; mcp-guard status ${ctx.server} shows it now.`, EXIT.fail, data);
  const warning = cliAlert(io, ctx, "cancel", `marked ${entry.status} entry failed`, { idempotency_key: entry.key });
  return {
    code: EXIT.ok,
    data: { ...data, changed: true, new_status: changed.status, ...(warning ? { warning } : {}) },
    text: [`Marked failed: a retry of ${entry.operation} will run it again. Nothing was cancelled at the provider.`, ...(warning ? [warning] : [])],
  };
}
