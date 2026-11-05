/**
 * `mcp-guard status [<server>]`: what the guard would enable, and why not.
 * Read-only: it never creates or changes a file.
 */
import { existsSync } from "node:fs";
import type { Mode } from "../guard/approvers.js";
import { IMPLEMENTED_APPROVERS } from "../guard/policy.js";
import { GROUPS } from "../guard/tiers.js";
import { knownServers, pathLib, requireServer, serverContext, type ServerContext } from "./context.js";
import { CliError, EXIT, type CliIo, type Outcome } from "./io.js";
import { formatCents, keySuffix, MODES, openEntries, snapshotServer, type ServerSnapshot } from "./snapshot.js";

export interface StatusArgs {
  server?: string;
  file?: string;
  mode?: Mode;
}

/** Left-aligned columns, two spaces apart. */
export function table(rows: string[][]): string[] {
  const widths: number[] = [];
  for (const r of rows) r.forEach((c, i) => (widths[i] = Math.max(widths[i] ?? 0, c.length)));
  return rows.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(widths[i]))).join("  ").trimEnd());
}

export function statusNotes(ctx: ServerContext, loaded: ServerSnapshot["loaded"]): string[] {
  const P = ctx.envPrefix;
  return [
    `The server's own environment can only narrow this: ${P}_PROFILE=reader or NST_MCP_READONLY=1 make it read-only, ${P}_ALLOW_WRITES=false turns off every group but read, and ${P}_ALLOW_DESTRUCTIVE=false and ${P}_ALLOW_SPEND=false turn off critical and spend. An unrecognized value counts as false.` +
      (loaded.source === "default" && !loaded.error ? ` With no policy file, a legacy ${P}_ALLOW_WRITES=true still raises change (deprecated).` : ""),
    "Server-specific checks (such as a verified live key) run only inside the server.",
    `This assumes the default env prefix ${P} and the built-in approvers (${IMPLEMENTED_APPROVERS.join(", ")}); a server can set its own.`,
    "Protection is checked as the user running mcp-guard. Run status as the user the agent runs as.",
  ];
}

function groupsText(snap: ServerSnapshot): string[] {
  const modes = Object.keys(snap.effective) as Mode[];
  const notes = new Map<string, number>();
  const foot: string[] = [];
  const rows: string[][] = [["group", ...modes.map((m) => `mode ${m}`)]];
  for (const g of GROUPS) {
    const cells = modes.map((m) => {
      const s = snap.effective[m]!.groups[g];
      if (s.enabled) return "on";
      const key = `${s.reason_code}\u0000${s.reason}`;
      let n = notes.get(key);
      if (n === undefined) {
        n = notes.size + 1;
        notes.set(key, n);
        foot.push(`  [${n}] ${s.reason_code}: ${s.reason}`);
        if (s.how_to_enable) foot.push(`      to enable: ${s.how_to_enable}`);
      }
      return `off [${n}]`;
    });
    rows.push([g, ...cells]);
  }
  return [...table(rows).map((l) => `  ${l}`), ...foot];
}

function serverText(snap: ServerSnapshot, warnings: string[], notes: string[]): string[] {
  const { ctx, loaded, protection, kill, ledger, idempotency, audit } = snap;
  const out: string[] = [`${ctx.server}: policy ${loaded.path}${ctx.override ? " (NST_MCP_POLICY_DIR override: tests only)" : ""}`];
  if (loaded.source === "file") {
    out.push(`  file: sha256 ${loaded.hash}${loaded.mtimeMs !== null ? `, modified ${new Date(loaded.mtimeMs).toISOString()}` : ""}`);
  } else if (loaded.error) {
    out.push(`  REJECTED, so the server runs read-only: ${loaded.error}`);
  } else {
    out.push("  no policy file: the read-only default applies (mcp-guard init writes one)");
  }
  if (snap.serverSpecificKeys.length) out.push(`  keys the base schema does not know (server-specific, or typos): ${snap.serverSpecificKeys.join(", ")}`);

  out.push(`protection: ${protection.protected ? "protected" : "NOT protected"}`);
  for (const r of [...protection.part1.reasons, ...protection.part2.reasons]) out.push(`  - ${r}`);

  out.push("groups:");
  out.push(...groupsText(snap));
  const first = Object.values(snap.effective)[0];
  if (first) out.push(`approvers: ${GROUPS.filter((g) => g !== "read").map((g) => `${g}=${first.approvers[g]}`).join(", ")}`);

  const manual = kill.manual.all ? `set for every server (${kill.manual.markers.all})` : kill.manual.server ? `set (${kill.manual.markers.server})` : "not set";
  out.push(`kill switch: ${manual}${kill.manual.note ? `; note: ${kill.manual.note}` : ""}`);
  if (kill.problem) out.push(`  ${kill.file} is ${kill.problem}, which stops every group: mcp-guard reset ${ctx.server} after checking why`);
  else for (const t of kill.trips) out.push(`  automatic trip (${t.scope}) at ${t.at}: ${t.reason}`);

  const spend = Object.entries(ledger.spendToday);
  const calls = GROUPS.filter((g) => g !== "read").map((g) => `${g} ${ledger.callsToday[g]}`).join(", ");
  out.push(`today (UTC): calls ${calls}; spend ${spend.length ? spend.map(([c, v]) => `${c} ${formatCents(v)}`).join(", ") : "none"}`);
  if (ledger.corrupt) out.push(`  ${ledger.file} is not valid JSON; the guard rebuilds it from the audit log`);

  if (!idempotency.ok) {
    out.push(`idempotency: UNREADABLE, so no non-read call runs: ${idempotency.error}`);
  } else {
    const open = openEntries(idempotency);
    out.push(`idempotency: ${idempotency.entries.length} entr${idempotency.entries.length === 1 ? "y" : "ies"}, ${open.length} open`);
    for (const e of open) {
      const ref = e.result?.pending?.ref ? ` ref ${e.result.pending.ref}` : "";
      out.push(`  ...${keySuffix(e.key)}  ${e.status.padEnd(9)}  ${e.operation}  created ${e.created_at}${ref}`);
    }
  }

  const broken = audit.filter((c) => !c.ok);
  const lines = audit.reduce((n, c) => n + c.lines, 0);
  out.push(`audit: ${audit.length} file${audit.length === 1 ? "" : "s"}, ${lines} line${lines === 1 ? "" : "s"}, ${broken.length ? `${broken.length} BROKEN` : `chain${audit.length === 1 ? "" : "s"} intact`}`);
  for (const b of broken) out.push(`  ${b.file}: broken at line ${b.brokenAt} (${b.reason})`);

  if (warnings.length) out.push("warnings:", ...warnings.map((w) => `  - ${w}`));
  out.push("notes:", ...notes.map((n) => `  - ${n}`), ...protection.notes.map((n) => `  - ${n}`));
  return out;
}

export function snapshotWarnings(snap: ServerSnapshot): string[] {
  const w = new Set<string>();
  for (const e of Object.values(snap.effective)) for (const x of e?.warnings ?? []) w.add(x);
  if (snap.serverSpecificKeys.length) {
    w.add(
      `The policy has keys the base schema does not know (${snap.serverSpecificKeys.join(", ")}). They are fine if the server's schema defines them; a typo makes the server reject the policy and run read-only, which this view cannot show.`
    );
  }
  if (snap.ctx.policyPath !== snap.ctx.standardPolicyPath) w.add(`--file: the server itself reads ${snap.ctx.standardPolicyPath}.`);
  return [...w];
}

function statusOne(args: StatusArgs, io: CliIo): Outcome {
  const server = requireServer(args.server, "status");
  const ctx = serverContext(server, io, args.file ? { file: args.file } : {});
  if (args.file && !existsSync(ctx.policyPath)) throw new CliError(`No such file: ${ctx.policyPath}`);
  const snap = snapshotServer(ctx, io, args.mode ? [args.mode] : MODES);
  const warnings = snapshotWarnings(snap);
  const notes = statusNotes(ctx, snap.loaded);
  const { loaded, protection, kill, ledger, idempotency, audit } = snap;
  const data = {
    server,
    policy: {
      path: loaded.path,
      standard_path: ctx.standardPolicyPath,
      source: loaded.source,
      override: loaded.override,
      hash: loaded.hash,
      modified: loaded.mtimeMs !== null ? new Date(loaded.mtimeMs).toISOString() : null,
      ...(loaded.error ? { error: loaded.error } : {}),
      server_specific_keys: snap.serverSpecificKeys,
      allow_live: loaded.policy.environment.allow_live,
      tiers_off: loaded.policy.tiers_off,
      limits: loaded.policy.limits,
      allowlists: Object.fromEntries(Object.entries(loaded.policy.allowlists).map(([k, v]) => [k, v.length])),
    },
    protection,
    effective: snap.effective,
    kill: { manual: kill.manual, trips: kill.trips, corrupt: kill.corrupt, problem: kill.problem, file: kill.file },
    today: { calls: ledger.callsToday, spend_cents: ledger.spendToday, ledger_corrupt: ledger.corrupt },
    idempotency: idempotency.ok
      ? {
          ok: true,
          entries: idempotency.entries.length,
          open: openEntries(idempotency).map((e) => ({
            key_suffix: keySuffix(e.key),
            status: e.status,
            operation: e.operation,
            created_at: e.created_at,
            ...(e.result?.pending ? { pending: e.result.pending } : {}),
          })),
        }
      : { ok: false, file: idempotency.file, error: idempotency.error },
    audit: audit.map((c) => ({ file: c.file, ok: c.ok, lines: c.lines, ...(c.ok ? {} : { broken_at: c.brokenAt, reason: c.reason }) })),
    state_dir: ctx.stateDir,
    warnings,
    notes: [...notes, ...protection.notes],
  };
  return { code: EXIT.ok, data, text: serverText(snap, warnings, notes) };
}

function statusAll(io: CliIo): Outcome {
  const known = knownServers(io);
  const allMarker = pathLib(io.platform).join(known.root, "KILL");
  const allKilled = existsSync(allMarker);
  const rows: string[][] = [["server", "policy", "state", "kill"]];
  const servers = known.all.map((s) => {
    const ctx = serverContext(s, io);
    const entry = { server: s, policy_file: existsSync(ctx.standardPolicyPath), state: known.state.includes(s), killed: existsSync(ctx.markers.server) };
    rows.push([s, entry.policy_file ? "file" : "-", entry.state ? "yes" : "-", entry.killed ? "SET" : "-"]);
    return entry;
  });
  const text = [
    `policy root: ${known.root}${known.override ? " (NST_MCP_POLICY_DIR override: tests only)" : ""}${allKilled ? `; kill switch for every server SET (${allMarker})` : ""}`,
    `state root (yours): ${known.stateRoot}`,
    ...(servers.length ? table(rows) : ["no servers found"]),
    ...(servers.length ? ["mcp-guard status <server> shows one in full."] : []),
  ];
  return {
    code: EXIT.ok,
    data: { policy_root: known.root, override: known.override, state_root: known.stateRoot, kill_all: allKilled, servers },
    text,
  };
}

export function statusCommand(args: StatusArgs, io: CliIo): Outcome {
  return args.server ? statusOne(args, io) : statusAll(io);
}
