/**
 * `mcp-guard verify <server>`: pass/warn/fail checks of one install, for an admin
 * or a CI job. Exits 1 when any check fails. Read-only, like status.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import type { Mode } from "../guard/approvers.js";
import { checkTiers, type TierEntry } from "../guard/tiers-check.js";
import { GROUPS } from "../guard/tiers.js";
import { pathLib, requireServer, serverContext } from "./context.js";
import { CliError, EXIT, type CliIo, type Outcome } from "./io.js";
import { checkManifest, locateManifest, readManifest } from "./manifest.js";
import { snapshotServer, type ServerSnapshot } from "./snapshot.js";

export type Level = "pass" | "warn" | "fail" | "skip";

export interface VerifyCheck {
  id: string;
  level: Level;
  message: string;
  detail?: string[];
}

export interface VerifyArgs {
  server?: string;
  strict?: boolean;
  file?: string;
  manifest?: string;
  package?: string;
  tiers?: string;
  operations?: string;
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const HTTP_METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];

function readJson(io: CliIo, file: string, what: string): unknown {
  const path = pathLib(io.platform).resolve(io.cwd, file);
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new CliError(`Cannot read ${what} ${path}: ${(e as Error).message}`);
  }
  try {
    return JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch (e) {
    throw new CliError(`${what} ${path} is not valid JSON: ${(e as Error).message}`);
  }
}

/** Operations from an OpenAPI document, or from a JSON array of {operationId, method, path} (or plain ids). */
export function operationsFrom(raw: unknown): { operations: Array<{ operationId: string; method?: string; path?: string }>; withoutId: number } {
  if (Array.isArray(raw)) {
    const operations = raw.flatMap((o) => {
      if (typeof o === "string" && o) return [{ operationId: o }];
      if (isRecord(o) && typeof o.operationId === "string" && o.operationId) {
        return [{ operationId: o.operationId, ...(typeof o.method === "string" ? { method: o.method } : {}), ...(typeof o.path === "string" ? { path: o.path } : {}) }];
      }
      return [];
    });
    return { operations, withoutId: raw.length - operations.length };
  }
  if (isRecord(raw) && isRecord(raw.paths)) {
    const operations: Array<{ operationId: string; method: string; path: string }> = [];
    let withoutId = 0;
    for (const [path, item] of Object.entries(raw.paths)) {
      if (!isRecord(item)) continue;
      for (const m of HTTP_METHODS) {
        const op = item[m];
        if (!isRecord(op)) continue;
        if (typeof op.operationId === "string" && op.operationId) operations.push({ operationId: op.operationId, method: m.toUpperCase(), path });
        else withoutId++;
      }
    }
    return { operations, withoutId };
  }
  throw new CliError("--operations must be an OpenAPI document or a JSON array of {operationId, method, path}.");
}

/** The `operations` object of a tiers.json, or the object itself. */
export function tiersFrom(raw: unknown): Record<string, TierEntry> {
  const ops = isRecord(raw) && isRecord(raw.operations) ? raw.operations : raw;
  if (!isRecord(ops)) throw new CliError("--tiers must be a tiers.json: {\"operations\": {\"<operationId>\": {\"tier\": \"read\"}, ...}}.");
  return ops as Record<string, TierEntry>;
}

function statePermissions(io: CliIo, snap: ServerSnapshot): VerifyCheck {
  if (io.platform === "win32") return { id: "state-permissions", level: "skip", message: "Windows: the state folder inherits your profile's ACL" };
  const dir = snap.ctx.stateDir;
  if (!existsSync(dir)) return { id: "state-permissions", level: "skip", message: `no state folder yet (${dir})` };
  const loose: string[] = [];
  const check = (p: string) => {
    try {
      const mode = statSync(p).mode & 0o777;
      if (mode & 0o077) loose.push(`${p} is mode ${mode.toString(8).padStart(4, "0")}`);
    } catch {
      // vanished
    }
  };
  check(dir);
  for (const f of readdirSync(dir)) if (/^(audit-\d{4}-\d{2}\.jsonl|ledger\.json|idempotency\.json|kill\.json)$/.test(f)) check(pathLib(io.platform).join(dir, f));
  return loose.length
    ? { id: "state-permissions", level: "warn", message: "other users can read or change your state (the guard writes 0700/0600)", detail: loose }
    : { id: "state-permissions", level: "pass", message: `owner-only (${dir})` };
}

export function verifyCommand(args: VerifyArgs, io: CliIo): Outcome {
  const server = requireServer(args.server, "verify");
  const ctx = serverContext(server, io, args.file ? { file: args.file } : {});
  if (args.file && !existsSync(ctx.policyPath)) throw new CliError(`No such file: ${ctx.policyPath}`);
  if (Boolean(args.tiers) !== Boolean(args.operations)) throw new CliError("--tiers and --operations go together.", EXIT.usage);
  const snap = snapshotServer(ctx, io);
  const checks: VerifyCheck[] = [];
  const add = (id: string, level: Level, message: string, detail?: string[]) => void checks.push({ id, level, message, ...(detail?.length ? { detail } : {}) });
  const { loaded, protection, kill, ledger, idempotency, audit } = snap;

  if (loaded.error) add("policy", "fail", `rejected, so the server runs read-only: ${loaded.error}`);
  else if (loaded.source === "default") add("policy", "warn", `no policy file at ${loaded.path}: the read-only default applies (mcp-guard init ${server})`);
  else {
    add(
      "policy",
      "pass",
      `${loaded.path} loads (sha256 ${loaded.hash?.slice(0, 16)}...)`,
      snap.serverSpecificKeys.length ? [`keys only the server's own schema checks: ${snap.serverSpecificKeys.join(", ")}`] : undefined
    );
  }

  const reasons = [...protection.part1.reasons, ...protection.part2.reasons];
  if (protection.protected) add("protection", "pass", `protected, as seen by the user running mcp-guard`);
  else add("protection", args.strict ? "fail" : "warn", "not protected: critical and spend stay off outside sandbox mode", reasons);

  const summary = (Object.keys(snap.effective) as Mode[]).map((m) => {
    const on = GROUPS.filter((g) => snap.effective[m]!.groups[g].enabled);
    return `${m}: ${on.length ? on.join(", ") : "nothing"}`;
  });
  add("effective", "pass", `groups on per mode (server env and server checks can only narrow this): ${summary.join("; ")}`);

  if (kill.corrupt) add("kill", "fail", `${kill.file} is unreadable, which stops every group (mcp-guard reset ${server} after checking why)`);
  else if (kill.manual.server || kill.manual.all || kill.trips.length) {
    add("kill", "warn", "calls are stopped", [
      ...(kill.manual.all ? [`manual, every server: ${kill.manual.markers.all}`] : []),
      ...(kill.manual.server ? [`manual: ${kill.manual.markers.server}`] : []),
      ...kill.trips.map((t) => `automatic (${t.scope}) at ${t.at}: ${t.reason}`),
    ]);
  } else add("kill", "pass", "not set, no automatic trips");

  const broken = audit.filter((c) => !c.ok);
  if (!audit.length) add("audit", "skip", "no audit files yet");
  else if (broken.length) add("audit", "fail", `${broken.length} broken chain${broken.length === 1 ? "" : "s"}: the server trips its kill switch at start`, broken.map((b) => `${b.file}: line ${b.brokenAt} (${b.reason})`));
  else {
    const lines = audit.reduce((n, c) => n + c.lines, 0);
    add("audit", "pass", `${audit.length} file${audit.length === 1 ? "" : "s"}, ${lines} line${lines === 1 ? "" : "s"}, chain${audit.length === 1 ? "" : "s"} intact`);
  }

  if (!idempotency.ok) add("idempotency", "fail", idempotency.error);
  else {
    const unknown = idempotency.entries.filter((e) => e.status === "unknown");
    const pending = idempotency.entries.filter((e) => e.status === "pending");
    if (unknown.length) {
      add(
        "idempotency",
        "warn",
        `${unknown.length} call${unknown.length === 1 ? "" : "s"} with an unknown outcome: retries are refused until someone checks the provider (mcp-guard cancel)`,
        unknown.map((e) => `...${e.key.slice(-12)} ${e.operation} created ${e.created_at}`)
      );
    } else add("idempotency", "pass", `${idempotency.entries.length} entries, ${pending.length} pending approval`);
  }

  if (ledger.corrupt) add("ledger", "warn", `${ledger.file} is not valid JSON; the guard rebuilds it from the audit log`);
  else add("ledger", "pass", ledger.exists ? "readable" : "no ledger yet");

  checks.push(statePermissions(io, snap));

  const loc = locateManifest(io, args);
  let manifest: unknown | null = null;
  try {
    manifest = readManifest(loc);
  } catch (e) {
    if (!(e instanceof CliError)) throw e;
    add("manifest", "fail", e.message);
  }
  if (manifest !== null) {
    const r = checkManifest(manifest);
    if (!loc.explicit && r.server !== server) add("manifest", "skip", `${loc.path} is for ${r.server ?? "an unnamed server"}, not ${server}`);
    else if (r.server !== server) add("manifest", "fail", `${loc.path} is for ${r.server ?? "an unnamed server"}, not ${server}`);
    else {
      const fails = r.issues.filter((i) => i.level === "fail");
      add(
        "manifest",
        fails.length ? "fail" : r.issues.length ? "warn" : "pass",
        `${loc.path}: ${r.tools} tools, ${r.operations} operations`,
        r.issues.map((i) => `${i.level}: ${i.where}: ${i.message}`)
      );
    }
  } else if (!checks.some((c) => c.id === "manifest")) {
    add("manifest", "skip", "no dist/guard-manifest.json here (--package <dir> or --manifest <file>)");
  }

  if (args.tiers && args.operations) {
    const { operations, withoutId } = operationsFrom(readJson(io, args.operations, "operations file"));
    const r = checkTiers({ operations, tiers: tiersFrom(readJson(io, args.tiers, "tiers file")) });
    const detail = [...r.issues.map((i) => `${i.code}: ${i.operationId}: ${i.message}`), ...(withoutId ? [`${withoutId} operation(s) without an operationId were not checked`] : [])];
    add("tiers", r.ok ? "pass" : "fail", `${operations.length} operations: ${r.ok ? "every one has a known tier" : `${r.issues.length} issue(s)`}`, detail);
  } else add("tiers", "skip", "--tiers <tiers.json> --operations <openapi.json> checks a tiers file");

  const failed = checks.filter((c) => c.level === "fail").length;
  const warned = checks.filter((c) => c.level === "warn").length;
  const text = [
    ...checks.flatMap((c) => [`${c.level.padEnd(4)}  ${c.id.padEnd(17)}  ${c.message}`, ...(c.detail ?? []).map((d) => `${" ".repeat(25)}${d}`)]),
    `${server}: ${failed ? `${failed} failed` : "no failures"}${warned ? `, ${warned} warning${warned === 1 ? "" : "s"}` : ""}.`,
  ];
  return { code: failed ? EXIT.fail : EXIT.ok, data: { server, ok: failed === 0, checks }, text };
}
