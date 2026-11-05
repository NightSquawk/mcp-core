/**
 * `mcp-guard manifest`: check a server's dist/guard-manifest.json (section 4).
 * Clients decide how much to trust a tool from its annotations and _meta, so a
 * manifest that marks a writing tool read-only, or drops the destructive hint
 * from a spend tool, fails.
 */
import { readFileSync } from "node:fs";
import { MANIFEST_VERSION } from "../guard/manifest.js";
import { KNOWN_FLAGS } from "../guard/tiers-check.js";
import { GROUP_ANNOTATIONS, GROUPS, groupToolName, isGroup, isTier, REQUIRES_USER_INTERACTION, TIER_GROUP, TIERS, type Group, type Tier } from "../guard/tiers.js";
import { isServerName, pathLib } from "./context.js";
import { CliError, errnoCode, EXIT, type CliIo, type Outcome } from "./io.js";

export interface ManifestIssue {
  level: "fail" | "warn";
  where: string;
  message: string;
}

export interface ManifestReport {
  ok: boolean;
  server: string | null;
  tools: number;
  operations: number;
  counts: Record<Tier, number>;
  issues: ManifestIssue[];
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export function checkManifest(raw: unknown): ManifestReport {
  const issues: ManifestIssue[] = [];
  const fail = (where: string, message: string) => void issues.push({ level: "fail", where, message });
  const warn = (where: string, message: string) => void issues.push({ level: "warn", where, message });
  const counts = Object.fromEntries(TIERS.map((t) => [t, 0])) as Record<Tier, number>;
  const report = (server: string | null, tools: number, operations: number): ManifestReport => ({
    ok: !issues.some((i) => i.level === "fail"),
    server,
    tools,
    operations,
    counts,
    issues,
  });
  if (!isRecord(raw)) {
    fail("(root)", "the manifest is not a JSON object");
    return report(null, 0, 0);
  }
  if (raw.manifest_version !== MANIFEST_VERSION) fail("manifest_version", `expected ${MANIFEST_VERSION}, found ${JSON.stringify(raw.manifest_version)}`);
  const server = typeof raw.server === "string" && isServerName(raw.server) ? raw.server : null;
  if (!server) fail("server", `not a valid server name: ${JSON.stringify(raw.server)}`);
  for (const k of ["version", "guard_version", "prefix"]) if (typeof raw[k] !== "string" || !raw[k]) fail(k, "missing or not a string");
  const prefix = typeof raw.prefix === "string" ? raw.prefix : null;
  const tools = Array.isArray(raw.tools) ? raw.tools : (fail("tools", "not an array"), []);
  const ops = Array.isArray(raw.operations) ? raw.operations : (fail("operations", "not an array"), []);

  const byName = new Map<string, { group: Group; operations: unknown }>();
  tools.forEach((t, i) => {
    const where = `tools[${i}]${isRecord(t) && typeof t.name === "string" ? ` ${t.name}` : ""}`;
    if (!isRecord(t) || typeof t.name !== "string" || !t.name) return fail(where, "a tool needs a name");
    if (byName.has(t.name)) fail(where, "duplicate tool name");
    if (!isGroup(t.group)) return fail(where, `unknown group ${JSON.stringify(t.group)}`);
    const group = t.group;
    byName.set(t.name, { group, operations: t.operations });
    if (!Array.isArray(t.tiers) || !t.tiers.every(isTier)) fail(where, "tiers must be a list of tier names");
    else for (const tier of t.tiers as Tier[]) if (TIER_GROUP[tier] !== group) fail(where, `tier ${tier} belongs to ${TIER_GROUP[tier] ?? "no group"}, not ${group}`);
    const ann = isRecord(t.annotations) ? t.annotations : {};
    if (group !== "read" && ann.readOnlyHint === true) fail(where, `annotations.readOnlyHint is true on a ${group} tool: clients may run it without asking`);
    if ((group === "critical" || group === "spend") && ann.destructiveHint !== true) fail(where, `annotations.destructiveHint must be true on a ${group} tool`);
    if (group === "read" && ann.readOnlyHint !== true) warn(where, "annotations.readOnlyHint should be true on a read tool");
    // The hints checked above are settled; any other difference from the group's annotations is a warning.
    const settled = (k: string) => k === "readOnlyHint" || (k === "destructiveHint" && group !== "change");
    for (const [k, v] of Object.entries(GROUP_ANNOTATIONS[group])) {
      if (!settled(k) && ann[k] !== v) warn(where, `annotations.${k} is ${JSON.stringify(ann[k])}; the ${group} group uses ${JSON.stringify(v)}`);
    }
    const meta = isRecord(t._meta) ? t._meta : null;
    if ((group === "critical" || group === "spend") && meta?.[REQUIRES_USER_INTERACTION] !== true) {
      warn(where, `no _meta["${REQUIRES_USER_INTERACTION}"]: clients will not ask the user before each call. That is right only for a group with an unattended human approver (6.5).`);
    }
  });
  if (prefix) {
    for (const g of GROUPS) {
      const t = byName.get(groupToolName(prefix, g));
      if (t && t.group !== g) fail(`tools ${groupToolName(prefix, g)}`, `named for the ${g} group but in the ${t.group} group`);
    }
  }
  const groupToolsMode = prefix !== null && GROUPS.some((g) => byName.get(groupToolName(prefix, g))?.group === g);

  const seen = new Set<string>();
  const perTool = new Map<string, number>();
  ops.forEach((o, i) => {
    const where = `operations[${i}]${isRecord(o) && typeof o.operation === "string" ? ` ${o.operation}` : ""}`;
    if (!isRecord(o) || typeof o.operation !== "string" || !o.operation) return fail(where, "an operation needs a name");
    if (seen.has(o.operation)) fail(where, "duplicate operation");
    seen.add(o.operation);
    if (!isTier(o.tier)) return fail(where, `unknown tier ${JSON.stringify(o.tier)}`);
    counts[o.tier]++;
    const group = TIER_GROUP[o.tier];
    if (o.group !== group) fail(where, `group is ${JSON.stringify(o.group)}, but tier ${o.tier} belongs to ${group === null ? "no group (null)" : group}`);
    if (group === null) {
      if (o.tool !== null) fail(where, "a blocked operation must not have a tool");
    } else if (o.tool === null || o.tool === undefined) {
      if (groupToolsMode && prefix) fail(where, `no tool, but ${groupToolName(prefix, group)} runs the ${group} group`);
    } else if (typeof o.tool !== "string" || !byName.has(o.tool)) {
      fail(where, `tool ${JSON.stringify(o.tool)} is not in tools`);
    } else {
      const tool = byName.get(o.tool)!;
      if (tool.group !== group) fail(where, `tool ${o.tool} is in the ${tool.group} group, not ${group}`);
      perTool.set(o.tool, (perTool.get(o.tool) ?? 0) + 1);
    }
    if (o.flags !== undefined) {
      if (!isRecord(o.flags)) fail(where, "flags must be an object");
      else
        for (const [k, v] of Object.entries(o.flags)) {
          if (!(KNOWN_FLAGS as readonly string[]).includes(k)) fail(where, `unknown flag ${k}`);
          else if (typeof v !== "boolean") fail(where, `flag ${k} must be true or false`);
        }
    }
  });
  if (prefix) {
    for (const g of GROUPS) {
      const name = groupToolName(prefix, g);
      const t = byName.get(name);
      if (t && t.group === g && t.operations !== (perTool.get(name) ?? 0)) fail(`tools ${name}`, `says ${JSON.stringify(t.operations)} operations, but ${perTool.get(name) ?? 0} list it`);
    }
  }
  return report(server, byName.size, seen.size);
}

export interface ManifestLocation {
  path: string;
  /** Named with --manifest or --package (a missing file is an error, not a skip). */
  explicit: boolean;
}

export function locateManifest(io: CliIo, args: { manifest?: string; package?: string }): ManifestLocation {
  const lib = pathLib(io.platform);
  if (args.manifest && args.package) throw new CliError("Give --manifest or --package, not both.", EXIT.usage);
  if (args.manifest) return { path: lib.resolve(io.cwd, args.manifest), explicit: true };
  if (args.package) return { path: lib.resolve(io.cwd, args.package, "dist", "guard-manifest.json"), explicit: true };
  return { path: lib.resolve(io.cwd, "dist", "guard-manifest.json"), explicit: false };
}

/** Read and parse a manifest. null when it is missing and was not asked for by name. */
export function readManifest(loc: ManifestLocation): unknown | null {
  let text: string;
  try {
    text = readFileSync(loc.path, "utf8");
  } catch (e) {
    if (errnoCode(e) === "ENOENT" && !loc.explicit) return null;
    throw new CliError(`Cannot read ${loc.path}: ${(e as Error).message}`);
  }
  try {
    return JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch (e) {
    throw new CliError(`${loc.path} is not valid JSON: ${(e as Error).message}`);
  }
}

export function renderManifestReport(r: ManifestReport, path: string): string[] {
  const tiers = Object.entries(r.counts)
    .filter(([, n]) => n > 0)
    .map(([t, n]) => `${t} ${n}`)
    .join(", ");
  return [
    `${path}: ${r.ok ? "ok" : "FAILED"}${r.server ? ` (${r.server})` : ""}, ${r.tools} tool${r.tools === 1 ? "" : "s"}, ${r.operations} operation${r.operations === 1 ? "" : "s"}${tiers ? ` (${tiers})` : ""}`,
    ...r.issues.map((i) => `  ${i.level}: ${i.where}: ${i.message}`),
  ];
}

export function manifestCommand(args: { manifest?: string; package?: string }, io: CliIo): Outcome {
  const loc = locateManifest(io, args);
  const raw = readManifest({ ...loc, explicit: true });
  const r = checkManifest(raw);
  return { code: r.ok ? EXIT.ok : EXIT.fail, data: { path: loc.path, ...r }, text: renderManifestReport(r, loc.path) };
}
