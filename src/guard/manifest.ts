/**
 * The guard manifest (section 4): tool -> group -> tiers, and every operation's
 * tier. It is static: every group that has operations, whatever the policy says
 * (the policy's effect is in guard://status). Servers write it to
 * dist/guard-manifest.json at build time and serve it as guard://manifest; the
 * `mcp-guard harness` generator reads it.
 */
import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import { GROUP_ANNOTATIONS, GROUPS, groupMeta, groupToolName, TIER_GROUP, type Group, type OperationFlags, type OperationRef, type Tier } from "./tiers.js";
import { GUARD_VERSION } from "./version.js";

export const MANIFEST_VERSION = 1 as const;

export interface ManifestTool {
  name: string;
  group: Group;
  tiers: Tier[];
  operations: number;
  annotations: ToolAnnotations;
  _meta: Record<string, unknown> | null;
}

export interface ManifestOperation {
  operation: string;
  tier: Tier;
  group: Group | null;
  tool: string | null;
  flags?: OperationFlags;
}

export interface GuardManifest {
  manifest_version: typeof MANIFEST_VERSION;
  server: string;
  version: string;
  guard_version: string;
  prefix: string;
  tools: ManifestTool[];
  operations: ManifestOperation[];
}

export interface ManifestInput {
  server: string;
  version: string;
  prefix: string;
  operations: readonly OperationRef[];
  /** Extra tools in a group, e.g. `<prefix>_list_endpoints` (read). Hand-written servers list every tool here. */
  extraTools?: ReadonlyArray<{ name: string; group: Group; tiers?: Tier[]; operations?: number }>;
  /** Groups whose approver is configured `unattended` (6.5); default: none. */
  unattended?: Partial<Record<Group, boolean>>;
  /** Hand-written-tool servers: no `<prefix>_<group>` tools, only extraTools. */
  groupTools?: boolean;
}

export function buildManifest(input: ManifestInput): GuardManifest {
  const tools: ManifestTool[] = [];
  const meta = (g: Group) => groupMeta(g, { unattended: input.unattended?.[g] }) ?? null;
  for (const t of input.extraTools ?? []) {
    tools.push({
      name: t.name,
      group: t.group,
      tiers: t.tiers ?? [...new Set(input.operations.filter((o) => TIER_GROUP[o.tier] === t.group).map((o) => o.tier))],
      operations: t.operations ?? 0,
      annotations: { ...GROUP_ANNOTATIONS[t.group] },
      _meta: meta(t.group),
    });
  }
  if (input.groupTools !== false) {
    for (const g of GROUPS) {
      const ops = input.operations.filter((o) => TIER_GROUP[o.tier] === g);
      if (!ops.length) continue;
      tools.push({
        name: groupToolName(input.prefix, g),
        group: g,
        tiers: [...new Set(ops.map((o) => o.tier))].sort(),
        operations: ops.length,
        annotations: { ...GROUP_ANNOTATIONS[g] },
        _meta: meta(g),
      });
    }
  }
  const operations = input.operations
    .map((o) => {
      const group = TIER_GROUP[o.tier];
      return {
        operation: o.operationId,
        tier: o.tier,
        group,
        tool: group && input.groupTools !== false ? groupToolName(input.prefix, group) : null,
        ...(o.flags && Object.keys(o.flags).length ? { flags: { ...o.flags } } : {}),
      };
    })
    .sort((a, b) => a.operation.localeCompare(b.operation));
  return {
    manifest_version: MANIFEST_VERSION,
    server: input.server,
    version: input.version,
    guard_version: GUARD_VERSION,
    prefix: input.prefix,
    tools,
    operations,
  };
}
