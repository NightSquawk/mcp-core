/**
 * The effective groups: what the policy enables, after everything that can only
 * narrow it (sections 5.1, 5.3, 6 step 3). Computed once at startup; a group that
 * is off here is not registered, so the model never sees its tool.
 */
import type { Mode } from "./approvers.js";
import { approverFor, fatigueLimits, HUMAN_APPROVERS, IMPLEMENTED_APPROVERS, type BasePolicy, type LoadedPolicy } from "./policy.js";
import type { ProtectionReport } from "./protection.js";
import { DEFAULT_GROUPS, GROUPS, GROUP_TIERS, HIGH_RISK_GROUPS, type Group, type Tier } from "./tiers.js";

export interface Narrowing {
  /** `<PREFIX>_PROFILE=reader` or `NST_MCP_READONLY=1`: read-only whatever the policy says. */
  readonly: boolean;
  readonlySource?: string;
  /**
   * Legacy flags (migration only): `false` lowers; only `writes=true` can raise, and only
   * without a policy file. `writes=false` lowers every non-read group: in 0.1 servers it
   * meant read-only, deletes and stops included.
   */
  legacy: { writes?: boolean; spend?: boolean; destructive?: boolean };
  /** The env prefix the flags were read with (`PROXMOX`), so refusals can name the variable. */
  envPrefix?: string;
}

const TRUE = /^(1|true|yes|on)$/i;
const FALSE = /^(0|false|no|off)$/i;

/**
 * An env switch the way the guard reads it: unset or empty is undefined, 1/true/yes/on
 * is true, 0/false/no/off is false, and anything else is false (an unrecognized value
 * lowers, never raises). Servers reading their own flags use this to match.
 */
export function parseFlag(value: string | undefined): boolean | undefined {
  if (value === undefined || value === "") return undefined;
  if (TRUE.test(value)) return true;
  if (FALSE.test(value)) return false;
  return false;
}

/** Read the narrowing switches. `envPrefix` is the server's env prefix, e.g. `COLUMN`. */
export function readNarrowing(env: NodeJS.ProcessEnv, envPrefix: string): Narrowing {
  const P = envPrefix.toUpperCase();
  const profile = env[`${P}_PROFILE`];
  const ro = parseFlag(env.NST_MCP_READONLY) === true;
  const writes = parseFlag(env[`${P}_ALLOW_WRITES`]);
  const spend = parseFlag(env[`${P}_ALLOW_SPEND`]);
  const destructive = parseFlag(env[`${P}_ALLOW_DESTRUCTIVE`]);
  return {
    readonly: ro || profile === "reader",
    ...(ro ? { readonlySource: "NST_MCP_READONLY" } : profile === "reader" ? { readonlySource: `${P}_PROFILE=reader` } : {}),
    legacy: {
      ...(writes !== undefined ? { writes } : {}),
      ...(spend !== undefined ? { spend } : {}),
      ...(destructive !== undefined ? { destructive } : {}),
    },
    envPrefix: P,
  };
}

/** `PROXMOX_ALLOW_WRITES`, or `ALLOW_WRITES` when the prefix is unknown. */
function legacyName(narrowing: Narrowing, which: "WRITES" | "SPEND" | "DESTRUCTIVE"): string {
  return `${narrowing.envPrefix ? `${narrowing.envPrefix}_` : ""}ALLOW_${which}`;
}

export interface GroupState {
  enabled: boolean;
  reason_code?: string;
  reason?: string;
  how_to_enable?: string;
  /** Tiers this group may run (minus tiers_off, minus sandbox outside sandbox mode). */
  tiers: Tier[];
}

export interface Effective {
  groups: Record<Group, GroupState>;
  /** The configured approver per group (object form's `approver`). */
  approvers: Record<Group, string>;
  warnings: string[];
  narrowing: Narrowing;
}

export interface ServerCheckResult {
  reason_code: string;
  reason: string;
  how_to_enable?: string;
}

export interface EffectiveInput<P extends BasePolicy = BasePolicy> {
  loaded: LoadedPolicy<P>;
  protection: ProtectionReport;
  mode: Mode;
  narrowing: Narrowing;
  /** Approver names this process can run (built-ins plus any a server injects). */
  availableApprovers?: readonly string[];
  /** Server-specific narrowing, e.g. Column's verified live key (applied last). */
  serverCheck?: (group: Group, policy: P) => ServerCheckResult | null;
}

const off = (code: string, reason: string, how?: string) => ({ reason_code: code, reason, ...(how ? { how_to_enable: how } : {}) });

export function computeEffective<P extends BasePolicy>(input: EffectiveInput<P>): Effective {
  const { loaded, protection, mode, narrowing } = input;
  const policy = loaded.policy;
  const available = new Set(input.availableApprovers ?? IMPLEMENTED_APPROVERS);
  const warnings: string[] = [];
  const groups = {} as Record<Group, GroupState>;
  const approvers = {} as Record<Group, string>;

  if (loaded.error) warnings.push(`Policy rejected, running read-only: ${loaded.error}`);
  const noFile = loaded.source === "default" && !loaded.error;
  if (noFile && narrowing.legacy.writes === true && !narrowing.readonly) {
    warnings.push(
      `Deprecated: ${legacyName(narrowing, "WRITES")}=true enabled the change group because no policy file exists. ` +
        "This works for one more minor release; write a policy file (mcp-guard init) instead."
    );
  }

  for (const group of GROUPS) {
    const cfg = approverFor(policy, group);
    approvers[group] = cfg.approver;
    const tiers = GROUP_TIERS[group].filter((t) => !policy.tiers_off.includes(t) && (t !== "sandbox" || mode === "sandbox"));
    let state: ServerCheckResult | null = null;

    // 1. The policy value (or the built-in default).
    const configured = policy.groups[group] ?? DEFAULT_GROUPS[group];
    // 2. Legacy ALLOW_WRITES=true raises `change` only when there is no policy file at all.
    const legacyRaise = group === "change" && noFile && narrowing.legacy.writes === true;
    if (!configured && !legacyRaise) {
      state = off(
        loaded.error ? "policy_invalid" : "group_off",
        loaded.error ? `The policy file was rejected, so only reads run: ${loaded.error}` : `The policy does not enable the ${group} group.`,
        `Set groups.${group} to true in ${loaded.path} (admin rights).`
      );
    }
    // 3. An invalid policy is read-only, whatever the legacy flags say.
    else if (loaded.error && group !== "read") {
      state = off("policy_invalid", `The policy file was rejected, so only reads run: ${loaded.error}`, `Fix ${loaded.path}; mcp-guard status shows the error.`);
    }
    // 4. Read-only narrowing.
    else if (narrowing.readonly && group !== "read") {
      state = off("readonly_profile", `${narrowing.readonlySource ?? "Read-only mode"} forces this process read-only.`, "Start the server without the read-only switch.");
    }
    // 5. Legacy flags lower groups. ALLOW_WRITES=false lowers every non-read group: in
    // 0.1 it meant read-only, so an upgrade that keeps it must not leave critical on.
    else if (group !== "read" && narrowing.legacy.writes === false) {
      const name = legacyName(narrowing, "WRITES");
      state = off(
        "legacy_flag_off",
        `${name} is set to a false or unrecognized value, which turns the ${group} group off (in 0.1 servers it meant read-only).`,
        `Remove ${name} from the server's environment; the policy file decides which groups run.`
      );
    } else if (group === "spend" && narrowing.legacy.spend === false) {
      const name = legacyName(narrowing, "SPEND");
      state = off("legacy_flag_off", `${name} is set to a false or unrecognized value, which turns the spend group off.`, `Remove ${name} from the server's environment.`);
    } else if (group === "critical" && narrowing.legacy.destructive === false) {
      const name = legacyName(narrowing, "DESTRUCTIVE");
      state = off("legacy_flag_off", `${name} is set to a false or unrecognized value, which turns the critical group off.`, `Remove ${name} from the server's environment.`);
    }
    // 6. Unprotected policies never enable critical or spend, except in sandbox mode.
    else if (HIGH_RISK_GROUPS.includes(group) && !protection.protected && mode !== "sandbox") {
      state = off(
        "policy_unprotected",
        `The policy at ${protection.policyPath} is not protected (${[...protection.part1.reasons, ...protection.part2.reasons].join("; ") || "override path"}), so ${group} stays off outside sandbox mode.`,
        "Protect the policy (hardening SOP): admin-owned file and folders, and an OS user that cannot become admin on its own."
      );
    }
    // 7. Anything but a sandbox key needs allow_live for anything but reads: a live key, and a key
    // the server cannot tell (mode none), which may be live.
    else if (mode !== "sandbox" && group !== "read" && !policy.environment.allow_live) {
      state = off(
        "live_not_allowed",
        mode === "live"
          ? "This is a live key and the policy does not set environment.allow_live."
          : "The server cannot tell whether this key is live, and the policy does not set environment.allow_live.",
        `Set environment.allow_live in ${loaded.path} (admin rights).`
      );
    }
    // 8. Approvers this version cannot run fail closed. `deny` keeps the group (visible, never runs).
    else if (group !== "read" && !available.has(cfg.approver)) {
      state = off("approver_unavailable", `The ${group} group's approver "${cfg.approver}" is not available in this version.`, "Use none, deny or external until G4 ships that approver.");
    } else if (group !== "read" && ((cfg.quorum ?? 1) > 1 || cfg.independent || cfg.delay)) {
      state = off("approval_feature_unavailable", `quorum, independent and delay (section 6.6) arrive with G4a; the ${group} group stays off rather than run without them.`);
    } else if (HIGH_RISK_GROUPS.includes(group) && policy.approval.delay_new_target) {
      state = off("approval_feature_unavailable", `approval.delay_new_target arrives with G4a; the ${group} group stays off rather than run without it.`);
    } else if (group !== "read" && (policy.kill_switch?.remote_flag ?? "none") !== "none") {
      state = off(
        "remote_kill_flag_unavailable",
        `kill_switch.remote_flag arrives with G5, so this version cannot see a remote stop; the ${group} group stays off rather than run without it.`,
        `Set kill_switch.remote_flag to "none" in ${loaded.path} (admin rights) to run ${group} without a remote flag.`
      );
    } else if (group !== "read" && HUMAN_APPROVERS.includes(cfg.approver) && fatigueLimits(policy).length) {
      state = off(
        "approval_feature_unavailable",
        `approval.fatigue (${fatigueLimits(policy).join(", ")}) arrives with G4a; the ${group} group's approver "${cfg.approver}" asks a person, so the group stays off rather than run without it.`,
        `Remove approval.fatigue from ${loaded.path} (admin rights) to run ${group} without those limits.`
      );
    }
    // 9. Nothing left to run.
    else if (!tiers.length) {
      state = off("tiers_off", `Every tier of the ${group} group is excluded (tiers_off${mode !== "sandbox" ? ", or sandbox-only" : ""}).`);
    }
    // 10. Server-specific checks.
    else if (input.serverCheck) {
      const r = input.serverCheck(group, policy);
      if (r) state = r;
    }

    groups[group] = state ? { enabled: false, ...state, tiers } : { enabled: true, tiers };
  }

  return { groups, approvers, warnings, narrowing };
}
