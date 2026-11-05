// computeEffective: every rule, in order (sections 5, 6.1).
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { describe, test } from "node:test";
import { computeEffective, loadPolicy, parseFlag, readNarrowing, staticProtection } from "../dist/guard/index.js";
import { ALL_ON, sandbox } from "./guard-helpers.mjs";

function eff(t, { policy = ALL_ON, env = {}, mode = "sandbox", protectedPolicy = true, raw, ...rest } = {}) {
  const sb = sandbox(t);
  if (raw !== undefined) writeFileSync(sb.policyPath, raw);
  else if (policy !== null) sb.writePolicy(policy);
  const fullEnv = { ...sb.env, ...env };
  const loaded = loadPolicy({ server: "toy", env: fullEnv });
  return computeEffective({ loaded, protection: staticProtection(protectedPolicy, sb.policyPath), mode, narrowing: readNarrowing(fullEnv, "TOY"), ...rest });
}
const on = (e) => Object.entries(e.groups).filter(([, s]) => s.enabled).map(([g]) => g);
const codes = (e) => Object.fromEntries(Object.entries(e.groups).map(([g, s]) => [g, s.enabled ? "on" : s.reason_code]));

describe("readNarrowing", () => {
  test("switches and legacy flags", () => {
    assert.deepEqual(readNarrowing({}, "toy"), { readonly: false, legacy: {}, envPrefix: "TOY" });
    assert.deepEqual(readNarrowing({ NST_MCP_READONLY: "yes" }, "toy"), { readonly: true, readonlySource: "NST_MCP_READONLY", legacy: {}, envPrefix: "TOY" });
    assert.equal(readNarrowing({ TOY_PROFILE: "reader" }, "toy").readonlySource, "TOY_PROFILE=reader");
    assert.equal(readNarrowing({ TOY_PROFILE: "operator" }, "toy").readonly, false);
    assert.equal(readNarrowing({ NST_MCP_READONLY: "0" }, "toy").readonly, false);
    assert.deepEqual(readNarrowing({ TOY_ALLOW_WRITES: "true", TOY_ALLOW_SPEND: "maybe", TOY_ALLOW_DESTRUCTIVE: "" }, "toy").legacy, { writes: true, spend: false });
  });

  test("parseFlag is the guard's own flag reader, exported for servers", () => {
    for (const v of ["1", "true", "YES", "on"]) assert.equal(parseFlag(v), true, v);
    for (const v of ["0", "False", "no", "OFF", "maybe", " true"]) assert.equal(parseFlag(v), false, v);
    assert.equal(parseFlag(undefined), undefined);
    assert.equal(parseFlag(""), undefined);
  });
});

describe("computeEffective", () => {
  test("all groups on with a protected policy", (t) => {
    const e = eff(t);
    assert.deepEqual(on(e), ["read", "change", "critical", "spend"]);
    assert.deepEqual(e.groups.change.tiers, ["reducing", "write", "sandbox"]);
    assert.deepEqual(e.approvers, { read: "none", change: "none", critical: "none", spend: "none" });
  });

  test("no policy file: read only; ALLOW_WRITES=true raises change with a warning", (t) => {
    assert.deepEqual(codes(eff(t, { policy: null })), { read: "on", change: "group_off", critical: "group_off", spend: "group_off" });
    const legacy = eff(t, { policy: null, env: { TOY_ALLOW_WRITES: "1" } });
    assert.deepEqual(on(legacy), ["read", "change"]);
    assert.ok(legacy.warnings.some((w) => /^Deprecated: TOY_ALLOW_WRITES=true/.test(w)), "the warning names the variable");
  });

  test("ALLOW_WRITES=true never raises over a policy file", (t) => {
    assert.equal(codes(eff(t, { policy: { groups: { read: true } }, env: { TOY_ALLOW_WRITES: "true" } })).change, "group_off");
  });

  test("an invalid policy is read-only", (t) => {
    for (const raw of ["{not json", JSON.stringify({ version: 1, server: "toy", groups: { spend: "yes" } }), JSON.stringify({ version: 1, server: "other", groups: { change: true } })]) {
      const e = eff(t, { raw, env: { TOY_ALLOW_WRITES: "true" } });
      assert.deepEqual(codes(e), { read: "on", change: "policy_invalid", critical: "policy_invalid", spend: "policy_invalid" }, raw);
      assert.ok(e.warnings.some((w) => /Policy rejected/.test(w)));
    }
  });

  test("read-only switches beat everything but the policy", (t) => {
    assert.deepEqual(on(eff(t, { env: { NST_MCP_READONLY: "1" } })), ["read"]);
    const reader = eff(t, { env: { TOY_PROFILE: "reader" } });
    assert.equal(reader.groups.spend.reason_code, "readonly_profile");
    assert.match(reader.groups.spend.reason, /TOY_PROFILE=reader/);
    assert.equal(eff(t, { env: { NST_MCP_READONLY: "1" }, protectedPolicy: false, mode: "live" }).groups.spend.reason_code, "readonly_profile");
  });

  test("legacy false flags lower groups; unknown values lower too", (t) => {
    // ALLOW_WRITES=false meant read-only in 0.1: it lowers every non-read group, so an
    // upgrade that keeps it next to a policy with critical on does not leave critical on.
    const writesOff = eff(t, { env: { TOY_ALLOW_WRITES: "false" } });
    assert.deepEqual(codes(writesOff), { read: "on", change: "legacy_flag_off", critical: "legacy_flag_off", spend: "legacy_flag_off" });
    for (const g of ["change", "critical", "spend"]) {
      assert.match(writesOff.groups[g].reason, /^TOY_ALLOW_WRITES is set to a false or unrecognized value/, g);
      assert.match(writesOff.groups[g].how_to_enable, /Remove TOY_ALLOW_WRITES/, g);
    }
    assert.deepEqual(codes(eff(t, { env: { TOY_ALLOW_WRITES: "garbage" } })), { read: "on", change: "legacy_flag_off", critical: "legacy_flag_off", spend: "legacy_flag_off" });
    assert.deepEqual(codes(eff(t, { env: { TOY_ALLOW_SPEND: "no" } })), { read: "on", change: "on", critical: "on", spend: "legacy_flag_off" });
    assert.deepEqual(codes(eff(t, { env: { TOY_ALLOW_DESTRUCTIVE: "off" } })), { read: "on", change: "on", critical: "legacy_flag_off", spend: "on" });
    assert.match(eff(t, { env: { TOY_ALLOW_SPEND: "sure" } }).groups.spend.reason, /^TOY_ALLOW_SPEND /);
    assert.match(eff(t, { env: { TOY_ALLOW_DESTRUCTIVE: "0" } }).groups.critical.reason, /^TOY_ALLOW_DESTRUCTIVE /);
    // A narrowing built by hand without a prefix still reads sensibly.
    const sb = sandbox(t);
    sb.writePolicy(ALL_ON);
    const loaded = loadPolicy({ server: "toy", env: sb.env });
    const bare = computeEffective({ loaded, protection: staticProtection(true, sb.policyPath), mode: "sandbox", narrowing: { readonly: false, legacy: { writes: false } } });
    assert.match(bare.groups.critical.reason, /^ALLOW_WRITES is set/);
  });

  test("an unprotected policy keeps critical and spend off outside sandbox", (t) => {
    for (const mode of ["live", "none"]) {
      assert.deepEqual(codes(eff(t, { protectedPolicy: false, mode })), { read: "on", change: "on", critical: "policy_unprotected", spend: "policy_unprotected" }, mode);
    }
    assert.deepEqual(on(eff(t, { protectedPolicy: false, mode: "sandbox" })), ["read", "change", "critical", "spend"]);
  });

  test("a live key, and one the server cannot tell, needs allow_live; a sandbox key does not", (t) => {
    const closed = { ...ALL_ON, environment: { allow_live: false } };
    for (const mode of ["live", "none"]) {
      assert.deepEqual(codes(eff(t, { policy: closed, mode })), { read: "on", change: "live_not_allowed", critical: "live_not_allowed", spend: "live_not_allowed" }, mode);
      assert.deepEqual(on(eff(t, { mode })), ["read", "change", "critical", "spend"], mode);
    }
    assert.match(eff(t, { policy: closed, mode: "live" }).groups.change.reason, /^This is a live key/);
    assert.match(eff(t, { policy: closed, mode: "none" }).groups.change.reason, /^The server cannot tell whether this key is live/);
    assert.deepEqual(on(eff(t, { policy: closed, mode: "sandbox" })), ["read", "change", "critical", "spend"]);
  });

  test("approvers this version cannot run fail closed; deny keeps the group visible", (t) => {
    const ext = { ...ALL_ON, approval: { ...ALL_ON.approval, spend: "external", critical: "deny" } };
    const e = eff(t, { policy: ext, availableApprovers: ["none", "deny"] });
    assert.equal(e.groups.spend.reason_code, "approver_unavailable");
    assert.equal(e.groups.critical.enabled, true);
    assert.equal(e.approvers.critical, "deny");
    assert.equal(eff(t, { policy: { ...ALL_ON, approval: { ...ALL_ON.approval, change: "duo" } } }).groups.change.reason_code, "approver_unavailable");
  });

  test("G4 approval features fail closed", (t) => {
    assert.equal(eff(t, { policy: { ...ALL_ON, approval: { ...ALL_ON.approval, spend: { approver: "none", quorum: 2 } } } }).groups.spend.reason_code, "approval_feature_unavailable");
    const delayed = eff(t, { policy: { ...ALL_ON, approval: { ...ALL_ON.approval, delay_new_target: "24h" } } });
    assert.deepEqual(codes(delayed), { read: "on", change: "on", critical: "approval_feature_unavailable", spend: "approval_feature_unavailable" });
    const tired = eff(t, { policy: { ...ALL_ON, approval: { ...ALL_ON.approval, spend: "external", fatigue: { pending_per_server: 1 } } } });
    assert.deepEqual(codes(tired), { read: "on", change: "on", critical: "on", spend: "approval_feature_unavailable" }, "only a group whose approver asks a person");
    assert.match(tired.groups.spend.reason, /^approval\.fatigue \(pending_per_server\) arrives with G4a; the spend group's approver "external" asks a person/);
    assert.equal(eff(t, { policy: { ...ALL_ON, approval: { ...ALL_ON.approval, spend: "external", fatigue: {} } } }).groups.spend.enabled, true, "an empty fatigue block sets no limit");
  });

  test("a remote kill flag fails closed until G5", (t) => {
    const remote = eff(t, { policy: { ...ALL_ON, kill_switch: { remote_flag: "https://example.test/flag" } } });
    assert.deepEqual(codes(remote), { read: "on", change: "remote_kill_flag_unavailable", critical: "remote_kill_flag_unavailable", spend: "remote_kill_flag_unavailable" });
    assert.match(remote.groups.change.reason, /^kill_switch\.remote_flag arrives with G5/);
    assert.equal(eff(t, { policy: { ...ALL_ON, kill_switch: { remote_flag: "none" } } }).groups.change.enabled, true);
  });

  test("tiers_off and sandbox-only tiers", (t) => {
    const e = eff(t, { policy: { ...ALL_ON, tiers_off: ["reducing", "write"] }, mode: "none" });
    assert.equal(e.groups.change.reason_code, "tiers_off");
    assert.deepEqual(eff(t, { policy: { ...ALL_ON, tiers_off: ["reducing", "write"] } }).groups.change.tiers, ["sandbox"]);
    assert.deepEqual(eff(t, { mode: "live" }).groups.change.tiers, ["reducing", "write"]);
    assert.deepEqual(eff(t, { policy: { ...ALL_ON, tiers_off: ["destructive"] } }).groups.critical.tiers, ["sensitive"]);
  });

  test("the server check runs last", (t) => {
    const seen = [];
    const e = eff(t, {
      serverCheck: (g) => (seen.push(g), g === "spend" ? { reason_code: "server_says_no", reason: "no vendor list" } : null),
    });
    assert.equal(e.groups.spend.reason_code, "server_says_no");
    assert.deepEqual(seen, ["read", "change", "critical", "spend"]);
    const ro = [];
    eff(t, { env: { NST_MCP_READONLY: "1" }, serverCheck: (g) => (ro.push(g), null) });
    assert.deepEqual(ro, ["read"], "groups already off skip the server check");
  });
});
