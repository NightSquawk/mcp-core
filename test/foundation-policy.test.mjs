import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { z } from "zod";
import { dist } from "./foundation-helpers.mjs";

const Pol = await import(dist("guard/policy.js"));

const sha = (s) => createHash("sha256").update(s).digest("hex");
const errno = (code) => Object.assign(new Error(`${code}: test`), { code });
const load = (text, extra = {}) =>
  Pol.loadPolicy({ server: "column", platform: "linux", env: {}, readFile: () => text, stat: () => ({ mtimeMs: 1234 }), ...extra });
const missing = (code, extra = {}) =>
  Pol.loadPolicy({
    server: "column",
    platform: "linux",
    env: {},
    readFile: () => {
      throw errno(code);
    },
    ...extra,
  });

const READ_ONLY = { read: true, change: false, critical: false, spend: false };

test("defaultPolicy: read-only, everything else off, defaults filled", () => {
  assert.deepEqual(Pol.defaultPolicy("column"), {
    version: 1,
    server: "column",
    groups: READ_ONLY,
    tiers_off: [],
    environment: { allow_live: false },
    allowlists: {},
    limits: {},
    approval: {},
    audit: { forward: "none", reads: false },
    taint: { egress_after_untrusted: "approve" },
    canaries: { hashes: [] },
  });
  assert.throws(() => Pol.defaultPolicy("Bad Name"));
});

test("loadPolicy: no file is the read-only default without an error", () => {
  for (const code of ["ENOENT", "ENOTDIR"]) {
    const r = missing(code);
    assert.equal(r.source, "default");
    assert.equal("error" in r, false, code);
    assert.deepEqual(r.policy.groups, READ_ONLY);
    assert.equal(r.path, "/etc/nightsquawk-mcp/column/policy.json");
    assert.equal(r.override, false);
    assert.equal(r.hash, null);
    assert.equal(r.mtimeMs, null);
  }
});

test("loadPolicy: an unreadable file is read-only with an error", () => {
  for (const code of ["EACCES", "EISDIR", "EIO"]) {
    const r = missing(code);
    assert.equal(r.source, "default");
    assert.match(r.error, /^Cannot read \/etc\/nightsquawk-mcp\/column\/policy\.json/, code);
    assert.deepEqual(r.policy.groups, READ_ONLY);
  }
});

test("loadPolicy: invalid JSON is read-only, and the hash still identifies the bytes", () => {
  const text = '{"version": 1, "server": "column",';
  const r = load(text);
  assert.equal(r.source, "default");
  assert.match(r.error, /is not valid JSON/);
  assert.equal(r.hash, sha(text));
  assert.equal(r.mtimeMs, 1234);
  assert.deepEqual(r.policy.groups, READ_ONLY);
});

test("loadPolicy: every schema violation fails closed and names the field", () => {
  const base = { version: 1, server: "column" };
  const cases = [
    [{ ...base, grups: {} }, "(root)"],
    [{ ...base, groups: { spnd: true } }, "groups"],
    [{ ...base, groups: { spend: "yes" } }, "groups.spend"],
    [{ version: 2, server: "column" }, "version"],
    [{ version: 1, server: "Column" }, "server"],
    [{ ...base, tiers_off: ["admin"] }, "tiers_off.0"],
    [{ ...base, environment: { allow_live: "true" } }, "environment.allow_live"],
    [{ ...base, limits: { rate: { spend_per_week: 1 } } }, "limits.rate.spend_per_week"],
    [{ ...base, limits: { rate: { spend_per_day: -1 } } }, "limits.rate.spend_per_day"],
    [{ ...base, limits: { spend: { unit: "cents", currency: "usd" } } }, "limits.spend.currency"],
    [{ ...base, limits: { spend: { unit: "dollars", currency: "USD" } } }, "limits.spend.unit"],
    [{ ...base, limits: { spend: { unit: "cents", currency: "USD", per_call: 12.5 } } }, "limits.spend.per_call"],
    [{ ...base, approval: { spend: "sms" } }, "approval.spend"],
    [{ ...base, approval: { spend: { approver: "external", tiers: [{ over_cents: -1, approver: "duo" }] } } }, "approval.spend.tiers.0.over_cents"],
    [{ ...base, approval: { critical: { approver: "duo", quorum: 0 } } }, "approval.critical.quorum"],
    [{ ...base, approval: { critical: { approver: "duo", sms: true } } }, "approval.critical"],
    [{ ...base, approval: { delay_new_target: "4 h" } }, "approval.delay_new_target"],
    [{ ...base, approval: { fatigue: { pushes_per_hour: 0 } } }, "approval.fatigue.pushes_per_hour"],
    [{ ...base, audit: { forward: "splunk" } }, "audit.forward"],
    [{ ...base, taint: { egress_after_untrusted: "ask" } }, "taint.egress_after_untrusted"],
    [{ ...base, canaries: { hashes: ["sha256:ABC"] } }, "canaries.hashes.0"],
    [{ ...base, canaries: { hashes: [`sha256:${sha("x").toUpperCase()}`] } }, "canaries.hashes.0"],
    [{ ...base, client_scope: { allowed: [] } }, "client_scope.allowed"],
    [{ ...base, allowlists: { did: [""] } }, "allowlists.did.0"],
    [{ ...base, allowlists: { did: [true] } }, "allowlists.did.0"],
    [{ ...base, duo: { api_host: "api-x.duosecurity.com", approvers: [{ id: "primary", duo_username: "u", device: "D", extra: 1 }] } }, "duo.approvers.0"],
    [[], "(root)"],
    [null, "(root)"],
    ["policy", "(root)"],
  ];
  for (const [value, path] of cases) {
    const r = load(JSON.stringify(value));
    const label = JSON.stringify(value);
    assert.equal(r.source, "default", label);
    assert.match(r.error ?? "", /does not match the policy schema/, label);
    assert.ok(r.error.includes(`${path}:`), `${label}: ${r.error}`);
    assert.deepEqual(r.policy.groups, READ_ONLY, label);
  }
});

test("loadPolicy: a policy for another server is rejected", () => {
  const r = load(JSON.stringify({ version: 1, server: "proxmox", groups: { change: true } }));
  assert.equal(r.source, "default");
  assert.match(r.error, /is for server "proxmox", not "column"/);
  assert.equal(r.policy.server, "column");
});

test("loadPolicy: a valid file loads with defaults filled, its hash and mtime", () => {
  const text = JSON.stringify({ version: 1, server: "column", groups: { change: true } });
  const r = load(text);
  assert.equal(r.source, "file");
  assert.equal("error" in r, false);
  assert.deepEqual(r.policy.groups, { change: true }, "unset groups stay unset (computeEffective applies DEFAULT_GROUPS)");
  assert.equal(r.policy.environment.allow_live, false);
  assert.deepEqual(r.policy.audit, { forward: "none", reads: false });
  assert.equal(r.hash, sha(text));
  assert.equal(r.mtimeMs, 1234);
  const noStat = Pol.loadPolicy({
    server: "column",
    platform: "linux",
    env: {},
    readFile: () => text,
    stat: () => {
      throw errno("ENOENT");
    },
  });
  assert.equal(noStat.mtimeMs, null);
  assert.equal(noStat.source, "file");
});

test("loadPolicy: the section 5.2 and 5.4 examples parse", () => {
  const example = {
    version: 1,
    server: "column",
    groups: { read: true, change: true, critical: false, spend: false },
    tiers_off: ["destructive"],
    environment: { allow_live: false },
    allowlists: { counterparty_id: ["cpty_example"], did: [5551234567] },
    limits: {
      spend: { unit: "cents", currency: "USD", per_call: 50000, per_day: 200000 },
      rate: { change_per_minute: 20, critical_per_hour: 5, spend_per_day: 10 },
    },
    approval: {
      critical: { approver: "duo", unattended: true },
      spend: {
        approver: "external",
        tiers: [
          { over_cents: 100000, approver: "duo" },
          { over_cents: 500000, approver: "duo", quorum: 2, independent: true, delay: "4h" },
        ],
      },
      delay_new_target: "24h",
      fatigue: { pending_per_server: 1, pushes_per_hour: 6, denied_cooldown_hours: 24 },
    },
    audit: { forward: "none" },
    duo: {
      api_host: "api-XXXXXXXX.duosecurity.com",
      approvers: [
        { id: "primary", duo_username: "primary-approvals", device: "DPXXXXXXXX" },
        { id: "second", duo_username: "second-approver", device: "DPYYYYYYYY" },
      ],
    },
    operators: { "agent-user": "primary" },
    kill_switch: { remote_flag: "none" },
    taint: { egress_after_untrusted: "approve" },
    canaries: { hashes: [`sha256:${sha("canary")}`] },
    client_scope: { allowed: ["NST-internal"], lock_per_session: true },
  };
  const r = load(JSON.stringify(example));
  assert.equal(r.error, undefined, r.error);
  assert.equal(r.source, "file");
  assert.deepEqual(r.policy.allowlists.did, ["5551234567"], "numbers become strings, so 5551234567 and \"5551234567\" match alike");
  assert.equal(r.policy.approval.spend.tiers.length, 2);
  assert.equal(r.policy.client_scope.lock_per_session, true);
  const minimal52 = { version: 1, server: "column", approval: { critical: "none", spend: "external" }, audit: { forward: "none" } };
  assert.equal(load(JSON.stringify(minimal52)).source, "file");
});

test("loadPolicy: NST_MCP_POLICY_DIR and --file change where it reads", () => {
  const r = missing("ENOENT", { env: { NST_MCP_POLICY_DIR: "/srv/guard-tests" } });
  assert.equal(r.path, "/srv/guard-tests/column/policy.json");
  assert.equal(r.override, true);
  let readPath;
  Pol.loadPolicy({
    server: "column",
    platform: "linux",
    env: {},
    path: "/home/kim/draft-policy.json",
    readFile: (p) => {
      readPath = p;
      throw errno("ENOENT");
    },
  });
  assert.equal(readPath, "/home/kim/draft-policy.json");
});

test("loadPolicy: __proto__ cannot pollute or slip through", () => {
  const root = load('{"version":1,"server":"column","__proto__":{"groups":{"spend":true}}}');
  assert.equal(root.source, "default", "an unknown root key, even __proto__, fails closed");
  const nested = load('{"version":1,"server":"column","allowlists":{"__proto__":["x"],"did":["1"]}}');
  assert.equal(nested.source, "file");
  assert.equal(Object.hasOwn(nested.policy.allowlists, "__proto__"), false);
  assert.deepEqual(Object.keys(nested.policy.allowlists), ["did"]);
  assert.equal({}.did, undefined);
  assert.equal({}.groups, undefined);
});

test("loadPolicy: a UTF-8 byte order mark (Windows PowerShell 5.1 Set-Content -Encoding UTF8) is accepted; the hash still covers the bytes as read", () => {
  const text = String.fromCodePoint(0xfeff) + '{"version":1,"server":"column"}';
  const r = load(text);
  assert.equal(r.source, "file", r.error);
  assert.equal(r.hash, sha(text));
  assert.equal(load(String.fromCodePoint(0xfeff, 0xfeff) + '{"version":1,"server":"column"}').source, "default", "only one mark is stripped");
});

test("basePolicySchema.extend keeps every object strict", () => {
  const extended = Pol.basePolicySchema.extend({ surfaces: z.object({ sms: z.boolean().default(false) }).strict().default({}) });
  const ok = load(JSON.stringify({ version: 1, server: "column", surfaces: { sms: true } }), { schema: extended });
  assert.equal(ok.source, "file", ok.error);
  assert.equal(ok.policy.surfaces.sms, true);
  assert.equal(load(JSON.stringify({ version: 1, server: "column" }), { schema: extended }).policy.surfaces.sms, false, "extension defaults fill");
  assert.equal(load(JSON.stringify({ version: 1, server: "column", surfaces: { fax: true } }), { schema: extended }).source, "default");
  assert.equal(load(JSON.stringify({ version: 1, server: "column", other: 1 }), { schema: extended }).source, "default");
  assert.equal(load(JSON.stringify({ version: 1, server: "column", surfaces: {} })).source, "default", "the base schema does not know surfaces");
});

test("parseDuration and durationSchema agree", () => {
  const good = { "500ms": 500, "10s": 10_000, "30m": 1_800_000, "4h": 14_400_000, "1d": 86_400_000, "0s": 0 };
  for (const [text, ms] of Object.entries(good)) {
    assert.equal(Pol.parseDuration(text), ms, text);
    assert.equal(Pol.durationSchema.safeParse(text).success, true, text);
  }
  for (const text of ["", "1w", "4 h", "-1h", "1.5h", "h", "4H", " 4h", "4h "]) {
    assert.throws(() => Pol.parseDuration(text), /Invalid duration/, JSON.stringify(text));
    assert.equal(Pol.durationSchema.safeParse(text).success, false, JSON.stringify(text));
  }
});

test("approverFor / approverNamesFor normalize the approval config", () => {
  const policy = load(
    JSON.stringify({
      version: 1,
      server: "column",
      approval: { change: "none", critical: "deny", spend: { approver: "external", tiers: [{ over_cents: 100000, approver: "duo" }] } },
    })
  ).policy;
  assert.deepEqual(Pol.approverFor(policy, "read"), { approver: "none" }, "reads never need approval");
  assert.deepEqual(Pol.approverFor(policy, "change"), { approver: "none" });
  assert.deepEqual(Pol.approverFor(policy, "critical"), { approver: "deny" });
  assert.equal(Pol.approverFor(policy, "spend").approver, "external");
  assert.deepEqual(Pol.approverNamesFor(policy, "spend"), ["external", "duo"]);
  assert.deepEqual(Pol.approverFor(Pol.defaultPolicy("column"), "spend"), { approver: "none" }, "unset is none; the group is off by default anyway");
  assert.deepEqual([...Pol.IMPLEMENTED_APPROVERS], ["none", "deny", "external"]);
  assert.ok(Object.isFrozen(Pol.IMPLEMENTED_APPROVERS));
});

test("RATE_KEY: <group>_per_<minute|hour|day> only", () => {
  for (const k of ["read_per_minute", "change_per_hour", "critical_per_day", "spend_per_day"]) assert.ok(Pol.RATE_KEY.test(k), k);
  for (const k of ["spend_per_week", "admin_per_day", "spend_per_day_x", "xspend_per_day", "spend-per-day", ""]) assert.ok(!Pol.RATE_KEY.test(k), k);
});
