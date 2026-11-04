// mcp-guard status: what the guard would enable per mode, and that it never writes.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { cli, openPolicy, sandbox, test } from "./cli-helpers.mjs";

const groups = (eff) => Object.fromEntries(Object.entries(eff.groups).map(([g, s]) => [g, s.enabled ? "on" : s.reason_code]));

test("status without a policy file shows the read-only default", async (t) => {
  const sb = sandbox(t);
  const r = await cli(["status", "column", "--json"], { env: sb.env });
  assert.equal(r.code, 0);
  assert.equal(r.json.policy.source, "default");
  assert.equal(r.json.policy.path, sb.policyFile("column"));
  assert.deepEqual(groups(r.json.effective.none), { read: "on", change: "group_off", critical: "group_off", spend: "group_off" });
  assert.equal(r.json.protection.protected, false, "an NST_MCP_POLICY_DIR override never counts as protected");

  const text = await cli(["status", "column"], { env: sb.env });
  assert.equal(text.code, 0);
  assert.match(text.text, /no policy file: the read-only default applies/);
  assert.match(text.text, /NST_MCP_POLICY_DIR override: tests only/);
  assert.match(text.text, /protection: NOT protected/);
});

test("unprotected: critical and spend run only in sandbox mode", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  const r = await cli(["status", "column", "--json"], { env: sb.env });
  assert.equal(r.code, 0);
  assert.equal(r.json.policy.source, "file");
  assert.match(r.json.policy.hash, /^[0-9a-f]{64}$|^sha256:/);
  assert.deepEqual(groups(r.json.effective.sandbox), { read: "on", change: "on", critical: "on", spend: "on" });
  assert.deepEqual(groups(r.json.effective.none), { read: "on", change: "on", critical: "policy_unprotected", spend: "policy_unprotected" });
  assert.deepEqual(groups(r.json.effective.live), { read: "on", change: "on", critical: "policy_unprotected", spend: "policy_unprotected" });
  assert.ok(r.json.effective.none.groups.critical.how_to_enable, "every off group says how to enable it");

  const text = await cli(["status", "column"], { env: sb.env });
  assert.match(text.text, /group\s+mode live\s+mode sandbox\s+mode none/);
  assert.match(text.text, /critical\s+off \[1\]\s+on\s+off \[1\]/);
  assert.match(text.text, /\[1\] policy_unprotected: /);
  assert.match(text.text, /to enable: Protect the policy/);
});

test("protected and allow_live: every group on in every mode", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  const r = await cli(["status", "column", "--json"], { env: sb.env, protect: true });
  for (const mode of ["live", "sandbox", "none"]) {
    assert.deepEqual(groups(r.json.effective[mode]), { read: "on", change: "on", critical: "on", spend: "on" }, mode);
  }
});

test("without allow_live, a live key runs reads only", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", { version: 1, server: "column", groups: { change: true } });
  const r = await cli(["status", "column", "--json"], { env: sb.env, protect: true });
  assert.deepEqual(groups(r.json.effective.live), { read: "on", change: "live_not_allowed", critical: "group_off", spend: "group_off" });
  assert.deepEqual(groups(r.json.effective.none), { read: "on", change: "on", critical: "group_off", spend: "group_off" });
  assert.equal(r.json.policy.allow_live, false);
});

test("--mode limits the view to one mode", async (t) => {
  const sb = sandbox(t);
  const r = await cli(["status", "column", "--mode", "sandbox", "--json"], { env: sb.env });
  assert.deepEqual(Object.keys(r.json.effective), ["sandbox"]);
  const bad = await cli(["status", "column", "--mode", "prod"], { env: sb.env });
  assert.equal(bad.code, 2);
  assert.match(bad.errText, /--mode is live, sandbox or none/);
});

test("keys the base schema does not know are listed and warned about", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", { version: 1, server: "column", column_accounts: { allowed: ["acct_1"] } });
  const r = await cli(["status", "column", "--json"], { env: sb.env });
  assert.equal(r.json.policy.source, "file");
  assert.equal(r.json.policy.error, undefined);
  assert.deepEqual(r.json.policy.server_specific_keys, ["column_accounts"]);
  assert.ok(r.json.warnings.some((w) => w.includes("column_accounts") && w.includes("typo")));
});

test("a server's keys inside base sections (Column's environment.verified_key_sha256) load and are listed by path", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", {
    ...openPolicy("column"),
    surfaces: { ach: true },
    client: "ops",
    environment: { allow_live: true, verified_key_sha256: "ab".repeat(32) },
    approval: { spend: { approver: "external", tiers: [{ over_cents: 100, approver: "external", note: "x" }] } },
    allowlists: { counterparty: ["cp_1"] },
  });
  const r = await cli(["status", "column", "--json"], { env: sb.env, protect: true });
  assert.equal(r.json.policy.error, undefined);
  assert.deepEqual(r.json.policy.server_specific_keys, ["approval.spend.tiers[0].note", "client", "environment.verified_key_sha256", "surfaces"]);
  assert.equal(groups(r.json.effective.live).change, "on", "the base fields still decide: allow_live came through");
  const typo = sb.policy("column", { ...openPolicy("column"), environment: { allow_live: "yes" } });
  assert.match((await cli(["status", "column", "--json"], { env: sb.env })).json.policy.error, /environment\.allow_live/, `${typo}: a wrong type in a base field is still an error`);
});

test("a rejected policy shows the error and leaves only reads", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", { version: 1, server: "column", groups: { change: "yes" } });
  const r = await cli(["status", "column", "--json"], { env: sb.env, protect: true });
  assert.equal(r.code, 0, "status reports a bad policy; it does not fail");
  assert.ok(r.json.policy.error);
  assert.deepEqual(groups(r.json.effective.none), { read: "on", change: "policy_invalid", critical: "policy_invalid", spend: "policy_invalid" });
  const text = await cli(["status", "column"], { env: sb.env });
  assert.match(text.text, /REJECTED, so the server runs read-only/);

  sb.policy("column", "{ not json");
  const broken = await cli(["status", "column", "--json"], { env: sb.env });
  assert.ok(broken.json.policy.error);
  assert.equal(groups(broken.json.effective.none).change, "policy_invalid");
});

test("a policy for another server is rejected", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", { version: 1, server: "stripe", groups: { change: true } });
  const r = await cli(["status", "column", "--json"], { env: sb.env });
  assert.ok(r.json.policy.error, "server mismatch must not load");
  assert.equal(groups(r.json.effective.none).change, "policy_invalid");
});

test("status never writes: no state folder, no policy folder", async (t) => {
  const sb = sandbox(t);
  await cli(["status", "column"], { env: sb.env });
  await cli(["status", "column", "--json"], { env: sb.env });
  await cli(["status"], { env: sb.env });
  assert.equal(existsSync(sb.stateDir), false, "status must not create the state root");
  assert.equal(existsSync(sb.policyDir), false, "status must not create the policy root");

  sb.policy("column", openPolicy("column"));
  const before = readdirSync(join(sb.policyDir, "column")).sort();
  await cli(["status", "column"], { env: sb.env });
  assert.deepEqual(readdirSync(join(sb.policyDir, "column")).sort(), before);
  assert.equal(existsSync(sb.serverState("column")), false);
});

test("status with no server lists servers from both roots", async (t) => {
  const sb = sandbox(t);
  sb.policy("alpha", openPolicy("alpha"));
  mkdirSync(sb.serverState("beta"), { recursive: true });
  mkdirSync(join(sb.stateDir, "_watch"), { recursive: true }); // not a server name
  mkdirSync(join(sb.stateDir, "Not-A-Server"), { recursive: true });
  writeFileSync(join(sb.policyDir, "alpha", "KILL"), "stop\n");
  const r = await cli(["status", "--json"], { env: sb.env });
  assert.equal(r.code, 0);
  assert.deepEqual(
    r.json.servers.map((s) => [s.server, s.policy_file, s.state, s.killed]),
    [
      ["alpha", true, false, true],
      ["beta", false, true, false],
    ]
  );
  assert.equal(r.json.kill_all, false);

  writeFileSync(join(sb.policyDir, "KILL"), "all stop\n");
  const text = await cli(["status"], { env: sb.env });
  assert.match(text.text, /kill switch for every server SET/);
  assert.match(text.text, /alpha\s+file\s+-\s+SET/);
});

test("status lists an empty install plainly", async (t) => {
  const sb = sandbox(t);
  const r = await cli(["status"], { env: sb.env });
  assert.equal(r.code, 0);
  assert.match(r.text, /no servers found/);
});

test("--file reads another policy and warns it is not the server's own", async (t) => {
  const sb = sandbox(t);
  const draft = join(sb.base, "draft.json");
  writeFileSync(draft, JSON.stringify(openPolicy("column")));
  const r = await cli(["status", "column", "--file", "draft.json", "--json"], { env: sb.env, cwd: sb.base });
  assert.equal(r.json.policy.path, draft);
  assert.equal(r.json.policy.standard_path, sb.policyFile("column"));
  assert.equal(r.json.effective.none.groups.change.enabled, true);
  assert.ok(r.json.warnings.some((w) => w.startsWith("--file:")));

  const missing = await cli(["status", "column", "--file", "nope.json"], { env: sb.env, cwd: sb.base });
  assert.equal(missing.code, 1);
  assert.match(missing.errText, /No such file/);

  const noServer = await cli(["status", "--file", "draft.json"], { env: sb.env, cwd: sb.base });
  assert.equal(noServer.code, 2);
});

test("status shows kill markers, trips and audit totals", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  writeFileSync(join(sb.policyDir, "column", "KILL"), "maintenance window\n");
  const soft = await cli(["kill", "column", "--soft", "--note", "pause"], { env: sb.env });
  assert.equal(soft.code, 0);
  const r = await cli(["status", "column", "--json"], { env: sb.env });
  assert.equal(r.json.kill.manual.server, true);
  assert.equal(r.json.kill.manual.note, "maintenance window");
  assert.equal(r.json.kill.trips.length, 1);
  assert.equal(r.json.kill.trips[0].reason, "mcp-guard kill --soft: pause");
  assert.deepEqual(r.json.audit.map((a) => [a.ok, a.lines]), [[true, 1]]);

  const text = await cli(["status", "column"], { env: sb.env });
  assert.match(text.text, /kill switch: set \(.*KILL\); note: maintenance window/);
  assert.match(text.text, /automatic trip \(all\) at 2026-11-04T12:00:00.000Z: mcp-guard kill --soft: pause/);
  assert.match(text.text, /audit: 1 file, 1 line, chain intact/);
});

test("invalid server names are usage errors", async (t) => {
  const sb = sandbox(t);
  for (const name of ["Column", "../etc", "-x", "a".repeat(65), "co lumn"]) {
    const r = await cli(["status", name], { env: sb.env });
    assert.equal(r.code, 2, name);
  }
});
