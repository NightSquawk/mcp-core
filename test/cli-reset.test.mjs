// mcp-guard reset: clears automatic trips and moves unreadable state aside, after confirmation.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { cli, dist, manualClock, sandbox, test } from "./cli-helpers.mjs";

const { AuditLog } = await import(dist("guard/audit.js"));
const { KillSwitch } = await import(dist("guard/kill-switch.js"));

const STAMP = "2026-11-04T12-00-00-000Z";

function trip(sb, server, reason = "audit chain broken") {
  const dir = sb.serverState(server);
  mkdirSync(dir, { recursive: true });
  new KillSwitch({ markers: { server: join(sb.policyDir, server, "KILL"), all: join(sb.policyDir, "KILL") }, stateDir: dir, clock: manualClock() }).trip("all", reason);
}

function auditLines(sb, server) {
  return new AuditLog(sb.serverState(server), server).read();
}

test("reset with nothing to do says so and asks nothing", async (t) => {
  const sb = sandbox(t);
  const r = await cli(["reset", "column", "--json"], { env: sb.env, interactive: true });
  assert.equal(r.code, 0);
  assert.equal(r.json.cleared, 0);
  assert.equal(r.asked.length, 0);
  assert.equal(existsSync(sb.stateDir), false, "nothing to reset writes nothing");
});

test("reset needs a person at a terminal", async (t) => {
  const sb = sandbox(t);
  trip(sb, "column");
  const r = await cli(["reset", "column"], { env: sb.env, interactive: false });
  assert.equal(r.code, 1);
  assert.match(r.errText, /mcp-guard reset column will:/);
  assert.match(r.errText, /clear the automatic trip \(all\) from 2026-11-04T12:00:00.000Z: audit chain broken/);
  const state = JSON.parse(readFileSync(join(sb.serverState("column"), "kill.json"), "utf8"));
  assert.equal(state.trips.length, 1, "refused reset changes nothing");

  const wrong = await cli(["reset", "column"], { env: sb.env, interactive: true, answers: ["yes"] });
  assert.equal(wrong.code, 1);
  assert.equal(JSON.parse(readFileSync(join(sb.serverState("column"), "kill.json"), "utf8")).trips.length, 1);
});

test("reset clears trips and leaves an audit alert", async (t) => {
  const sb = sandbox(t);
  trip(sb, "column", "first");
  trip(sb, "column", "second");
  const r = await cli(["reset", "column", "--json"], { env: sb.env, interactive: true, answers: ["column"] });
  assert.equal(r.code, 0);
  assert.equal(r.json.cleared, 2);
  assert.deepEqual(JSON.parse(readFileSync(join(sb.serverState("column"), "kill.json"), "utf8")), { trips: [] });
  const lines = auditLines(sb, "column");
  assert.equal(lines.length, 1);
  assert.equal(lines[0].alert, "cli_reset");
  assert.equal(lines[0].note, "cleared 2 trip(s)");
  assert.ok(new AuditLog(sb.serverState("column"), "column").verifyAll().every((c) => c.ok));
});

test("reset keeps a copy of an unreadable kill.json and replaces it", async (t) => {
  const sb = sandbox(t);
  const dir = sb.serverState("column");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "kill.json"), "{ half a file");
  const r = await cli(["reset", "column", "--json"], { env: sb.env, interactive: true, answers: ["column"] });
  assert.equal(r.code, 0);
  assert.equal(r.json.kill_file_replaced, true);
  assert.equal(readFileSync(join(dir, `kill.json.corrupt-${STAMP}`), "utf8"), "{ half a file");
  assert.deepEqual(JSON.parse(readFileSync(join(dir, "kill.json"), "utf8")), { trips: [] });
  assert.match(r.asked[0], /replace the unreadable .*kill\.json \(a copy is kept as .*kill\.json\.corrupt-/);
});

test("reset moves an unreadable idempotency store aside, with a warning to check the provider", async (t) => {
  const sb = sandbox(t);
  const dir = sb.serverState("column");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "idempotency.json"), "not json");
  const r = await cli(["reset", "column", "--json"], { env: sb.env, interactive: true, answers: ["column"] });
  assert.equal(r.code, 0);
  assert.equal(r.json.idempotency_moved_to, join(dir, `idempotency.json.corrupt-${STAMP}`));
  assert.equal(existsSync(join(dir, "idempotency.json")), false);
  assert.equal(readFileSync(join(dir, `idempotency.json.corrupt-${STAMP}`), "utf8"), "not json");
  assert.match(r.asked[0], /check the provider for each before retrying anything/);
  const s = await cli(["status", "column", "--json"], { env: sb.env });
  assert.equal(s.json.idempotency.ok, true);
});

test("reset explains a broken audit chain instead of touching it", async (t) => {
  const sb = sandbox(t);
  const dir = sb.serverState("column");
  const log = new AuditLog(dir, "column", { clock: manualClock() });
  const entry = { server: "column", version: "1", guard: "t", session: "s", tool: "x", operation: "op", tier: "read", group: "read", mode: "none", decision: "read", dry_run: false };
  log.append(entry);
  log.append(entry);
  const file = log.files()[0];
  const text = readFileSync(file, "utf8").replace('"operation":"op"', '"operation":"edited"');
  writeFileSync(file, text);

  const r = await cli(["reset", "column", "--json"], { env: sb.env, interactive: true });
  assert.equal(r.code, 0);
  assert.deepEqual(r.json.broken_audit, [file]);
  assert.equal(r.asked.length, 0);
  const human = await cli(["reset", "column"], { env: sb.env });
  assert.match(human.text, /audit chain in .* is broken at line 1/);
  assert.ok(human.out.some((l) => l === `  After you have inspected it: mv -- '${file}' '${file}.broken-${STAMP}'`));
  assert.equal(readFileSync(file, "utf8"), text, "reset never edits or moves the audit log");
});

test("reset says the manual marker is separate", async (t) => {
  const sb = sandbox(t);
  trip(sb, "column");
  mkdirSync(join(sb.policyDir, "column"), { recursive: true });
  writeFileSync(join(sb.policyDir, "column", "KILL"), "admin stop\n");
  const r = await cli(["reset", "column"], { env: sb.env, interactive: true, answers: ["column"] });
  assert.equal(r.code, 0);
  assert.match(r.text, /manual kill switch is set too .* reset does not clear it \(mcp-guard unkill\)/);
  assert.ok(existsSync(join(sb.policyDir, "column", "KILL")));
});
