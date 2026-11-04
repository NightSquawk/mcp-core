// mcp-guard kill / unkill: the manual marker, the soft (user-state) kill, and confirmations.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { cli, dist, openPolicy, sandbox, test } from "./cli-helpers.mjs";

const { AuditLog } = await import(dist("guard/audit.js"));

const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
const posixHost = process.platform !== "win32";

test("kill writes the server marker with the note and time; status and the guard see it", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  const r = await cli(["kill", "column", "--note", "maintenance", "--json"], { env: sb.env });
  assert.equal(r.code, 0);
  const marker = join(sb.policyDir, "column", "KILL");
  assert.equal(r.json.marker, marker);
  assert.equal(r.json.written, true);
  assert.equal(readFileSync(marker, "utf8"), "maintenance (2026-11-04T12:00:00.000Z)\n");
  const s = await cli(["status", "column", "--json"], { env: sb.env });
  assert.equal(s.json.kill.manual.server, true);
  assert.equal(s.json.kill.manual.note, "maintenance (2026-11-04T12:00:00.000Z)");
});

test("kill --all writes the marker at the policy root, even before any server exists", async (t) => {
  const sb = sandbox(t);
  const r = await cli(["kill", "--all"], { env: sb.env });
  assert.equal(r.code, 0);
  assert.equal(readFileSync(join(sb.policyDir, "KILL"), "utf8"), "Stopped with mcp-guard kill. (2026-11-04T12:00:00.000Z)\n");
  assert.match(r.text, /Kill switch set for every server/);
});

test("kill argument errors are usage errors", async (t) => {
  const sb = sandbox(t);
  assert.equal((await cli(["kill"], { env: sb.env })).code, 2);
  assert.equal((await cli(["kill", "column", "--all"], { env: sb.env })).code, 2);
  assert.equal((await cli(["kill", "column", "--note", "two\nlines"], { env: sb.env })).code, 2);
  assert.equal((await cli(["kill", "column", "--note", "bell\u0007"], { env: sb.env })).code, 2);
  assert.equal((await cli(["kill", "column", "--note", "x".repeat(301)], { env: sb.env })).code, 2);
  assert.equal((await cli(["kill", "column", "--note", "x".repeat(300)], { env: sb.env })).code, 0);
  assert.equal((await cli(["kill", "column", "--note"], { env: sb.env })).code, 2, "--note without a value");
});

test("kill without rights prints marker commands (exit 3) and offers --soft", async (t) => {
  if (isRoot) return t.skip("root can write anywhere");
  const server = "cli-test-kill-zz";
  if (existsSync(`/etc/nightsquawk-mcp/${server}`)) return t.skip("a real policy folder exists");
  const r = await cli(["kill", server, "--json"], { env: {}, platform: "linux" });
  assert.equal(r.code, 3);
  assert.equal(r.json.written, false);
  const marker = `/etc/nightsquawk-mcp/${server}/KILL`;
  assert.deepEqual(r.json.admin.commands, [
    `sudo install -d -m 0755 -o 0 -g 0 '/etc/nightsquawk-mcp/${server}'`,
    `printf '%s\\n' 'Stopped with mcp-guard kill. (2026-11-04T12:00:00.000Z)' | sudo tee '${marker}' > /dev/null`,
    `sudo chmod 0644 '${marker}'`,
  ]);
  const text = await cli(["kill", server], { env: {}, platform: "linux" });
  assert.match(text.text, new RegExp(`mcp-guard kill --soft ${server} stops it from your account`));
  assert.doesNotMatch(text.text, /sudo mcp-guard/);
});

test("kill in a read-only folder prints commands without the install line", async (t) => {
  if (isRoot || !posixHost) return t.skip("needs a non-root POSIX user");
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  const dir = join(sb.policyDir, "column");
  chmodSync(dir, 0o555);
  try {
    const r = await cli(["kill", "column", "--json"], { env: sb.env });
    assert.equal(r.code, 3);
    assert.equal(r.json.admin.commands.length, 2);
    assert.match(r.json.admin.commands[0], /^printf '%s\\n' '.*' \| sudo tee '.*\/column\/KILL' > \/dev\/null$/);
    assert.equal(existsSync(join(dir, "KILL")), false);
  } finally {
    chmodSync(dir, 0o755);
  }
});

test("unkill: not set is a no-op that asks nothing", async (t) => {
  const sb = sandbox(t);
  const r = await cli(["unkill", "column", "--json"], { env: sb.env, interactive: true });
  assert.equal(r.code, 0);
  assert.equal(r.json.was_set, false);
  assert.equal(r.asked.length, 0);
});

test("unkill needs a person at a terminal who types the server name", async (t) => {
  const sb = sandbox(t);
  await cli(["kill", "column"], { env: sb.env });
  const marker = join(sb.policyDir, "column", "KILL");

  const agent = await cli(["unkill", "column"], { env: sb.env, interactive: false });
  assert.equal(agent.code, 1);
  assert.match(agent.errText, /type "column" at a terminal/);
  assert.match(agent.errText, /Run it yourself/);
  assert.ok(existsSync(marker));

  const wrong = await cli(["unkill", "column"], { env: sb.env, interactive: true, answers: ["yes"] });
  assert.equal(wrong.code, 1);
  assert.match(wrong.errText, /did not match\. Nothing was changed/);
  assert.match(wrong.asked[0], /Type column to continue/);
  assert.ok(existsSync(marker));

  const right = await cli(["unkill", "column", "--json"], { env: sb.env, interactive: true, answers: [" column \n"] });
  assert.equal(right.code, 0);
  assert.equal(right.json.removed, true);
  assert.equal(existsSync(marker), false);
});

test("unkill --all asks for 'all'", async (t) => {
  const sb = sandbox(t);
  await cli(["kill", "--all"], { env: sb.env });
  const wrong = await cli(["unkill", "--all"], { env: sb.env, interactive: true, answers: ["every server"] });
  assert.equal(wrong.code, 1);
  const right = await cli(["unkill", "--all"], { env: sb.env, interactive: true, answers: ["all"] });
  assert.equal(right.code, 0);
  assert.equal(existsSync(join(sb.policyDir, "KILL")), false);
});

test("unkill without rights prints the rm command (exit 3)", async (t) => {
  if (isRoot || !posixHost) return t.skip("needs a non-root POSIX user");
  const sb = sandbox(t);
  await cli(["kill", "column"], { env: sb.env });
  const dir = join(sb.policyDir, "column");
  chmodSync(dir, 0o555);
  try {
    const r = await cli(["unkill", "column", "--json"], { env: sb.env, interactive: true, answers: ["column"] });
    assert.equal(r.code, 3);
    assert.deepEqual(r.json.admin.commands, [`sudo rm -f -- '${join(dir, "KILL")}'`]);
    assert.ok(existsSync(join(dir, "KILL")));
  } finally {
    chmodSync(dir, 0o755);
  }
});

test("kill --soft trips the user's state and writes one verifiable audit alert", async (t) => {
  const sb = sandbox(t);
  const r = await cli(["kill", "column", "--soft", "--note", "pause", "--json"], { env: sb.env });
  assert.equal(r.code, 0);
  assert.deepEqual(r.json.servers, ["column"]);
  const state = JSON.parse(readFileSync(join(sb.serverState("column"), "kill.json"), "utf8"));
  assert.deepEqual(state.trips, [{ scope: "all", reason: "mcp-guard kill --soft: pause", at: "2026-11-04T12:00:00.000Z" }]);
  const log = new AuditLog(sb.serverState("column"), "column");
  const lines = log.read();
  assert.equal(lines.length, 1);
  assert.equal(lines[0].decision, "alert");
  assert.equal(lines[0].alert, "cli_kill_soft");
  assert.equal(lines[0].operation, "cli.kill_soft");
  assert.equal(lines[0].session, "cli:4242");
  assert.ok(log.verifyAll().every((c) => c.ok));
  if (posixHost) assert.equal(statSync(sb.serverState("column")).mode & 0o777, 0o700);

  const again = await cli(["kill", "column", "--soft", "--note", "pause"], { env: sb.env });
  assert.equal(again.code, 0);
  const after = JSON.parse(readFileSync(join(sb.serverState("column"), "kill.json"), "utf8"));
  assert.equal(after.trips.length, 1, "the same soft kill twice is one trip");
});

test("kill --soft --all trips every known server; with none it fails", async (t) => {
  const sb = sandbox(t);
  const none = await cli(["kill", "--soft", "--all"], { env: sb.env });
  assert.equal(none.code, 1);
  assert.match(none.errText, /No servers found/);

  sb.policy("alpha", openPolicy("alpha"));
  mkdirSync(sb.serverState("beta"), { recursive: true });
  const r = await cli(["kill", "--soft", "--all", "--json"], { env: sb.env });
  assert.equal(r.code, 0);
  assert.deepEqual(r.json.servers, ["alpha", "beta"]);
  for (const s of ["alpha", "beta"]) assert.ok(existsSync(join(sb.serverState(s), "kill.json")), s);
});

test("kill --soft reports, not fails, when the audit line cannot be written", async (t) => {
  const sb = sandbox(t);
  const dir = sb.serverState("column");
  // A folder where this month's audit file belongs: the append fails at once.
  mkdirSync(join(dir, "audit-2026-11.jsonl"), { recursive: true });
  const r = await cli(["kill", "column", "--soft", "--json"], { env: sb.env });
  assert.equal(r.code, 0, "the trip itself must still land");
  assert.ok(existsSync(join(dir, "kill.json")));
  assert.equal(r.json.warnings.length, 1);
  assert.match(r.json.warnings[0], /^Could not write the audit line for column: /);
});
