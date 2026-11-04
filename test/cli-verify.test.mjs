// mcp-guard verify: pass/warn/fail checks; exit 1 on any failure.
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { cli, dist, manualClock, openPolicy, sandbox, tempDir, test } from "./cli-helpers.mjs";

const { AuditLog } = await import(dist("guard/audit.js"));
const { IdempotencyStore } = await import(dist("guard/idempotency.js"));
const { buildManifest } = await import(dist("guard/manifest.js"));

const posixHost = process.platform !== "win32";
const levels = (json) => Object.fromEntries(json.checks.map((c) => [c.id, c.level]));

test("a clean install passes, with protection a warning", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  const r = await cli(["verify", "column", "--json"], { env: sb.env, cwd: sb.base });
  assert.equal(r.code, 0);
  assert.equal(r.json.ok, true);
  assert.deepEqual(levels(r.json), {
    policy: "pass",
    protection: "warn",
    effective: "pass",
    kill: "pass",
    audit: "skip",
    idempotency: "pass",
    ledger: "pass",
    "state-permissions": "skip",
    manifest: "skip",
    tiers: "skip",
  });
  const text = await cli(["verify", "column"], { env: sb.env, cwd: sb.base });
  assert.match(text.text, /column: no failures, 1 warning\./);
});

test("--strict fails an unprotected policy; a protected one passes", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  const strict = await cli(["verify", "column", "--strict", "--json"], { env: sb.env, cwd: sb.base });
  assert.equal(strict.code, 1);
  assert.equal(levels(strict.json).protection, "fail");
  const ok = await cli(["verify", "column", "--strict", "--json"], { env: sb.env, cwd: sb.base, protect: true });
  assert.equal(ok.code, 0);
  assert.equal(levels(ok.json).protection, "pass");
});

test("no policy file warns; a rejected policy fails", async (t) => {
  const sb = sandbox(t);
  const none = await cli(["verify", "column", "--json"], { env: sb.env, cwd: sb.base });
  assert.equal(none.code, 0);
  assert.equal(levels(none.json).policy, "warn");
  sb.policy("column", { version: 1, server: "column", groups: { change: 1 } });
  const bad = await cli(["verify", "column", "--json"], { env: sb.env, cwd: sb.base });
  assert.equal(bad.code, 1);
  assert.equal(levels(bad.json).policy, "fail");
});

test("a broken audit chain fails", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  const log = new AuditLog(sb.serverState("column"), "column", { clock: manualClock() });
  const entry = { server: "column", version: "1", guard: "t", session: "s", tool: "x", operation: "op", tier: "read", group: "read", mode: "none", decision: "read", dry_run: false };
  log.append(entry);
  log.append(entry);
  const good = await cli(["verify", "column", "--json"], { env: sb.env, cwd: sb.base });
  assert.equal(levels(good.json).audit, "pass");
  assert.match(good.json.checks.find((c) => c.id === "audit").message, /1 file, 2 lines, chain intact/);

  const file = log.files()[0];
  const lines = readFileSync(file, "utf8").split("\n");
  lines.splice(0, 1); // drop the first line
  writeFileSync(file, lines.join("\n"));
  const r = await cli(["verify", "column", "--json"], { env: sb.env, cwd: sb.base });
  assert.equal(r.code, 1);
  const audit = r.json.checks.find((c) => c.id === "audit");
  assert.equal(audit.level, "fail");
  assert.match(audit.message, /1 broken chain: the server trips its kill switch at start/);
});

test("unreadable kill or idempotency state fails; an unknown outcome warns", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  const dir = sb.serverState("column");
  mkdirSync(dir, { recursive: true, mode: 0o700 });

  writeFileSync(join(dir, "kill.json"), "{");
  const kill = await cli(["verify", "column", "--json"], { env: sb.env, cwd: sb.base });
  assert.equal(kill.code, 1);
  assert.equal(levels(kill.json).kill, "fail");
  writeFileSync(join(dir, "kill.json"), JSON.stringify({ trips: [] }));

  writeFileSync(join(dir, "idempotency.json"), "[]");
  const idem = await cli(["verify", "column", "--json"], { env: sb.env, cwd: sb.base });
  assert.equal(idem.code, 1);
  assert.equal(levels(idem.json).idempotency, "fail");
  writeFileSync(join(dir, "idempotency.json"), JSON.stringify({ version: 1, entries: {} }));

  const clock = manualClock();
  const key = "nst-column-0123456789abcdef01234567";
  new IdempotencyStore(dir, { clock }).begin(key, { operation: "create_transfer", request_hash: "h", day: "2026-11-04" });
  clock.advance(10 * 60_000); // a running entry older than five minutes reads as unknown
  const unknown = await cli(["verify", "column", "--json"], { env: sb.env, cwd: sb.base, clock });
  assert.equal(unknown.code, 0);
  const check = unknown.json.checks.find((c) => c.id === "idempotency");
  assert.equal(check.level, "warn");
  assert.deepEqual(check.detail, [`...${key.slice(-12)} create_transfer created 2026-11-04T12:00:00.000Z`]);

  writeFileSync(join(dir, "ledger.json"), "nope");
  const ledger = await cli(["verify", "column", "--json"], { env: sb.env, cwd: sb.base, clock });
  assert.equal(levels(ledger.json).ledger, "warn");
});

test("state readable by other users warns", async (t) => {
  if (!posixHost) return t.skip("POSIX modes only");
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  const dir = sb.serverState("column");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tight = await cli(["verify", "column", "--json"], { env: sb.env, cwd: sb.base });
  assert.equal(levels(tight.json)["state-permissions"], "pass");
  chmodSync(dir, 0o755);
  const loose = await cli(["verify", "column", "--json"], { env: sb.env, cwd: sb.base });
  assert.equal(levels(loose.json)["state-permissions"], "warn");
  assert.match(loose.json.checks.find((c) => c.id === "state-permissions").detail[0], /is mode 0755$/);
});

test("verify checks a manifest for the same server and skips one for another", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  const pkg = tempDir(t);
  mkdirSync(join(pkg, "dist"));
  const manifest = (server) => buildManifest({ server, version: "1.0.0", prefix: server, operations: [{ operationId: "list", tier: "read" }] });
  writeFileSync(join(pkg, "dist", "guard-manifest.json"), JSON.stringify(manifest("column")));
  const r = await cli(["verify", "column", "--package", pkg, "--json"], { env: sb.env });
  assert.equal(levels(r.json).manifest, "pass");

  writeFileSync(join(pkg, "dist", "guard-manifest.json"), JSON.stringify(manifest("other")));
  const auto = await cli(["verify", "column", "--json"], { env: sb.env, cwd: pkg });
  assert.equal(levels(auto.json).manifest, "skip", "./dist for another server is not this server's");
  const named = await cli(["verify", "column", "--package", pkg, "--json"], { env: sb.env });
  assert.equal(named.code, 1);
  assert.equal(levels(named.json).manifest, "fail");

  const missing = await cli(["verify", "column", "--manifest", join(pkg, "nope.json"), "--json"], { env: sb.env });
  assert.equal(levels(missing.json).manifest, "fail");
});

test("verify --tiers checks every operation of an OpenAPI document", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", openPolicy("column"));
  const dir = tempDir(t);
  const openapi = {
    openapi: "3.1.0",
    paths: {
      "/accounts": { get: { operationId: "list_accounts" }, post: { operationId: "create_account" } },
      "/transfers": { post: { operationId: "create_transfer" }, delete: {} },
    },
  };
  writeFileSync(join(dir, "openapi.json"), JSON.stringify(openapi));
  writeFileSync(join(dir, "tiers.json"), JSON.stringify({ operations: { list_accounts: { tier: "read" }, create_account: { tier: "write" }, create_transfer: { tier: "spend" } } }));
  const ok = await cli(["verify", "column", "--tiers", "tiers.json", "--operations", "openapi.json", "--json"], { env: sb.env, cwd: dir });
  const tiers = ok.json.checks.find((c) => c.id === "tiers");
  assert.equal(tiers.level, "pass");
  assert.deepEqual(tiers.detail, ["1 operation(s) without an operationId were not checked"]);

  writeFileSync(join(dir, "tiers.json"), JSON.stringify({ operations: { list_accounts: { tier: "read" }, create_account: { tier: "write" } } }));
  const missing = await cli(["verify", "column", "--tiers", "tiers.json", "--operations", "openapi.json", "--json"], { env: sb.env, cwd: dir });
  assert.equal(missing.code, 1);
  const m = missing.json.checks.find((c) => c.id === "tiers");
  assert.equal(m.level, "fail");
  assert.ok(m.detail.some((d) => d.startsWith("missing: create_transfer:")));

  const half = await cli(["verify", "column", "--tiers", "tiers.json"], { env: sb.env, cwd: dir });
  assert.equal(half.code, 2);
});

test("verify needs a server; --file must exist", async (t) => {
  const sb = sandbox(t);
  assert.equal((await cli(["verify"], { env: sb.env })).code, 2);
  const r = await cli(["verify", "column", "--file", "nope.json"], { env: sb.env, cwd: sb.base });
  assert.equal(r.code, 1);
  assert.match(r.errText, /No such file/);
});
