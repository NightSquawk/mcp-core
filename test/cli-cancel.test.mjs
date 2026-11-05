// mcp-guard cancel: reopen a pending or unknown-outcome call, never a completed or running one.
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { cli, dist, manualClock, sandbox, test } from "./cli-helpers.mjs";

const { AuditLog } = await import(dist("guard/audit.js"));
const { IdempotencyStore, deriveKey } = await import(dist("guard/idempotency.js"));
const { Ledger } = await import(dist("guard/ledger.js"));

const DAY = "2026-11-04";

/** One entry in <state>/<server>, left in `status`. Returns { key, store }. */
function entry(sb, clock, server, status, opts = {}) {
  const dir = sb.serverState(server);
  mkdirSync(dir, { recursive: true });
  const store = new IdempotencyStore(dir, { clock });
  const key = deriveKey({ server, operation: opts.operation ?? "create_transfer", canonicalBody: opts.body ?? JSON.stringify({ status, n: Math.random() }), proposalDay: DAY });
  const b = store.begin(key, { operation: opts.operation ?? "create_transfer", request_hash: "sha256:x", day: DAY });
  assert.ok(b.claimed);
  if (status === "pending") store.finish(key, "pending", { pending: opts.pending ?? { ref: "APR-123", status: "waiting", url: "https://approvals.example.test/APR-123" } });
  else if (status !== "in_flight" && status !== "unknown") store.finish(key, status);
  return { key, store };
}

const statusOf = (store, key) => store.entries().find((e) => e.key === key)?.status;

test("cancel needs at least 8 characters of the key", async (t) => {
  const sb = sandbox(t);
  const r = await cli(["cancel", "abc1234"], { env: sb.env });
  assert.equal(r.code, 2);
  assert.match(r.errText, /at least 8 characters/);
  assert.equal((await cli(["cancel"], { env: sb.env })).code, 2);
});

test("cancel with no match fails", async (t) => {
  const sb = sandbox(t);
  mkdirSync(sb.serverState("column"), { recursive: true });
  const r = await cli(["cancel", "deadbeefcafe"], { env: sb.env });
  assert.equal(r.code, 1);
  assert.match(r.errText, /No idempotency entry matches "deadbeefcafe"/);
});

test("an unknown outcome is reopened only after typing the key's last 12 characters", async (t) => {
  const sb = sandbox(t);
  const clock = manualClock();
  const { key, store } = entry(sb, clock, "column", "unknown");
  clock.advance(6 * 60_000); // in_flight past five minutes reads as unknown
  const suffix = key.slice(-12);

  const agent = await cli(["cancel", suffix], { env: sb.env, clock });
  assert.equal(agent.code, 1);
  assert.match(agent.errText, /unknown outcome: the call may have run at the provider/);
  assert.match(agent.errText, /Run it yourself/);
  assert.equal(statusOf(store, key), "unknown");

  const wrong = await cli(["cancel", suffix], { env: sb.env, clock, interactive: true, answers: ["cancelled"] });
  assert.equal(wrong.code, 1);
  assert.equal(statusOf(store, key), "unknown");

  const right = await cli(["cancel", suffix, "--json"], { env: sb.env, clock, interactive: true, answers: [suffix] });
  assert.equal(right.code, 0);
  assert.equal(right.json.changed, true);
  assert.equal(right.json.new_status, "failed");
  assert.equal(statusOf(store, key), "failed");

  const lines = new AuditLog(sb.serverState("column"), "column").read();
  assert.equal(lines.length, 1);
  assert.equal(lines[0].alert, "cli_cancel");
  assert.equal(lines[0].idempotency_key, key);
  assert.equal(lines[0].note, "marked unknown entry failed; released 0 ledger reservation(s)");
});

test("a pending call needs its approval reference typed", async (t) => {
  const sb = sandbox(t);
  const clock = manualClock();
  const { key, store } = entry(sb, clock, "column", "pending");
  const wrong = await cli(["cancel", key.slice(0, 20)], { env: sb.env, clock, interactive: true, answers: ["cancelled"] });
  assert.equal(wrong.code, 1);
  assert.match(wrong.asked[0], /waiting for approval \(reference APR-123, waiting\) at https:\/\/approvals\.example\.test\/APR-123/);
  assert.match(wrong.asked[0], /cancels nothing there/);
  assert.equal(statusOf(store, key), "pending");

  const right = await cli(["cancel", key.slice(0, 20)], { env: sb.env, clock, interactive: true, answers: ["APR-123"] });
  assert.equal(right.code, 0);
  assert.match(right.text, /Nothing was cancelled at the provider/);
  assert.equal(statusOf(store, key), "failed");
});

test("cancel releases the call's ledger reservation, so the retry it allows is not refused for it", async (t) => {
  const sb = sandbox(t);
  const clock = manualClock();
  const dir = sb.serverState("column");
  const { key, store } = entry(sb, clock, "column", "pending");
  // What the guard left, in its order: a reservation of 500 USD settled pending, then the audit line.
  const audit = new AuditLog(dir, "column", { clock });
  const ledger = new Ledger(dir, { clock, audit });
  const r = ledger.reserve({ group: "spend", op: "create_transfer", key, cents: 500, currency: "USD" }, () => null);
  ledger.settle(r.id, "pending");
  const line = { server: "column", version: "t", guard: "t", session: "s", tool: "column_spend", tier: "spend", group: "spend", mode: "live", dry_run: false };
  audit.append({ ...line, operation: "create_transfer", decision: "pending", idempotency_key: key, amount_cents: 500, currency: "USD" });
  assert.equal(ledger.snapshot().spendToday("USD"), 500);

  const out = await cli(["cancel", key.slice(0, 20), "--json"], { env: sb.env, clock, interactive: true, answers: ["APR-123"] });
  assert.equal(out.code, 0);
  assert.equal(out.json.ledger_released, 1);
  assert.equal(statusOf(store, key), "failed");
  assert.equal(ledger.snapshot().spendToday("USD"), 0, "no longer counted");
  assert.match(audit.read().at(-1).note, /released 1 ledger reservation/);

  // A ledger rebuilt from the audit log releases it again.
  rmSync(ledger.file);
  assert.equal(new Ledger(dir, { clock, audit }).snapshot().spendToday("USD"), 0);
});

test("a pending call without a reference needs 'cancelled'", async (t) => {
  const sb = sandbox(t);
  const clock = manualClock();
  const { key, store } = entry(sb, clock, "column", "pending", { pending: {} });
  const r = await cli(["cancel", key.slice(-12)], { env: sb.env, clock, interactive: true, answers: ["cancelled"] });
  assert.equal(r.code, 0);
  assert.equal(statusOf(store, key), "failed");
});

test("a completed call is never reopened", async (t) => {
  const sb = sandbox(t);
  const clock = manualClock();
  const { key, store } = entry(sb, clock, "column", "done");
  const r = await cli(["cancel", key.slice(-12), "--json"], { env: sb.env, clock, interactive: true, answers: [key.slice(-12)] });
  assert.equal(r.code, 1);
  assert.equal(r.json.ok, false);
  assert.equal(r.json.status, "done");
  assert.match(r.json.error, /would let the same request run a second time/);
  assert.equal(r.asked.length, 0);
  assert.equal(statusOf(store, key), "done");
});

test("a running call is never reopened", async (t) => {
  const sb = sandbox(t);
  const clock = manualClock();
  const { key, store } = entry(sb, clock, "column", "in_flight");
  const r = await cli(["cancel", key.slice(-12)], { env: sb.env, clock, interactive: true, answers: [key.slice(-12)] });
  assert.equal(r.code, 1);
  assert.match(r.errText, /is running right now \(pid \d+\)/);
  assert.equal(statusOf(store, key), "in_flight");
});

test("an already failed call is a no-op", async (t) => {
  const sb = sandbox(t);
  const clock = manualClock();
  const { key } = entry(sb, clock, "column", "failed");
  const r = await cli(["cancel", key.slice(-12), "--json"], { env: sb.env, clock, interactive: true });
  assert.equal(r.code, 0);
  assert.equal(r.json.changed, false);
  assert.equal(r.asked.length, 0);
});

test("an ambiguous key lists the matches and changes nothing", async (t) => {
  const sb = sandbox(t);
  const clock = manualClock();
  const a = entry(sb, clock, "column", "pending", { body: "a" });
  const b = entry(sb, clock, "column", "pending", { body: "b" });
  const r = await cli(["cancel", "nst-column-"], { env: sb.env, clock, interactive: true, answers: ["APR-123"] });
  assert.equal(r.code, 1);
  assert.match(r.errText, /2 entries match "nst-column-"/);
  assert.equal(statusOf(a.store, a.key), "pending");
  assert.equal(statusOf(b.store, b.key), "pending");
});

test("without --server, cancel searches every state folder and names unreadable stores", async (t) => {
  const sb = sandbox(t);
  const clock = manualClock();
  const { key, store } = entry(sb, clock, "beta", "pending");
  mkdirSync(sb.serverState("alpha"), { recursive: true });
  writeFileSync(join(sb.serverState("alpha"), "idempotency.json"), "garbage");

  const miss = await cli(["cancel", "0000000000000000"], { env: sb.env, clock });
  assert.match(miss.errText, /Unreadable stores: alpha: /);

  const r = await cli(["cancel", key.slice(-12), "--json"], { env: sb.env, clock, interactive: true, answers: ["APR-123"] });
  assert.equal(r.code, 0);
  assert.equal(r.json.server, "beta");
  assert.equal(statusOf(store, key), "failed");

  const scoped = await cli(["cancel", key.slice(-12), "--server", "alpha"], { env: sb.env, clock });
  assert.equal(scoped.code, 1, "--server limits the search");
  assert.equal(readFileSync(join(sb.serverState("alpha"), "idempotency.json"), "utf8"), "garbage");
});
