import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { dist, manualClock, runWorkers, tempDir } from "./foundation-helpers.mjs";

const { Ledger, CANCEL_ALERT } = await import(dist("guard/ledger.js"));
const { AuditLog } = await import(dist("guard/audit.js"));

const ok = (r) => {
  assert.ok("id" in r, JSON.stringify(r));
  return r.id;
};
const always = () => null;

test("ledger: reserve records a reservation that counts until it fails", (t) => {
  const clock = manualClock("2026-11-04T12:00:00.000Z");
  const l = new Ledger(tempDir(t), { clock });
  const id = ok(l.reserve({ group: "spend", op: "ach_create", cents: 5000, currency: "USD" }, always));
  assert.match(id, /^[0-9a-f]{24}$/);
  assert.equal(l.snapshot().spendToday("USD"), 5000, "a reservation counts before the call returns");
  for (const status of ["done", "pending", "unknown"]) {
    l.settle(id, status);
    assert.equal(l.snapshot().spendToday("USD"), 5000, status);
  }
  l.settle(id, "failed");
  assert.equal(l.snapshot().spendToday("USD"), 0, "a failed call is not spend");
  assert.equal(l.snapshot().count("spend", "day"), 0);
  assert.doesNotThrow(() => l.settle("no-such-id", "done"));
});

test("ledger: the check sees the totals under the lock, and a refusal records nothing", (t) => {
  const l = new Ledger(tempDir(t), { clock: manualClock() });
  const cap = (s) => (s.spendToday("USD") + 6000 > 10000 ? { refused: true, reason_code: "over_per_day" } : null);
  ok(l.reserve({ group: "spend", op: "x", cents: 6000, currency: "USD" }, cap));
  assert.deepEqual(l.reserve({ group: "spend", op: "x", cents: 6000, currency: "USD" }, cap), { refusal: { refused: true, reason_code: "over_per_day" } });
  assert.equal(l.snapshot().spendToday("USD"), 6000);
  assert.equal(l.snapshot().count("spend", "day"), 1);
});

test("ledger: spend is per currency and per UTC day", (t) => {
  const clock = manualClock("2026-11-04T23:59:45.000Z");
  const l = new Ledger(tempDir(t), { clock });
  ok(l.reserve({ group: "spend", op: "x", cents: 1000, currency: "USD" }, always));
  ok(l.reserve({ group: "spend", op: "x", cents: 500, currency: "USD" }, always));
  ok(l.reserve({ group: "spend", op: "x", cents: 700, currency: "EUR" }, always));
  ok(l.reserve({ group: "change", op: "y" }, always));
  const s = l.snapshot();
  assert.equal(s.spendToday("USD"), 1500);
  assert.equal(s.spendToday("EUR"), 700);
  assert.equal(s.spendToday("GBP"), 0);
  clock.set("2026-11-05T00:00:15.000Z"); // 30 s later, across midnight UTC
  assert.equal(l.snapshot().spendToday("USD"), 0, "a new UTC day starts at zero");
  assert.equal(l.snapshot().count("spend", "day"), 0);
  assert.equal(l.snapshot().count("spend", "minute"), 3, "minute and hour windows roll across midnight");
});

test("ledger: rolling minute and hour windows", (t) => {
  const clock = manualClock("2026-11-04T12:00:00.000Z");
  const l = new Ledger(tempDir(t), { clock });
  ok(l.reserve({ group: "change", op: "a" }, always));
  clock.advance(30_000);
  ok(l.reserve({ group: "change", op: "b" }, always));
  clock.advance(29_000);
  ok(l.reserve({ group: "change", op: "c" }, always));
  ok(l.reserve({ group: "critical", op: "d" }, always));
  clock.advance(2_000); // 61 s after the first
  const s = l.snapshot();
  assert.equal(s.count("change", "minute"), 2);
  assert.equal(s.count("change", "hour"), 3);
  assert.equal(s.count("change", "day"), 3);
  assert.equal(s.count("critical", "minute"), 1);
  assert.equal(s.count("spend", "hour"), 0);
  clock.advance(3_600_000);
  assert.equal(l.snapshot().count("change", "hour"), 0);
});

test("ledger: events older than 49 hours are pruned on the next reserve", (t) => {
  const clock = manualClock("2026-11-01T00:00:00.000Z");
  const l = new Ledger(tempDir(t), { clock });
  ok(l.reserve({ group: "change", op: "old" }, always));
  clock.advance(48 * 3_600_000);
  ok(l.reserve({ group: "change", op: "mid" }, always));
  clock.advance(2 * 3_600_000);
  ok(l.reserve({ group: "change", op: "new" }, always));
  const ops = JSON.parse(readFileSync(l.file, "utf8")).events.map((e) => e.op);
  assert.deepEqual(ops, ["mid", "new"]);
});

function seedAudit(dir, clock) {
  const audit = new AuditLog(dir, "column", { clock });
  const base = { server: "column", version: "t", guard: "t", session: "s", tool: "column_spend", tier: "spend", group: "spend", mode: "live", dry_run: false, currency: "USD" };
  audit.append({ ...base, operation: "a", decision: "executed", amount_cents: 1000 });
  audit.append({ ...base, operation: "b", decision: "executed", amount_cents: 500 });
  audit.append({ ...base, operation: "c", decision: "pending", amount_cents: 200 });
  audit.append({ ...base, operation: "d", decision: "unknown_outcome", amount_cents: 300 });
  audit.append({ ...base, operation: "e", decision: "refused", amount_cents: 9999 });
  audit.append({ ...base, operation: "f", decision: "failed", amount_cents: 700 });
  audit.append({ ...base, operation: "g", decision: "dry_run", dry_run: true, amount_cents: 400 });
  audit.append({ ...base, operation: "h", decision: "deduplicated", amount_cents: 1000 });
  audit.append({ ...base, operation: "i", decision: "executed", amount_cents: 50, currency: "EUR" });
  audit.append({ ...base, tool: "column_change", tier: "write", group: "change", operation: "j", decision: "executed", currency: undefined });
  audit.append({ ...base, tool: "column_read", tier: "read", group: null, operation: "k", decision: "read", currency: undefined });
  return audit;
}

test("ledger: without a ledger file it is rebuilt from the audit log", (t) => {
  const dir = tempDir(t);
  const clock = manualClock("2026-11-04T12:00:00.000Z");
  const audit = seedAudit(dir, clock);
  const l = new Ledger(dir, { clock, audit });
  const s = l.snapshot();
  assert.equal(s.spendToday("USD"), 2000, "executed + pending + unknown_outcome; not refused, failed, dry runs or dedupes");
  assert.equal(s.spendToday("EUR"), 50);
  assert.equal(s.count("spend", "day"), 5);
  assert.equal(s.count("change", "day"), 1);
  ok(l.reserve({ group: "spend", op: "z", cents: 1, currency: "USD" }, always));
  const file = JSON.parse(readFileSync(l.file, "utf8"));
  assert.equal(file.rebuilt_from_audit, "2026-11-04T12:00:00.000Z");
  assert.equal(l.snapshot().spendToday("USD"), 2001, "the rebuilt events are kept once written");
});

test("ledger: a corrupt ledger file is rebuilt from the audit log", (t) => {
  const dir = tempDir(t);
  const clock = manualClock("2026-11-04T12:00:00.000Z");
  const audit = seedAudit(dir, clock);
  const l = new Ledger(dir, { clock, audit });
  writeFileSync(l.file, "{not json");
  assert.equal(l.snapshot().spendToday("USD"), 2000);
  // Valid JSON that is not a ledger is rebuilt too: read as empty, it would count nothing against the caps.
  const event = { id: "e", t: Date.parse("2026-11-04T11:00:00.000Z"), group: "spend", op: "pay", cents: 5, currency: "USD", status: "done" };
  const bad = [
    {},
    null,
    [],
    { version: 1, events: "nope" },
    { version: 1, events: [{ ...event, group: "Spend" }] },
    { version: 1, events: [{ ...event, status: "settled" }] },
    { version: 1, events: [{ ...event, t: "2026-11-04T11:00:00.000Z" }] },
    { version: 1, events: [{ ...event, cents: "5" }] },
    { version: 1, events: [event, null] },
  ];
  for (const shape of bad) {
    writeFileSync(l.file, JSON.stringify(shape));
    assert.equal(l.snapshot().spendToday("USD"), 2000, JSON.stringify(shape));
    assert.equal(l.snapshot().count("spend", "day"), 5, JSON.stringify(shape));
  }
  writeFileSync(l.file, JSON.stringify({ version: 1, events: [event] }));
  assert.equal(l.snapshot().spendToday("USD"), 5, "a ledger with the right shape is read as it is");
  const noAudit = new Ledger(dir, { clock });
  writeFileSync(noAudit.file, "{}");
  assert.equal(noAudit.snapshot().spendToday("USD"), 0, "without an audit log to rebuild from, it starts empty");
});

test("ledger: release frees only the open reservations held() read, of that call", (t) => {
  const l = new Ledger(tempDir(t), { clock: manualClock("2026-11-04T12:00:00.000Z") });
  const spend = (key, cents) => ok(l.reserve({ group: "spend", op: "pay", key, cents, currency: "USD" }, always));
  l.settle(spend("A", 100), "pending");
  spend("A", 200); // still reserved: its process died mid-call
  l.settle(spend("A", 400), "done");
  l.settle(spend("B", 800), "pending");
  const held = l.held("A");
  assert.equal(held.length, 2, "the pending and the reserved one, not the completed one");
  spend("A", 1600); // a retry that claimed the key after held() was read
  assert.equal(l.release("A", held), 2);
  assert.equal(l.snapshot().spendToday("USD"), 2800, "A's completed call, A's retry and B's call still count");
  assert.equal(l.release("A", held), 0, "nothing left to release");
  assert.equal(l.release("B", held), 0, "another call's ids release nothing");
  assert.equal(l.release("nobody", []), 0);
});

test("ledger: a retry under the key of an unknown-outcome call replaces it, in the check and the totals", (t) => {
  const l = new Ledger(tempDir(t), { clock: manualClock("2026-11-04T12:00:00.000Z") });
  const cap = (s) => (s.spendToday("USD") + 600 > 1000 ? { refused: true, reason_code: "over_per_day" } : null);
  l.settle(ok(l.reserve({ group: "spend", op: "pay", key: "K", cents: 600, currency: "USD" }, always)), "unknown");
  ok(l.reserve({ group: "spend", op: "pay", key: "other", cents: 100, currency: "USD" }, always));
  assert.equal(l.snapshot().spendToday("USD"), 700);
  assert.equal(l.snapshot({ replacing: "K" }).spendToday("USD"), 100, "the attempt being retried is left out");
  assert.equal(l.snapshot({ replacing: "K" }).count("spend", "day"), 1);
  assert.deepEqual(l.reserve({ group: "spend", op: "pay", key: "K", cents: 600, currency: "USD" }, cap), { refusal: { refused: true, reason_code: "over_per_day" } }, "without replacing it, the retry counts twice");
  const id = ok(l.reserve({ group: "spend", op: "pay", key: "K", cents: 600, currency: "USD" }, cap, { replacing: "K" }));
  assert.equal(l.snapshot().spendToday("USD"), 700, "counted once: the new reservation stands for the call");
  l.settle(id, "done");
  assert.equal(l.snapshot().spendToday("USD"), 700);
  assert.equal(l.snapshot().count("spend", "day"), 2);
});

test("ledger: a rebuild counts every read that reached the provider, answered or not", (t) => {
  const dir = tempDir(t);
  const clock = manualClock("2026-11-04T12:00:00.000Z");
  const audit = new AuditLog(dir, "column", { clock });
  const base = { server: "column", version: "t", guard: "t", session: "s", tool: "column_read", tier: "read", group: "read", mode: "live", dry_run: false, operation: "get" };
  audit.append({ ...base, decision: "read", http_status: 200 });
  audit.append({ ...base, decision: "failed", http_status: 503, sent: true });
  audit.append({ ...base, decision: "failed", http_status: null, sent: false }); // never sent
  audit.append({ ...base, decision: "failed", http_status: 500 }); // an older line that does not say
  audit.append({ ...base, decision: "refused", reason_code: "rate_limited" });
  audit.append({ ...base, decision: "alert", alert: "canary_read" });
  clock.advance(30 * 60_000);
  const s = new Ledger(dir, { clock, audit }).snapshot();
  assert.equal(s.count("read", "hour"), 2);
  assert.equal(s.count("read", "minute"), 0, "at the times they ran");
  assert.equal(s.count("change", "day"), 0);
});

test("ledger: a rebuild counts an unknown-outcome call and its retry under the same key once", (t) => {
  const dir = tempDir(t);
  const clock = manualClock("2026-11-04T12:00:00.000Z");
  const audit = new AuditLog(dir, "column", { clock });
  const base = { server: "column", version: "t", guard: "t", session: "s", tool: "column_spend", tier: "spend", group: "spend", mode: "live", dry_run: false, currency: "USD", operation: "pay" };
  audit.append({ ...base, decision: "unknown_outcome", idempotency_key: "K", amount_cents: 600 });
  audit.append({ ...base, decision: "executed", idempotency_key: "K", amount_cents: 600 });
  audit.append({ ...base, decision: "unknown_outcome", idempotency_key: "L", amount_cents: 50 });
  audit.append({ ...base, decision: "unknown_outcome", idempotency_key: "L", amount_cents: 50 });
  const s = new Ledger(dir, { clock, audit }).snapshot();
  assert.equal(s.spendToday("USD"), 650);
  assert.equal(s.count("spend", "day"), 2);
});

test("ledger: a rebuild releases what mcp-guard cancel released, and counts a retry, even one written before the cancel line", (t) => {
  const dir = tempDir(t);
  const clock = manualClock("2026-11-04T12:00:00.000Z");
  const audit = new AuditLog(dir, "column", { clock });
  const base = { server: "column", version: "t", guard: "t", session: "s", tool: "column_spend", tier: "spend", group: "spend", mode: "live", dry_run: false, currency: "USD" };
  const cancelLine = (key, cancelledAt) =>
    audit.append({ ...base, tool: "mcp-guard", operation: "cli.cancel", tier: "unknown", group: null, mode: "none", decision: "alert", alert: CANCEL_ALERT, idempotency_key: key, currency: undefined, ...(cancelledAt ? { cancelled_at: cancelledAt } : {}) });
  audit.append({ ...base, operation: "pay", decision: "pending", idempotency_key: "A", amount_cents: 200 });
  audit.append({ ...base, operation: "pay", decision: "unknown_outcome", idempotency_key: "B", amount_cents: 300 });
  audit.append({ ...base, operation: "pay", decision: "pending", idempotency_key: "C", amount_cents: 4000 });
  audit.append({ ...base, operation: "pay", decision: "pending", idempotency_key: "D", amount_cents: 50000 });
  clock.advance(60_000); // the person checks the provider, then cancels
  cancelLine("A", clock().toISOString());
  audit.append({ ...base, operation: "pay", decision: "executed", idempotency_key: "A", amount_cents: 200 });
  // C's retry claimed the key the moment cancel freed it, and its line was written before cancel's own.
  const cancelledAt = clock().toISOString();
  audit.append({ ...base, operation: "pay", decision: "pending", idempotency_key: "C", amount_cents: 4000 });
  cancelLine("C", cancelledAt);
  cancelLine("D"); // a cancel line without cancelled_at is cut at its own time
  assert.equal(new Ledger(dir, { clock, audit }).snapshot().spendToday("USD"), 4500, "B's 300, A's retry and C's retry; not the cancelled calls");
});

test("ledger: owner-only file", { skip: process.platform === "win32" }, (t) => {
  const l = new Ledger(tempDir(t), { clock: manualClock() });
  ok(l.reserve({ group: "change", op: "x" }, always));
  assert.equal(statSync(l.file).mode & 0o777, 0o600);
});

test("ledger: a cap holds across 6 processes reserving at once", async (t) => {
  const dir = tempDir(t);
  const code = `
    import { Ledger } from ${JSON.stringify(dist("guard/ledger.js"))};
    const l = new Ledger(process.env.LEDGER_DIR);
    let ok = 0;
    for (let i = 0; i < 5; i++) {
      const r = l.reserve({ group: "change", op: "x" }, (s) => (s.count("change", "hour") >= 10 ? "cap" : null));
      if ("id" in r) ok++;
    }
    process.stdout.write(String(ok));
  `;
  const outs = await runWorkers(6, code, { LEDGER_DIR: dir });
  assert.equal(
    outs.map(Number).reduce((a, b) => a + b, 0),
    10
  );
  assert.equal(new Ledger(dir).snapshot().count("change", "hour"), 10);
});
