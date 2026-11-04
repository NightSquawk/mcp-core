import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dist, manualClock, runWorkers, tempDir } from "./foundation-helpers.mjs";

const I = await import(dist("guard/idempotency.js"));

const MIN = 60_000;
const input = (over = {}) => ({ server: "column", operation: "ach_create", canonicalBody: '{"body":{"amount":100}}', proposalDay: "2026-11-04", ...over });
const info = { operation: "ach_create", request_hash: "sha256:test", day: "2026-11-04" };

test("deriveKey: deterministic, prefixed, and sensitive to every input", () => {
  const k = I.deriveKey(input());
  assert.match(k, /^nst-column-[0-9a-f]{64}$/);
  assert.equal(I.deriveKey(input()), k);
  for (const over of [{ server: "proxmox" }, { operation: "wire_create" }, { canonicalBody: '{"body":{"amount":101}}' }, { proposalDay: "2026-11-05" }]) {
    assert.notEqual(I.deriveKey(input(over)), k, JSON.stringify(over));
  }
  // Field boundaries are unambiguous: moving text between fields changes the key.
  assert.notEqual(I.deriveKey(input({ server: "a", operation: "b\nc" })), I.deriveKey(input({ server: "a\nb", operation: "c" })));
});

test("deriveKey: respects the provider's length limit, with a 16-character floor", () => {
  assert.equal(I.deriveKey(input({ maxLength: 40 })).length, 40);
  assert.equal(I.deriveKey(input({ maxLength: 40 })), I.deriveKey(input()).slice(0, 40));
  assert.equal(I.deriveKey(input({ maxLength: 5 })).length, 16);
  assert.equal(I.deriveKey(input({ maxLength: 1000 })).length, "nst-column-".length + 64);
});

test("deriveKey: a long server name never truncates the digest away", () => {
  const server = "x".repeat(60);
  const a = I.deriveKey(input({ server, maxLength: 64 }));
  const b = I.deriveKey(input({ server, maxLength: 64, canonicalBody: '{"body":{"amount":999}}' }));
  assert.ok(a.length <= 64);
  assert.notEqual(a, b, `two different requests got the same key ${a}, so the second would be answered with the first's result`);
});

test("idempotency: begin claims once; a second call sees the first", (t) => {
  const clock = manualClock();
  const s = new I.IdempotencyStore(tempDir(t), { clock });
  assert.deepEqual(s.begin("k1", info), { claimed: true });
  const again = s.begin("k1", info);
  assert.equal(again.claimed, false);
  assert.equal(again.existing.status, "in_flight");
  assert.equal(again.existing.pid, process.pid);
  s.finish("k1", "done", { http_status: 201, provider_ids: ["tr_1"] });
  const done = s.begin("k1", info);
  assert.equal(done.claimed, false);
  assert.equal(done.existing.status, "done");
  assert.deepEqual(done.existing.result, { http_status: 201, provider_ids: ["tr_1"] });
  assert.equal(s.lookup(["nope", "k1"]).status, "done");
  assert.equal(s.lookup(["nope"]), null);
  assert.doesNotThrow(() => s.finish("never-begun", "done"));
});

test("idempotency: a failed call may be retried", (t) => {
  const s = new I.IdempotencyStore(tempDir(t), { clock: manualClock() });
  s.begin("k", info);
  s.finish("k", "failed");
  assert.deepEqual(s.begin("k", info), { claimed: true });
});

test("idempotency: a dead in-flight call becomes unknown and is never claimed by begin", (t) => {
  const clock = manualClock();
  const s = new I.IdempotencyStore(tempDir(t), { clock });
  s.begin("k", info);
  clock.advance(4 * MIN);
  assert.equal(s.lookup(["k"]).status, "in_flight");
  clock.advance(2 * MIN);
  assert.equal(s.lookup(["k"]).status, "unknown");
  assert.equal(s.entries()[0].status, "unknown");
  const r = s.begin("k", info);
  assert.equal(r.claimed, false);
  assert.equal(r.existing.status, "unknown");
  assert.equal(s.reclaimUnknown("k"), true, "only reclaimUnknown retries it");
  assert.equal(s.lookup(["k"]).status, "in_flight");
  assert.equal(s.reclaimUnknown("k"), false, "a live in-flight call is not unknown");
  s.finish("k", "done");
  assert.equal(s.reclaimUnknown("k"), false);
  assert.equal(s.reclaimUnknown("missing"), false);
});

test("idempotency: the window re-opens done entries only, never unknown or pending ones", (t) => {
  const clock = manualClock();
  const s = new I.IdempotencyStore(tempDir(t), { clock });
  const windowMs = 10 * MIN;
  s.begin("done", info);
  s.finish("done", "done");
  s.begin("unknown", info);
  s.finish("unknown", "unknown");
  s.begin("pending", info);
  s.finish("pending", "pending", { pending: { ref: "apr_1", status: "awaiting_approval" } });
  s.begin("dead", info); // never finished: in flight, then unknown
  clock.advance(5 * MIN);
  for (const k of ["done", "unknown", "pending", "dead"]) assert.equal(s.begin(k, info, { windowMs }).claimed, false, `${k} inside the window`);
  clock.advance(6 * MIN);
  assert.deepEqual(s.begin("done", info, { windowMs }), { claimed: true }, "after the window the same request is a new request");
  for (const k of ["unknown", "pending", "dead"]) {
    assert.equal(s.begin(k, info, { windowMs }).claimed, false, `${k} after the window: it may have executed, so begin() must not run it again`);
    assert.notEqual(s.lookup([k], { windowMs }), null, `${k}: lookup() must still report it`);
  }
});

test("idempotency: lookup never writes", (t) => {
  const dir = tempDir(t);
  const s = new I.IdempotencyStore(dir, { clock: manualClock() });
  assert.equal(s.lookup(["k"]), null);
  assert.deepEqual(readdirSync(dir), []);
  s.begin("k", info);
  const before = readFileSync(s.file, "utf8");
  s.lookup(["k"], { windowMs: 1 });
  assert.equal(readFileSync(s.file, "utf8"), before);
});

test("idempotency: entries older than three days are pruned on begin", (t) => {
  const clock = manualClock("2026-11-01T00:00:00.000Z");
  const s = new I.IdempotencyStore(tempDir(t), { clock });
  s.begin("old", info);
  s.finish("old", "done");
  clock.advance(3 * 86_400_000 + 1);
  s.begin("new", info);
  assert.deepEqual(
    s.entries().map((e) => e.key),
    ["new"]
  );
});

test("idempotency: cancel needs a unique match and only reopens a call that may not have happened", (t) => {
  const s = new I.IdempotencyStore(tempDir(t), { clock: manualClock() });
  const keyOf = (b) => I.deriveKey(input({ canonicalBody: b }));
  const [p, u, d, live] = ["p", "u", "d", "live"].map(keyOf);
  s.begin(p, info);
  s.finish(p, "pending", { pending: { ref: "apr_1" } });
  s.begin(u, info);
  s.finish(u, "unknown");
  s.begin(d, info);
  s.finish(d, "done");
  s.begin(live, info);
  assert.equal(s.cancel("nst-column-"), null, "ambiguous prefix");
  assert.equal(s.cancel("nothing-matches"), null);
  for (const k of [p, u]) {
    const c = s.cancel(k.slice(-12));
    assert.equal(c?.key, k, "a unique suffix matches (the guard's outcome_unknown hint prints key.slice(-12))");
    assert.equal(c.status, "failed");
    assert.equal(s.begin(k, info).claimed, true, "a cancelled call may be retried");
  }
  assert.equal(s.cancel(d.slice(-12)), null, "a completed call cannot be cancelled");
  assert.equal(s.lookup([d]).status, "done");
  assert.equal(s.begin(d, info).claimed, false, "so a retry is still answered from the store, not run again");
  assert.equal(s.cancel(live.slice(-12)), null, "a call running right now cannot be cancelled");
  assert.equal(s.lookup([live]).status, "in_flight");
});

test("idempotency: an empty prefix never matches, even with a single entry", (t) => {
  const s = new I.IdempotencyStore(tempDir(t), { clock: manualClock() });
  const k = I.deriveKey(input());
  s.begin(k, info);
  s.finish(k, "pending", { pending: { ref: "apr_1" } });
  assert.equal(s.cancel(""), null);
  assert.equal(s.lookup([k]).status, "pending");
});

test("idempotency: a corrupt store never lets a completed call run again", (t) => {
  const dir = tempDir(t);
  const s = new I.IdempotencyStore(dir, { clock: manualClock() });
  s.begin("k", info);
  s.finish("k", "done");
  writeFileSync(s.file, '{"version":1,"entries":{"k":');
  for (const attempt of [1, 2]) {
    let r;
    try {
      r = s.begin("k", info);
    } catch {
      r = { threw: true };
    }
    assert.notDeepEqual(r, { claimed: true }, `attempt ${attempt}: with its records unreadable the store must refuse, not start empty (moving the file aside must not reopen it either)`);
  }
  const kept = readdirSync(dir).some((f) => f.startsWith("idempotency.json") && readFileSync(`${dir}/${f}`, "utf8").startsWith('{"version":1,"entries":{"k":'));
  assert.ok(kept, "the corrupt file is kept for inspection, not overwritten");
});

test("idempotency: owner-only file", { skip: process.platform === "win32" }, (t) => {
  const s = new I.IdempotencyStore(tempDir(t), { clock: manualClock() });
  s.begin("k", info);
  assert.equal(statSync(s.file).mode & 0o777, 0o600);
  assert.equal(existsSync(`${s.file.replace(/\.json$/, "")}.lock`), false);
});

test("idempotency: today() is the UTC day", () => {
  assert.equal(I.IdempotencyStore.today(() => new Date("2026-11-04T23:30:00-08:00")), "2026-11-05");
});

test("idempotency: exactly one of 8 racing processes claims a key", async (t) => {
  const dir = tempDir(t);
  const code = `
    import { IdempotencyStore } from ${JSON.stringify(dist("guard/idempotency.js"))};
    const s = new IdempotencyStore(process.env.IDEM_DIR);
    const r = s.begin("nst-column-race", { operation: "ach_create", request_hash: "sha256:x", day: "2026-11-04" });
    process.stdout.write(r.claimed ? "1" : "0");
  `;
  const outs = await runWorkers(8, code, { IDEM_DIR: dir });
  assert.equal(outs.filter((o) => o === "1").length, 1, JSON.stringify(outs));
});
