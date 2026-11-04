import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFileSync, copyFileSync, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { dist, manualClock, runWorkers, tempDir } from "./foundation-helpers.mjs";

const A = await import(dist("guard/audit.js"));
const { canonicalJson } = await import(dist("guard/canonical.js"));

const entry = (over = {}) => ({
  server: "column",
  version: "0.0.0-test",
  guard: "0.3.0-dev.0",
  session: "s1",
  tool: "column_change",
  operation: "counterparty_create",
  tier: "write",
  group: "change",
  mode: "sandbox",
  decision: "executed",
  dry_run: false,
  ...over,
});
const linesOf = (file) => readFileSync(file, "utf8").split("\n").filter(Boolean);

function logWith(t, n = 4, clock = manualClock("2026-11-04T12:00:00.000Z")) {
  const dir = tempDir(t);
  const log = new A.AuditLog(dir, "column", { clock });
  const out = [];
  for (let i = 0; i < n; i++) {
    out.push(log.append(entry({ operation: `op_${i}`, amount_cents: 100 * (i + 1) })));
    clock.advance(1_000);
  }
  return { dir, log, lines: out, file: log.fileFor("2026-11"), clock };
}

test("audit: genesis and lineHash are what verify recomputes", () => {
  assert.equal(A.genesis("column", "2026-11"), "genesis:column:2026-11");
  const body = { v: 1, ts: "2026-11-04T12:00:00.000Z", pid: 1, ...entry(), prev: "genesis:column:2026-11" };
  const expected = "sha256:" + createHash("sha256").update(`genesis:column:2026-11\n${canonicalJson(body)}`).digest("hex");
  assert.equal(A.lineHash("genesis:column:2026-11", body), expected);
});

test("audit: each line chains onto the one before", (t) => {
  const { lines, file } = logWith(t, 3);
  assert.equal(lines[0].prev, "genesis:column:2026-11");
  assert.equal(lines[1].prev, lines[0].hash);
  assert.equal(lines[2].prev, lines[1].hash);
  for (const l of lines) {
    assert.equal(l.v, 1);
    assert.equal(l.pid, process.pid);
    const { hash, ...rest } = l;
    assert.equal(hash, A.lineHash(l.prev, rest));
  }
  assert.equal(lines[0].ts, "2026-11-04T12:00:00.000Z");
  assert.equal(lines[1].ts, "2026-11-04T12:00:01.000Z");
  assert.deepEqual(linesOf(file).map((s) => JSON.parse(s)), lines, "what append returns is what is on disk");
});

test("audit: verify passes an intact chain", (t) => {
  const { log, file } = logWith(t, 4);
  assert.deepEqual(log.verify(file), { file, ok: true, lines: 4 });
  assert.deepEqual(log.verifyAll(), [{ file, ok: true, lines: 4 }]);
  assert.deepEqual(log.verify(join(log.dir, "audit-2020-01.jsonl")), { file: join(log.dir, "audit-2020-01.jsonl"), ok: true, lines: 0 });
});

test("audit: verify finds edits, deletions, reordering, insertions and forged lines", (t) => {
  const { dir, log, file } = logWith(t, 4);
  const original = linesOf(file);
  const check = (mutated) => {
    writeFileSync(file, mutated.join("\n") + "\n");
    return log.verify(file);
  };
  const edited = original.map((l, i) => (i === 1 ? l.replace('"amount_cents":200', '"amount_cents":20000') : l));
  assert.notDeepEqual(edited, original);
  assert.deepEqual(check(edited), { file, ok: false, lines: 4, brokenAt: 2, reason: "hash does not match the line" });
  assert.deepEqual(check([original[0], original[2], original[3]]), { file, ok: false, lines: 3, brokenAt: 2, reason: "prev does not match the line before" });
  assert.deepEqual(check([original[0], original[2], original[1], original[3]]).brokenAt, 2);
  assert.deepEqual(check([original[0], original[1], "not json at all", original[2], original[3]]), { file, ok: false, lines: 5, brokenAt: 3, reason: "not JSON" });
  // A consistent forgery of line 2 still breaks the link from line 3.
  const forged = JSON.parse(original[1]);
  forged.amount_cents = 1;
  delete forged.hash;
  forged.hash = A.lineHash(forged.prev, forged);
  assert.deepEqual(check([original[0], JSON.stringify(forged), original[2], original[3]]).brokenAt, 3);
  // The first line must start from this server's genesis for this month.
  const firstEdited = JSON.parse(original[0]);
  firstEdited.prev = "genesis:column:2026-10";
  assert.equal(check([JSON.stringify(firstEdited), ...original.slice(1)]).brokenAt, 1);
  writeFileSync(file, original.join("\n") + "\n");
  copyFileSync(file, join(dir, "audit-2026-10.jsonl"));
  assert.equal(log.verify(join(dir, "audit-2026-10.jsonl")).brokenAt, 1, "lines cannot be moved to another month");
  assert.equal(new A.AuditLog(dir, "proxmox").verify(file).brokenAt, 1, "or claimed by another server");
});

test("audit: known limit, a cut tail still verifies (G5 forwards lines off-box)", (t) => {
  const { log, file } = logWith(t, 4);
  writeFileSync(file, linesOf(file).slice(0, 2).join("\n") + "\n");
  assert.deepEqual(log.verify(file), { file, ok: true, lines: 2 });
});

test("audit: a new UTC month starts a new file and a new chain", (t) => {
  const dir = tempDir(t);
  const clock = manualClock("2026-11-30T23:59:59.000Z");
  const log = new A.AuditLog(dir, "column", { clock });
  const nov = log.append(entry({ operation: "nov" }));
  clock.set("2026-12-01T00:00:01.000Z");
  const dec = log.append(entry({ operation: "dec" }));
  assert.equal(dec.prev, "genesis:column:2026-12");
  assert.notEqual(dec.prev, nov.hash);
  assert.deepEqual(log.files(), [join(dir, "audit-2026-11.jsonl"), join(dir, "audit-2026-12.jsonl")]);
  assert.ok(log.verifyAll().every((c) => c.ok && c.lines === 1));
  assert.deepEqual(log.read().map((l) => l.operation), ["nov", "dec"], "read() covers last month and this one");
  assert.deepEqual(log.read(["2026-11"]).map((l) => l.operation), ["nov"]);
  clock.set("2027-02-01T00:00:00.000Z");
  assert.deepEqual(log.read(), [], "two months later neither file is read by default");
  writeFileSync(join(dir, "audit-2026-12.jsonl.bak"), "x");
  writeFileSync(join(dir, "notes.txt"), "x");
  assert.equal(log.files().length, 2, "only audit-YYYY-MM.jsonl files count");
});

test("audit: everything is redacted before it is hashed and written; amounts survive", (t) => {
  const dir = tempDir(t);
  const secretValue = "Zx9Zx9Zx9Zx9Zx9Zx9";
  const log = new A.AuditLog(dir, "column", { clock: manualClock(), secrets: () => [secretValue] });
  const line = log.append(
    entry({ note: `Authorization: Bearer abcdefgh123 key ${secretValue} acct 123456789012`, amount_cents: 12345678, http_status: 201, provider_ids: ["acct_1"] })
  );
  const raw = readFileSync(log.fileFor("2026-11"), "utf8");
  assert.ok(!raw.includes("abcdefgh123") && !raw.includes(secretValue) && !raw.includes("123456789012"), raw);
  assert.match(line.note, /Bearer \[redacted\] key \[redacted\] acct \*\*\*\*9012/);
  assert.equal(line.amount_cents, 12345678);
  assert.equal(line.operation, "counterparty_create");
  assert.deepEqual(log.verifyAll()[0].ok, true, "the hash covers the redacted text");
});

test("audit: append refuses anything but an entry object with an operation", (t) => {
  const log = new A.AuditLog(tempDir(t), "column", { clock: manualClock() });
  for (const bad of [null, undefined, "x", 5, [], [entry()], {}, { operation: 5 }]) {
    assert.throws(() => log.append(bad), /must be an object with an operation/, JSON.stringify(bad));
  }
  assert.deepEqual(log.files(), []);
});

test("audit: caller fields cannot replace v, ts, pid, prev or hash", (t) => {
  const clock = manualClock("2026-11-04T12:00:00.000Z");
  const log = new A.AuditLog(tempDir(t), "column", { clock });
  const line = log.append({ ...entry(), v: 9, ts: "1999-01-01T00:00:00.000Z", pid: 1, prev: "forged", hash: "forged" });
  assert.equal(line.ts, "2026-11-04T12:00:00.000Z", "a line cannot be backdated");
  assert.equal(line.v, 1);
  assert.equal(line.pid, process.pid);
  assert.equal(line.prev, "genesis:column:2026-11");
  assert.notEqual(line.hash, "forged");
  assert.equal(log.verifyAll()[0].ok, true);
});

test("audit: after a corrupt last line the chain stays broken where it broke", (t) => {
  const { log, file } = logWith(t, 2);
  appendFileSync(file, "{truncated\n");
  const next = log.append(entry({ operation: "after" }));
  assert.equal(next.prev, "sha256:" + createHash("sha256").update("{truncated").digest("hex"));
  assert.deepEqual(log.verify(file), { file, ok: false, lines: 4, brokenAt: 3, reason: "not JSON" });
  assert.deepEqual(log.read(["2026-11"]).map((l) => l.operation), ["op_0", "op_1", "after"], "read() skips the corrupt line");
});

test("audit: owner-only permissions", { skip: process.platform === "win32" }, (t) => {
  const dir = join(tempDir(t), "state", "column");
  const log = new A.AuditLog(dir, "column", { clock: manualClock() });
  log.append(entry());
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  assert.equal(statSync(log.fileFor("2026-11")).mode & 0o777, 0o600);
  assert.equal(existsSync(join(dir, "audit.lock")), false, "the lock is released");
});

test("audit: 6 processes appending at once keep one valid chain", async (t) => {
  const dir = tempDir(t);
  const code = `
    import { AuditLog } from ${JSON.stringify(dist("guard/audit.js"))};
    const log = new AuditLog(process.env.AUDIT_DIR, "column");
    for (let i = 0; i < 20; i++) {
      log.append({ server: "column", version: "t", guard: "t", session: "w" + process.env.WORKER, tool: "column_change",
        operation: "op_" + i, tier: "write", group: "change", mode: "sandbox", decision: "executed", dry_run: false });
    }
  `;
  await runWorkers(6, code, { AUDIT_DIR: dir });
  const checks = new A.AuditLog(dir, "column").verifyAll();
  assert.ok(checks.length >= 1 && checks.every((c) => c.ok), JSON.stringify(checks));
  assert.equal(
    checks.reduce((n, c) => n + c.lines, 0),
    120
  );
});
