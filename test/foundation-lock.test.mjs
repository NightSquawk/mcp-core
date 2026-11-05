import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { dist, runWorkers, tempDir } from "./foundation-helpers.mjs";

const L = await import(dist("guard/lock.js"));

/** A process number that was in use a moment ago and is not now. */
function exitedPid() {
  return spawnSync(process.execPath, ["-e", ""]).pid;
}

/** Lock file text naming a holder; by default the test runner, which is running. */
function holder(over = {}) {
  return `${JSON.stringify({ pid: process.ppid, host: hostname(), id: "another-copy:1", at: new Date().toISOString(), ...over })}\n`;
}

function backdate(file, ms) {
  const t = (Date.now() - ms) / 1000;
  utimesSync(file, t, t);
}

test("withFileLock: returns the callback's value, creates folders, removes the lock", (t) => {
  const dir = tempDir(t);
  const lock = join(dir, "deep", "er", "state.lock");
  assert.equal(
    L.withFileLock(lock, () => {
      assert.ok(existsSync(lock), "the lock file exists while held");
      return 42;
    }),
    42
  );
  assert.equal(existsSync(lock), false);
});

test("withFileLock: released when the callback throws", (t) => {
  const lock = join(tempDir(t), "x.lock");
  assert.throws(
    () =>
      L.withFileLock(lock, () => {
        throw new Error("boom");
      }),
    /boom/
  );
  assert.equal(existsSync(lock), false);
  assert.equal(L.withFileLock(lock, () => "again", { timeoutMs: 50 }), "again");
});

test("withFileLock: a held lock times out without running the callback", (t) => {
  const lock = join(tempDir(t), "held.lock");
  writeFileSync(lock, "999999 holder\n");
  let ran = false;
  const started = Date.now();
  assert.throws(
    () =>
      L.withFileLock(
        lock,
        () => {
          ran = true;
        },
        { timeoutMs: 100 }
      ),
    (e) => e instanceof L.LockTimeoutError && e.name === "LockTimeoutError"
  );
  assert.equal(ran, false);
  assert.ok(Date.now() - started >= 100);
  assert.ok(existsSync(lock), "someone else's lock is left alone");
});

test("withFileLock: not re-entrant, so a nested take fails at once instead of corrupting state", (t) => {
  const lock = join(tempDir(t), "n.lock");
  const started = Date.now();
  assert.throws(() => L.withFileLock(lock, () => L.withFileLock(lock, () => 1, { timeoutMs: 5_000 })), L.LockTimeoutError);
  assert.ok(Date.now() - started < 2_000, "it does not wait for itself");
  assert.equal(existsSync(lock), false);
});

test("withFileLock: an old lock that names no holder (crashed before writing it) is broken", (t) => {
  const lock = join(tempDir(t), "stale.lock");
  writeFileSync(lock, "4242 crashed\n");
  backdate(lock, 3_600_000);
  assert.equal(L.withFileLock(lock, () => "ran", { timeoutMs: 100, staleMs: 1_000 }), "ran");
  assert.equal(existsSync(lock), false);
});

test("withFileLock: a lock whose holder is still running is never taken, however old", (t) => {
  const lock = join(tempDir(t), "live.lock");
  const text = holder({ at: new Date(Date.now() - 3_600_000).toISOString() });
  writeFileSync(lock, text);
  backdate(lock, 3_600_000);
  assert.throws(
    () => L.withFileLock(lock, () => assert.fail("ran"), { timeoutMs: 150, staleMs: 1_000, abandonMs: 7_200_000 }),
    (e) => e instanceof L.LockTimeoutError && e.message.includes(`held by process ${process.ppid} on ${hostname()}`)
  );
  assert.equal(readFileSync(lock, "utf8"), text, "the holder's lock is left alone");
});

test("withFileLock: a lock whose holder has exited is taken at once, however new", (t) => {
  const lock = join(tempDir(t), "exited.lock");
  writeFileSync(lock, holder({ pid: exitedPid() }));
  assert.equal(L.withFileLock(lock, () => "ran", { timeoutMs: 100 }), "ran");
  assert.equal(existsSync(lock), false);
  assert.ok(!existsSync(`${lock}.break`));
});

test("withFileLock: a holder on another machine is not judged by its process number", (t) => {
  const lock = join(tempDir(t), "remote.lock");
  writeFileSync(lock, holder({ pid: exitedPid(), host: "another-machine.invalid" }));
  assert.throws(() => L.withFileLock(lock, () => assert.fail("ran"), { timeoutMs: 150 }), L.LockTimeoutError);
  assert.ok(existsSync(lock));
});

test("withFileLock: an abandoned lock (old, its number in use, not changing) is taken only after watching it", (t) => {
  const lock = join(tempDir(t), "abandoned.lock");
  writeFileSync(lock, holder());
  backdate(lock, 3_600_000);
  const started = Date.now();
  assert.equal(L.withFileLock(lock, () => "ran", { timeoutMs: 5_000, abandonMs: 60_000 }), "ran");
  assert.ok(Date.now() - started >= 1_000, "watched for a second first, so a holder resumed from a suspend can finish");
  assert.equal(existsSync(lock), false);
});

test("withFileLock: each holder removes only its own lock", (t) => {
  const lock = join(tempDir(t), "own.lock");
  const other = holder();
  // Another process takes the lock while this one holds it (an older version did, by age alone).
  L.withFileLock(lock, () => writeFileSync(lock, other));
  assert.equal(readFileSync(lock, "utf8"), other, "the other holder's lock stays");
});

test(
  "withFileLock: a lock this process could not remove is its own leftover, taken at its next take",
  { skip: process.platform === "win32" || process.getuid?.() === 0 ? "needs a folder this process cannot write" : false },
  (t) => {
    const dir = join(tempDir(t), "locks");
    mkdirSync(dir);
    const lock = join(dir, "left.lock");
    L.withFileLock(lock, () => chmodSync(dir, 0o500));
    chmodSync(dir, 0o700);
    assert.ok(existsSync(lock), "the release could not remove it, and did not throw");
    assert.equal(L.withFileLock(lock, () => "ran", { timeoutMs: 100 }), "ran");
    assert.equal(existsSync(lock), false);
  }
);

test("readJsonFile: fallback only for a missing file", (t) => {
  const dir = tempDir(t);
  const fallback = { n: 0 };
  assert.equal(L.readJsonFile(join(dir, "missing.json"), fallback), fallback);
  writeFileSync(join(dir, "ok.json"), '{"n":3}');
  assert.deepEqual(L.readJsonFile(join(dir, "ok.json"), fallback), { n: 3 });
  writeFileSync(join(dir, "bad.json"), '{"n":');
  assert.throws(() => L.readJsonFile(join(dir, "bad.json"), fallback), SyntaxError, "corrupt is an error, never the fallback");
  mkdirSync(join(dir, "adir"));
  assert.throws(() => L.readJsonFile(join(dir, "adir"), fallback), (e) => e.code === "EISDIR" || e.code === "EPERM");
});

test("writeJsonFile: complete file, no temp file left, owner-only mode", (t) => {
  const dir = tempDir(t);
  const file = join(dir, "sub", "state.json");
  L.writeJsonFile(file, { a: 1 });
  assert.equal(readFileSync(file, "utf8"), '{\n  "a": 1\n}\n');
  writeFileSync(join(dir, "loose.json"), "{}");
  if (process.platform !== "win32") chmodSync(join(dir, "loose.json"), 0o644);
  L.writeJsonFile(join(dir, "loose.json"), { b: 2 });
  assert.deepEqual(JSON.parse(readFileSync(join(dir, "loose.json"), "utf8")), { b: 2 });
  assert.deepEqual(readdirSync(join(dir, "sub")), ["state.json"]);
  assert.ok(!readdirSync(dir).some((f) => f.endsWith(".tmp")));
  if (process.platform !== "win32") {
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(statSync(join(dir, "loose.json")).mode & 0o777, 0o600, "rewriting tightens a loose file");
  }
});

test("withFileLock: read-modify-write from 8 processes loses no update", async (t) => {
  const file = join(tempDir(t), "counter.json");
  const code = `
    import { withFileLock, readJsonFile, writeJsonFile } from ${JSON.stringify(dist("guard/lock.js"))};
    const file = process.env.COUNTER_FILE;
    for (let i = 0; i < 25; i++) {
      withFileLock(file + ".lock", () => {
        const v = readJsonFile(file, { n: 0 });
        writeJsonFile(file, { n: v.n + 1 });
      });
    }
  `;
  await runWorkers(8, code, { COUNTER_FILE: file });
  assert.deepEqual(L.readJsonFile(file, null), { n: 200 });
  assert.equal(existsSync(`${file}.lock`), false);
});

test("withFileLock: 8 processes breaking one exited holder's lock lose no update", async (t) => {
  const file = join(tempDir(t), "counter.json");
  // Dated an hour back: a worker that is given the exited holder's number (Windows reuses them) sees it as a previous process's.
  writeFileSync(`${file}.lock`, holder({ pid: exitedPid(), at: new Date(Date.now() - 3_600_000).toISOString() }));
  const code = `
    import { withFileLock, readJsonFile, writeJsonFile } from ${JSON.stringify(dist("guard/lock.js"))};
    const file = process.env.COUNTER_FILE;
    for (let i = 0; i < 25; i++) {
      withFileLock(file + ".lock", () => {
        const v = readJsonFile(file, { n: 0 });
        writeJsonFile(file, { n: v.n + 1 });
      });
    }
  `;
  await runWorkers(8, code, { COUNTER_FILE: file });
  assert.deepEqual(L.readJsonFile(file, null), { n: 200 });
  assert.equal(existsSync(`${file}.lock`), false);
  assert.equal(existsSync(`${file}.lock.break`), false);
});
