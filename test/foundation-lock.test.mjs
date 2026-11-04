import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { dist, runWorkers, tempDir } from "./foundation-helpers.mjs";

const L = await import(dist("guard/lock.js"));

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

test("withFileLock: not re-entrant, so a nested take fails instead of corrupting state", (t) => {
  const lock = join(tempDir(t), "n.lock");
  assert.throws(() => L.withFileLock(lock, () => L.withFileLock(lock, () => 1, { timeoutMs: 50 })), L.LockTimeoutError);
  assert.equal(existsSync(lock), false);
});

test("withFileLock: a stale lock (crashed holder) is broken", (t) => {
  const lock = join(tempDir(t), "stale.lock");
  writeFileSync(lock, "4242 crashed\n");
  const past = (Date.now() - 3_600_000) / 1000;
  utimesSync(lock, past, past);
  assert.equal(L.withFileLock(lock, () => "ran", { timeoutMs: 100, staleMs: 1_000 }), "ran");
  assert.equal(existsSync(lock), false);
});

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
