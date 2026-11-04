/**
 * A small cross-process file lock (O_EXCL create) for read-modify-write of the
 * state files. Every agent session runs its own server process, so the audit log,
 * ledger and idempotency store are shared between processes.
 */
import { closeSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync, writeSync } from "node:fs";
import { dirname } from "node:path";

const sleeper = new Int32Array(new SharedArrayBuffer(4));
function sleepSync(ms: number): void {
  Atomics.wait(sleeper, 0, 0, ms);
}

export class LockTimeoutError extends Error {
  override name = "LockTimeoutError";
}

export function withFileLock<T>(lockPath: string, fn: () => T, opts: { timeoutMs?: number; staleMs?: number } = {}): T {
  const timeoutMs = opts.timeoutMs ?? 5_000;
  const staleMs = opts.staleMs ?? 15_000;
  mkdirSync(dirname(lockPath), { recursive: true });
  const deadline = Date.now() + timeoutMs;
  let fd: number | null = null;
  let wait = 5;
  while (fd === null) {
    try {
      fd = openSync(lockPath, "wx", 0o600);
      writeSync(fd, `${process.pid} ${new Date().toISOString()}\n`);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      try {
        const age = Date.now() - statSync(lockPath).mtimeMs;
        if (age > staleMs) {
          rmSync(lockPath, { force: true });
          continue;
        }
      } catch {
        continue; // removed between our open and stat: retry at once
      }
      if (Date.now() > deadline) throw new LockTimeoutError(`Timed out waiting for ${lockPath}.`);
      sleepSync(wait);
      wait = Math.min(wait * 2, 100);
    }
  }
  try {
    return fn();
  } finally {
    closeSync(fd);
    rmSync(lockPath, { force: true });
  }
}

/** Read a JSON file, or `fallback` when it does not exist. Throws on corrupt JSON. */
export function readJsonFile<T>(path: string, fallback: T): T {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return fallback;
    throw e;
  }
  return JSON.parse(text) as T;
}

/** Write a JSON file atomically (temp file + rename). */
export function writeJsonFile(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, path);
}
