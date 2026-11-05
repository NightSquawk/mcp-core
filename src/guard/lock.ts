/**
 * A small cross-process file lock (O_EXCL create) for read-modify-write of the
 * state files. Every agent session runs its own server process, so the audit log,
 * ledger and idempotency store are shared between processes.
 *
 * The lock file names its holder. A lock is taken from its holder only when the
 * holder is gone: its process has exited, or the file is a leftover of this process.
 * A holder that is alive but paused (a debugger, a suspended laptop) keeps its lock,
 * however old the lock is, and each holder removes only its own lock file.
 */
import { randomBytes } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync, writeSync } from "node:fs";
import { hostname } from "node:os";
import { dirname } from "node:path";

const sleeper = new Int32Array(new SharedArrayBuffer(4));
function sleepSync(ms: number): void {
  Atomics.wait(sleeper, 0, 0, ms);
}

export class LockTimeoutError extends Error {
  override name = "LockTimeoutError";
}

export interface LockOptions {
  /** How long to wait for the lock. Default 5 s. */
  timeoutMs?: number;
  /** A lock file that names no holder (a crash between creating and writing it) is taken once it is this old. Default 15 s. */
  staleMs?: number;
  /**
   * A lock whose holder cannot be shown to be gone is taken once it is this old and has not
   * changed for a second of watching. Its process number may have been reused by a new process
   * (Windows reuses them quickly), or it names another machine. A running holder keeps a lock
   * for milliseconds. Default 10 minutes.
   */
  abandonMs?: number;
}

interface Holder {
  pid: number;
  host: string;
  /** This copy of the module and which take: no two takes write the same text. */
  id: string;
  at: string;
}

interface Seen {
  text: string;
  holder: Holder | null;
}

const HOST = hostname();
/** This copy of the module: each worker thread, and each bundled copy, loads its own. */
const INSTANCE = randomBytes(8).toString("hex");
const STARTED = Date.now() - Math.round(process.uptime() * 1000);
/** An abandoned lock must be watched this long, over this many looks, before it is taken. */
const WATCH_MS = 1_000;
const WATCH_LOOKS = 10;
let takes = 0;
/** Locks this copy holds now. Takes are synchronous, so any other lock naming this copy is a leftover. */
const held = new Set<string>();

export function withFileLock<T>(lockPath: string, fn: () => T, opts: LockOptions = {}): T {
  if (held.has(lockPath)) throw new LockTimeoutError(`${lockPath} is already held by this process: a nested take would wait for itself.`);
  const timeoutMs = opts.timeoutMs ?? 5_000;
  const limits = { staleMs: opts.staleMs ?? 15_000, abandonMs: opts.abandonMs ?? 600_000 };
  mkdirSync(dirname(lockPath), { recursive: true });
  const deadline = Date.now() + timeoutMs;
  let mine = "";
  // Typed by assertion so that the loop does not narrow it to null.
  let watched = null as { text: string; since: number; looks: number } | null;
  let wait = 5;
  for (;;) {
    mine = holderText();
    const made = create(lockPath, mine);
    if (made === "taken") break;
    if (made === "exists") {
      const seen = readLock(lockPath);
      if (seen === "gone") continue; // removed between our create and our read: try again at once
      if (seen !== "busy") {
        watched = watched && watched.text === seen.text ? { ...watched, looks: watched.looks + 1 } : { text: seen.text, since: Date.now(), looks: 0 };
        const abandoned = watched.looks >= WATCH_LOOKS && Date.now() - watched.since >= WATCH_MS;
        if (takeable(lockPath, seen, limits, abandoned) && breakLock(lockPath, seen.text, limits)) continue;
      }
    }
    if (Date.now() > deadline) {
      // Windows refuses to create a file that another process is still deleting (EPERM). If that
      // lasts until the deadline, the EPERM is the answer.
      if (made instanceof Error) throw made;
      throw new LockTimeoutError(timeoutMessage(lockPath, watched ? parseHolder(watched.text) : null));
    }
    sleepSync(wait);
    wait = Math.min(wait * 2, 100);
  }
  held.add(lockPath);
  try {
    return fn();
  } finally {
    held.delete(lockPath);
    removeIfStill(lockPath, mine);
  }
}

function holderText(): string {
  const h: Holder = { pid: process.pid, host: HOST, id: `${INSTANCE}:${++takes}`, at: new Date().toISOString() };
  return `${JSON.stringify(h)}\n`;
}

function parseHolder(text: string): Holder | null {
  try {
    const h = JSON.parse(text) as Partial<Holder> | null;
    if (h && Number.isSafeInteger(h.pid) && (h.pid as number) > 0 && typeof h.host === "string" && typeof h.id === "string" && typeof h.at === "string") return h as Holder;
  } catch {
    // no holder named (an older format, or a crash before the write)
  }
  return null;
}

/** Create the lock file with its holder's name: "taken", "exists", or the error when Windows says it is busy. */
function create(path: string, text: string): "taken" | "exists" | Error {
  let fd: number;
  try {
    fd = openSync(path, "wx", 0o600);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "EEXIST") return "exists";
    // Windows refuses to create a file that another process is still deleting, and Node reports
    // that as EPERM: the lock is busy, not broken.
    if (code === "EPERM" && process.platform === "win32") return e as Error;
    throw e;
  }
  try {
    writeSync(fd, text);
  } catch (e) {
    closeSync(fd);
    rmSync(path, { force: true });
    throw e;
  }
  closeSync(fd);
  return "taken";
}

function readLock(path: string): Seen | "gone" | "busy" {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return "gone";
    if (code === "EPERM" && process.platform === "win32") return "busy"; // being deleted
    throw e;
  }
  return { text, holder: parseHolder(text) };
}

function ageOf(path: string): number {
  try {
    return Date.now() - statSync(path).mtimeMs;
  } catch {
    return 0;
  }
}

function running(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code !== "ESRCH"; // EPERM: running, as another user
  }
}

/** The holder is gone: its process has exited, or the lock is a leftover of this process. */
function holderGone(h: Holder): boolean {
  if (h.host !== HOST) return false; // another machine's processes cannot be checked from here
  if (h.pid !== process.pid) return !running(h.pid);
  // Our process number: this copy's own leftover (a release that could not remove the file), or
  // a previous process that had the same number (a container's pid 1, say). Another copy in this
  // process that holds it now is neither.
  return h.id.startsWith(`${INSTANCE}:`) || Date.parse(h.at) < STARTED - 2_000;
}

function takeable(path: string, seen: Seen, limits: { staleMs: number; abandonMs: number }, abandoned: boolean): boolean {
  if (!seen.holder) return ageOf(path) > limits.staleMs;
  return holderGone(seen.holder) || (abandoned && ageOf(path) > limits.abandonMs);
}

/**
 * Remove a gone holder's lock. This runs under a second lock, so that two waiters cannot both
 * remove it, the second one by then removing a new holder's lock. Returns true when the caller
 * should try to take the lock again at once.
 */
function breakLock(path: string, seenText: string, limits: { staleMs: number; abandonMs: number }): boolean {
  const breaker = `${path}.break`;
  const mine = holderText();
  const made = create(breaker, mine);
  if (made !== "taken") {
    if (made === "exists") {
      // Breaking takes microseconds: a breaker file whose holder is gone, or an old one, is left over from a crash.
      const b = readLock(breaker);
      if (b !== "gone" && b !== "busy" && (takeable(breaker, b, limits, false) || ageOf(breaker) > limits.abandonMs)) removeIfStill(breaker, b.text);
    }
    return false;
  }
  try {
    const now = readLock(path);
    if (now === "busy") return false;
    if (now !== "gone" && now.text === seenText) rmSync(path, { force: true, maxRetries: 3, retryDelay: 10 });
    return true;
  } finally {
    removeIfStill(breaker, mine);
  }
}

/** Remove a lock file only while it still holds `text`: nobody removes another holder's lock. */
function removeIfStill(path: string, text: string): void {
  try {
    if (readFileSync(path, "utf8") === text) rmSync(path, { force: true, maxRetries: 3, retryDelay: 10 });
  } catch {
    // Gone already, or it cannot be removed now: this copy's next take finds it as its own leftover.
  }
}

function timeoutMessage(path: string, h: Holder | null): string {
  if (!h) return `Timed out waiting for ${path}.`;
  return `Timed out waiting for ${path}, held by process ${h.pid} on ${h.host} since ${h.at}. If no MCP server is running as process ${h.pid} there, delete the file.`;
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
