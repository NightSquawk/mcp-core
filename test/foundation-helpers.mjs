// Shared helpers for the foundation-*.test.mjs files. Not a test file itself: it
// defines no tests, so the runner reports it as an empty pass when it scans test/.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** Absolute file URL of a built module, e.g. dist("guard/audit.js"). */
export function dist(rel) {
  return new URL(`../dist/${rel}`, import.meta.url).href;
}

/** A fresh temp folder, removed when the test ends. */
export function tempDir(t, prefix = "mcp-guard-test-") {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** A clock the test moves by hand. */
export function manualClock(iso = "2026-11-04T12:00:00.000Z") {
  let now = Date.parse(iso);
  const clock = () => new Date(now);
  clock.set = (v) => {
    now = typeof v === "number" ? v : Date.parse(v);
  };
  clock.advance = (ms) => {
    now += ms;
  };
  return clock;
}

/**
 * Run `count` copies of an ES module snippet in separate Node processes at the same
 * time. Each gets WORKER (its index) and the given env. Resolves with every stdout.
 */
export async function runWorkers(count, code, env = {}) {
  const runs = [];
  for (let i = 0; i < count; i++) {
    runs.push(
      new Promise((resolve, reject) => {
        const child = spawn(process.execPath, ["--input-type=module", "-e", code], {
          env: { ...process.env, ...env, WORKER: String(i) },
          stdio: ["ignore", "pipe", "pipe"],
        });
        let out = "";
        let err = "";
        child.stdout.on("data", (d) => (out += d));
        child.stderr.on("data", (d) => (err += d));
        child.on("error", reject);
        child.on("close", (status) => (status === 0 ? resolve(out) : reject(new Error(`worker ${i} exited ${status}: ${err}`))));
      })
    );
  }
  return Promise.all(runs);
}

/** Path of the repo root (for spawning the built CLI). */
export const repoRoot = fileURLToPath(new URL("..", import.meta.url));
