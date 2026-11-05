#!/usr/bin/env node
/**
 * Cross-platform test runner: `node --test` with an explicit file list, because
 * shell globs differ between bash, cmd and PowerShell and between Node versions.
 * Extra arguments (e.g. --experimental-test-coverage, --test-reporter=spec) pass
 * through; a bare word filters test files by name.
 */
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = fileURLToPath(new URL("../test/", import.meta.url));
const flags = process.argv.slice(2).filter((a) => a.startsWith("-"));
const filters = process.argv.slice(2).filter((a) => !a.startsWith("-"));
const files = readdirSync(dir)
  .filter((f) => f.endsWith(".test.mjs"))
  .filter((f) => filters.length === 0 || filters.some((x) => f.includes(x)))
  .sort()
  .map((f) => join(dir, f));
if (files.length === 0) {
  console.error(`run-tests: no test files in ${dir}${filters.length ? ` matching ${filters.join(", ")}` : ""}`);
  process.exit(1);
}
const r = spawnSync(process.execPath, ["--test", ...flags, ...files], { stdio: "inherit" });
process.exit(r.status ?? 1);
