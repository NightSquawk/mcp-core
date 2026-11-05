// Shared helpers for the cli-*.test.mjs files. Not a test file itself.
// The CLI never touches process.*: every test drives run() with a fake CliIo.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test as nodeTest } from "node:test";
import { dist, manualClock, tempDir } from "./foundation-helpers.mjs";

const { run } = await import(dist("cli/run.js"));
const { staticProtection } = await import(dist("guard/protection.js"));

export { dist, manualClock, run, staticProtection, tempDir };

/**
 * node:test's test, skipped on a Windows host. The cli-*.test.mjs files drive the
 * CLI as a Linux host would (POSIX temp paths read through io.platform "linux",
 * sudo commands, file modes), and those paths do not resolve on Windows.
 * cli-windows.test.mjs runs the CLI there with real Windows paths instead.
 */
export function test(name, options, fn) {
  if (typeof options === "function") [options, fn] = [{}, options];
  if (process.platform === "win32") options = { ...options, skip: "a POSIX-host CLI test; cli-windows.test.mjs covers Windows" };
  return nodeTest(name, options, fn);
}

/**
 * A fake CliIo. `answers` are returned in order by ask(); each question is kept. An answer
 * that is a function is called with the question, and what it returns is the answer.
 * `protect` is true/false (a static report) or a function; omitted, the real
 * check runs (it never counts an NST_MCP_POLICY_DIR override as protected).
 */
const ROOT_OWNED = Object.freeze({
  lstat: () => ({ isFile: true, isDirectory: false, isSymbolicLink: false, uid: 0, mode: 0o100644 }),
  readlink: () => null,
});

export function fakeIo(opts = {}) {
  const out = [];
  const err = [];
  const asked = [];
  const answers = [...(opts.answers ?? [])];
  const io = {
    out: (line) => void out.push(...String(line).split("\n")),
    err: (line) => void err.push(...String(line).split("\n")),
    env: opts.env ?? {},
    platform: opts.platform ?? "linux",
    cwd: opts.cwd ?? process.cwd(),
    home: opts.home ?? "/home/tester",
    interactive: opts.interactive ?? false,
    ask: async (q) => {
      asked.push(q);
      if (!answers.length) throw new Error(`fakeIo: unexpected question: ${q}`);
      const a = answers.shift();
      return typeof a === "function" ? a(q) : a;
    },
    clock: opts.clock ?? manualClock(),
    uid: opts.uid === undefined ? 1000 : opts.uid,
    pid: 4242,
    readStdin: async () => {
      if (opts.stdin instanceof Error) throw opts.stdin;
      return opts.stdin ?? "";
    },
    execPath: opts.execPath ?? "/usr/bin/node",
  };
  if (opts.clientPaths) io.clientPaths = opts.clientPaths;
  // harness checks who owns the files a hook runs. By default every path looks root-owned,
  // so tests do not depend on who owns the checkout; pathProbes: null uses the real file system.
  if (opts.pathProbes !== null) io.pathProbes = opts.pathProbes ?? ROOT_OWNED;
  if (typeof opts.protect === "function") io.protect = opts.protect;
  else if (typeof opts.protect === "boolean") io.protect = (path) => staticProtection(opts.protect, path);
  return { io, out, err, asked, remaining: answers };
}

/** Run the CLI with a fake io. Returns { code, out, err, asked, json? }. */
export async function cli(argv, opts = {}) {
  const f = fakeIo(opts);
  const code = await run(argv, f.io);
  const result = { code, out: f.out, err: f.err, asked: f.asked, remaining: f.remaining, text: f.out.join("\n"), errText: f.err.join("\n") };
  if (argv.includes("--json")) result.json = JSON.parse(f.out.join("\n"));
  return result;
}

/**
 * A sandbox with NST_MCP_POLICY_DIR and NST_MCP_STATE_DIR under one temp folder.
 * policy(server, obj) writes <policy>/<server>/policy.json.
 */
export function sandbox(t, extraEnv = {}) {
  const base = tempDir(t, "mcp-guard-cli-");
  const policyDir = join(base, "policy");
  const stateDir = join(base, "state");
  const env = { NST_MCP_POLICY_DIR: policyDir, NST_MCP_STATE_DIR: stateDir, ...extraEnv };
  return {
    base,
    policyDir,
    stateDir,
    env,
    policyFile: (server) => join(policyDir, server, "policy.json"),
    serverState: (server) => join(stateDir, server),
    policy(server, obj) {
      mkdirSync(join(policyDir, server), { recursive: true });
      const file = join(policyDir, server, "policy.json");
      writeFileSync(file, typeof obj === "string" ? obj : JSON.stringify(obj, null, 2));
      return file;
    },
  };
}

/** A full policy that turns every group on and allows live mode. */
export function openPolicy(server) {
  return { version: 1, server, groups: { read: true, change: true, critical: true, spend: true }, environment: { allow_live: true } };
}

/**
 * The harness rules files hook reads, for both clients (or the ones named): four
 * tools, one per group. `over` replaces top-level keys; a string is written as is.
 */
export function writeRules(sb, server, over = {}, clients = ["claude", "cursor"]) {
  mkdirSync(join(sb.policyDir, server), { recursive: true });
  for (const client of clients) writeRulesFile(sb, server, client, over);
}

function writeRulesFile(sb, server, client, over) {
  const doc = {
    mcp_guard_harness: 1,
    client,
    server,
    names: [server],
    manifest: { version: "1.0.0", guard_version: "0.1.0", sha256: "a".repeat(64) },
    generated_at: "2026-11-04T12:00:00.000Z",
    tools: {
      [`${server}_read`]: { group: "read", rule: "allow" },
      [`${server}_change`]: { group: "change", rule: "ask" },
      [`${server}_critical`]: { group: "critical", rule: "deny" },
      [`${server}_spend`]: { group: "spend", rule: "deny" },
    },
    ...(typeof over === "string" ? {} : over),
  };
  writeFileSync(join(sb.policyDir, server, `harness-${client}.json`), typeof over === "string" ? over : JSON.stringify(doc, null, 2));
}
