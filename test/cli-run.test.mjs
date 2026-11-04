// mcp-guard argument parsing, exit codes, --json errors, and the real binary.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { cli, dist, sandbox, test } from "./cli-helpers.mjs";

const { GUARD_VERSION } = await import(dist("guard/version.js"));
const { COMMANDS } = await import(dist("cli/run.js"));
const bin = fileURLToPath(dist("cli/index.js"));

test("no command, help, -h and --help print the usage", async () => {
  for (const argv of [[], ["help"], ["-h"], ["--help"]]) {
    const r = await cli(argv);
    assert.equal(r.code, 0, argv.join(" "));
    for (const name of Object.keys(COMMANDS)) assert.match(r.text, new RegExp(`^  ${name}\\s`, "m"));
    assert.match(r.text, /Exit codes: 0 ok, 1 failed or refused, 2 usage error, 3 an admin has to run the printed commands/);
  }
});

test("--version prints the guard version", async () => {
  const r = await cli(["--version"]);
  assert.equal(r.code, 0);
  assert.equal(r.text, GUARD_VERSION);
});

test("unknown commands, including object keys, are usage errors", async () => {
  for (const name of ["bogus", "constructor", "__proto__", "toString", "hasOwnProperty"]) {
    const r = await cli([name]);
    assert.equal(r.code, 2, name);
    assert.match(r.errText, /unknown command/);
  }
});

test("unknown options and extra arguments are usage errors with the command's usage", async (t) => {
  const sb = sandbox(t);
  const opt = await cli(["status", "column", "--bogus"], { env: sb.env });
  assert.equal(opt.code, 2);
  assert.match(opt.errText, /usage: mcp-guard status/);
  const extra = await cli(["status", "a", "b"], { env: sb.env });
  assert.equal(extra.code, 2);
  assert.match(extra.errText, /unexpected argument "b"/);
  const manifest = await cli(["manifest", "x"], { env: sb.env });
  assert.equal(manifest.code, 2);
});

test("<command> --help prints that command's usage", async () => {
  const r = await cli(["kill", "--help"]);
  assert.equal(r.code, 0);
  assert.match(r.text, /^usage: mcp-guard kill <server>\|--all/);
});

test("--json errors go to stdout as JSON with the exit code; text errors go to stderr", async (t) => {
  const sb = sandbox(t);
  const j = await cli(["init", "--json"], { env: sb.env });
  assert.equal(j.code, 2);
  assert.equal(j.json.ok, false);
  assert.equal(j.json.code, 2);
  assert.match(j.json.error, /init needs a server name/);
  assert.equal(j.err.length, 0);

  const s = await cli(["init"], { env: sb.env });
  assert.equal(s.code, 2);
  assert.equal(s.out.length, 0);
  assert.match(s.errText, /^mcp-guard: init needs a server name/);
  assert.match(s.errText, /usage: mcp-guard init/);

  const ok = await cli(["status", "column", "--json"], { env: sb.env });
  assert.equal(ok.json.ok, true);
  assert.equal(ok.json.code, 0);
});

test("a refused confirmation in --json mode is a JSON error", async (t) => {
  const sb = sandbox(t);
  await cli(["kill", "column"], { env: sb.env });
  const r = await cli(["unkill", "column", "--json"], { env: sb.env });
  assert.equal(r.code, 1);
  assert.equal(r.json.ok, false);
  assert.match(r.json.error, /at a terminal/);
});

test("the built binary runs: shebang, --version, and status --json", async (t) => {
  assert.ok(readFileSync(bin, "utf8").startsWith("#!/usr/bin/env node\n"));
  const pkg = JSON.parse(readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"));
  assert.equal(pkg.bin["mcp-guard"], "dist/cli/index.js");

  const v = spawnSync(process.execPath, [bin, "--version"], { encoding: "utf8" });
  assert.equal(v.status, 0, v.stderr);
  assert.equal(v.stdout.trim(), GUARD_VERSION);

  const sb = sandbox(t);
  const s = spawnSync(process.execPath, [bin, "status", "column", "--json"], { encoding: "utf8", env: { ...process.env, ...sb.env }, stdio: ["ignore", "pipe", "pipe"] });
  assert.equal(s.status, 0, s.stderr);
  const json = JSON.parse(s.stdout);
  assert.equal(json.server, "column");
  assert.equal(json.policy.path, join(sb.policyDir, "column", "policy.json"));

  const bad = spawnSync(process.execPath, [bin, "nope"], { encoding: "utf8" });
  assert.equal(bad.status, 2);

  // No terminal on stdin: a confirmation is refused rather than read from the pipe.
  await cli(["kill", "column"], { env: sb.env });
  const u = spawnSync(process.execPath, [bin, "unkill", "column"], { encoding: "utf8", env: { ...process.env, ...sb.env }, input: "column\n" });
  assert.equal(u.status, 1);
  assert.match(u.stderr, /at a terminal/);
});
