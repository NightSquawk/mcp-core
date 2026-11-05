// mcp-guard hook: the permission hook harness installs. It reads the request on stdin
// and the admin-owned harness-<client>.json, and fails closed: anything it cannot read is
// a deny. As Claude's PostToolUse hook it marks sessions that read outside text (7.9).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { cli, dist, sandbox, tempDir, test, writeRules } from "./cli-helpers.mjs";

const { buildManifest } = await import(dist("guard/manifest.js"));
const { readAll, STDIN_LIMIT } = await import(dist("cli/io.js"));

const request = (stdin) => (typeof stdin === "string" || stdin instanceof Error ? stdin : JSON.stringify(stdin));
const hook = (sb, args, stdin, opts = {}) => cli(["hook", ...args], { env: sb.env, stdin: request(stdin), ...opts });

/** Claude's answer: null when the hook said nothing, else the decision and its reason. */
function claude(r) {
  assert.equal(r.code, 0, `exit ${r.code}: ${r.errText}`);
  if (!r.out.length) return null;
  assert.equal(r.out.length, 1);
  const { hookSpecificOutput: o } = JSON.parse(r.out[0]);
  assert.equal(o.hookEventName, "PreToolUse");
  return { decision: o.permissionDecision, reason: o.permissionDecisionReason };
}

function cursor(r) {
  assert.equal(r.code, 0, `exit ${r.code}: ${r.errText}`);
  assert.equal(r.out.length, 1);
  return JSON.parse(r.out[0]);
}

test("claude: a denied group's tool is denied, with a reason the agent is told to pass on", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy");
  for (const tool of ["toy_critical", "toy_spend"]) {
    const a = claude(await hook(sb, ["claude", "toy"], { tool_name: `mcp__toy__${tool}`, tool_input: {} }));
    assert.equal(a.decision, "deny");
    assert.match(a.reason, new RegExp(`^Blocked by mcp-guard: ${tool} is in the \\w+ group, which the harness rules for toy deny on this machine\\.`));
    assert.match(a.reason, /Tell the user; do not try another route to the same action\.$/);
  }
});

test("claude: allowed and asked tools get no answer, so the managed allow and ask rules decide", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy");
  assert.equal(claude(await hook(sb, ["claude", "toy"], { tool_name: "mcp__toy__toy_read" })), null);
  assert.equal(claude(await hook(sb, ["claude", "toy"], { tool_name: "mcp__toy__toy_change" })), null);
  assert.equal(claude(await hook(sb, ["claude", "toy"], `﻿${JSON.stringify({ tool_name: "mcp__toy__toy_read" })}`)), null, "a byte-order mark is not an error");
});

test("claude: a tool the manifest did not list is denied until harness runs again", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy");
  const a = claude(await hook(sb, ["claude", "toy"], { tool_name: "mcp__toy__toy_new" }));
  assert.equal(a.decision, "deny");
  assert.match(a.reason, /toy_new is not in the guard manifest that the toy rules were made from \(toy 1\.0\.0\)\. .* runs mcp-guard harness toy again\./);
});

test("claude: built-in tools and other servers' tools get no answer", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy");
  for (const tool_name of ["Bash", "Edit", "mcp__other__toy_spend", "mcp__toyx__toy_spend", "mcp__toy", "mcp_toy__toy_spend"]) {
    assert.equal(claude(await hook(sb, ["claude", "toy"], { tool_name })), null, tool_name);
  }
});

test("claude: __proto__, constructor and toString are tool names, not object members", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy");
  for (const tool of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
    assert.equal(claude(await hook(sb, ["claude", "toy"], { tool_name: `mcp__toy__${tool}` })).decision, "deny", tool);
  }
  const listed = sandbox(t);
  writeRules(listed, "toy", { tools: { ["__proto__"]: { group: "read", rule: "allow" }, toy_spend: { group: "spend", rule: "deny" } } });
  assert.equal(claude(await hook(listed, ["claude", "toy"], { tool_name: "mcp__toy____proto__" })), null, "a listed __proto__ tool is allowed");
  assert.equal(claude(await hook(listed, ["claude", "toy"], { tool_name: "mcp__toy__constructor" })).decision, "deny");
});

test("claude: the longest matching client name wins", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy", { names: ["toy", "toy__dev"] });
  // mcp__toy__dev__toy_read is toy__dev's toy_read (allowed), not toy's dev__toy_read (unknown, denied).
  assert.equal(claude(await hook(sb, ["claude", "toy"], { tool_name: "mcp__toy__dev__toy_read" })), null);
  assert.equal(claude(await hook(sb, ["claude", "toy"], { tool_name: "mcp__toy__dev__toy_spend" })).decision, "deny");
});

test("claude: mcp_server (Claude 2.1.274+) names the server, so a name holding __ is not guessed", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy", { names: ["toy", "toy__dev"] });
  const req = (tool_name, name) => ({ tool_name, mcp_server: { name, source: "user" } });
  assert.equal(claude(await hook(sb, ["claude", "toy"], req("mcp__toy__dev__toy_read", "toy__dev"))), null);
  const asToy = claude(await hook(sb, ["claude", "toy"], req("mcp__toy__dev__toy_read", "toy")));
  assert.equal(asToy.decision, "deny", "toy's tool dev__toy_read is not in the manifest");
  assert.match(asToy.reason, /dev__toy_read is not in the guard manifest/);
  assert.equal(claude(await hook(sb, ["claude", "toy"], req("mcp__toy__toy_spend", "elsewhere"))), null, "another server's tool, whatever its name looks like");
  assert.equal(claude(await hook(sb, ["claude", "toy"], req("mcp__other__toy_spend", "toy"))), null, "a name that does not start with the server's is not its tool");
  assert.equal(claude(await hook(sb, ["claude", "toy"], { tool_name: "mcp__toy__toy_spend", mcp_server: { source: "user" } })).decision, "deny", "no name: the longest match");
});

test("claude: missing or broken rules, and requests it cannot read, are denied", async (t) => {
  const none = sandbox(t);
  const missing = claude(await hook(none, ["claude", "toy"], { tool_name: "mcp__toy__toy_read" }));
  assert.equal(missing.decision, "deny");
  assert.match(missing.reason, /there are no harness rules for toy \(.*harness-claude\.json\)\. An admin runs mcp-guard harness toy --claude --hook\./);

  const broken = [
    ["{ nope", /is not valid JSON/],
    [{ server: "other" }, /it is for "other"/],
    [{ mcp_guard_harness: 2 }, /mcp_guard_harness must be 1/],
    [{ names: [] }, /names must be a list/],
    [{ names: ["bad name"] }, /names must be a list/],
    [{ manifest: { version: "1" } }, /manifest must say version, guard_version and sha256/],
    [{ tools: [] }, /tools must be an object/],
    [{ tools: { toy_read: { group: "read", rule: "maybe" } } }, /tools\.toy_read needs a group and a rule/],
    [{ tools: { toy_read: { group: "admin", rule: "allow" } } }, /tools\.toy_read needs a group and a rule/],
    [{ tools: { "bad tool": { group: "read", rule: "allow" } } }, /"bad tool" is not a tool name/],
    [{ extra: true }, /unknown keys extra/],
    [{ client: "cursor" }, /it is for client "cursor"/],
    [{ operations: [] }, /operations must be an object/],
    [{ operations: { x: { tool: "toy_read", group: "nope" } } }, /operations\.x needs a group and a tool/],
    [{ operations: { x: { tool: "bad tool", group: "read" } } }, /operations\.x needs a group and a tool/],
    [{ operations: { x: { tool: "toy_read", group: "read", egress: "yes" } } }, /operations\.x\.egress is true or left out/],
    [{ operations: { x: { tool: null, group: "read", note: 1 } } }, /operations\.x: unknown keys note/],
    [{ operations: { "a\nb": { tool: null, group: "read" } } }, /is not an operation id/],
    [{ taint: { from: [] } }, /taint needs operations/],
    [{ operations: {}, taint: { from: ["gmail"] } }, /taint must be \{ from: \[tool names\] \}/],
    [{ operations: {}, taint: { from: [], also: 1 } }, /taint must be/],
  ];
  for (const [over, why] of broken) {
    const sb = sandbox(t);
    writeRules(sb, "toy", over);
    const a = claude(await hook(sb, ["claude", "toy"], { tool_name: "mcp__toy__toy_read" }));
    assert.equal(a?.decision, "deny", JSON.stringify(over));
    assert.match(a.reason, /the harness rules for toy do not load: /);
    assert.match(a.reason, why);
  }

  const sb = sandbox(t);
  writeRules(sb, "toy");
  for (const [stdin, why] of [
    ["", /not valid JSON/],
    ["not json", /not valid JSON/],
    ["[]", /not a JSON object/],
    ["null", /not a JSON object/],
    [new Error("stdin is over 8388608 bytes"), /could not read the request on stdin \(stdin is over 8388608 bytes\)/],
    [{ tool_input: {} }, /the request has no tool_name/],
    [{ tool_name: 7 }, /the request has no tool_name/],
  ]) {
    const a = claude(await hook(sb, ["claude", "toy"], stdin));
    assert.equal(a?.decision, "deny", String(stdin));
    assert.match(a.reason, why);
  }
});

test("cursor: allow, ask or deny from the rules", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy");
  assert.deepEqual(cursor(await hook(sb, ["cursor", "toy"], { mcp_server_name: "toy", tool_name: "toy_read", tool_input: "{}" })), { permission: "allow" });
  assert.deepEqual(cursor(await hook(sb, ["cursor", "toy"], { mcp_server_name: "toy", tool_name: "MCP:toy_read" })), { permission: "allow" });
  assert.deepEqual(cursor(await hook(sb, ["cursor", "toy"], { mcp_server_name: "toy", tool_name: "toy_change" })), { permission: "ask" });
  const denied = cursor(await hook(sb, ["cursor", "toy"], { mcp_server_name: "toy", tool_name: "toy_spend" }));
  assert.equal(denied.permission, "deny");
  assert.match(denied.user_message, /^mcp-guard blocked this call: toy_spend is in the spend group/);
  assert.match(denied.agent_message, /^Blocked by mcp-guard: toy_spend is in the spend group/);
  assert.equal(cursor(await hook(sb, ["cursor", "toy"], { mcp_server_name: "toy", tool_name: "toy_new" })).permission, "deny");
  assert.equal(cursor(await hook(sb, ["cursor", "toy"], { mcp_server_name: "toy", tool_name: "__proto__" })).permission, "deny");
});

test("cursor: without a server it reads every server's rules; servers without rules get --others", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy");
  writeRules(sb, "bank", { names: ["bank-live"] });
  sb.policy("legacy", { version: 1, server: "legacy" }); // a server folder with no rules file
  assert.equal(cursor(await hook(sb, ["cursor"], { mcp_server_name: "bank-live", tool_name: "bank_spend" })).permission, "deny");
  assert.equal(cursor(await hook(sb, ["cursor"], { mcp_server_name: "toy", tool_name: "toy_read" })).permission, "allow");
  assert.equal(cursor(await hook(sb, ["cursor"], { mcp_server_name: "bank", tool_name: "bank_read" })).permission, "ask", "bank's client name is bank-live");
  assert.deepEqual(cursor(await hook(sb, ["cursor"], { mcp_server_name: "github", tool_name: "create_issue" })), { permission: "ask" });
  assert.deepEqual(cursor(await hook(sb, ["cursor", "--others", "allow"], { mcp_server_name: "github", tool_name: "create_issue" })), { permission: "allow" });
  assert.deepEqual(cursor(await hook(sb, ["cursor", "toy"], { mcp_server_name: "github", tool_name: "create_issue" })), { permission: "ask" }, "a named server covers its own names only");
  assert.deepEqual(cursor(await hook(sandbox(t), ["cursor"], { mcp_server_name: "github", tool_name: "x" })), { permission: "ask" }, "no rules anywhere");
});

test("cursor: rules that do not load, or a name two servers claim, block calls", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy");
  writeRules(sb, "bad", "{ nope");
  const blocked = cursor(await hook(sb, ["cursor"], { mcp_server_name: "github", tool_name: "x" }));
  assert.equal(blocked.permission, "deny");
  assert.match(blocked.agent_message, /the harness rules for bad do not load \(.*\), so every MCP call is blocked until an admin fixes them\./);

  const named = cursor(await hook(sandbox(t), ["cursor", "toy"], { mcp_server_name: "toy", tool_name: "toy_read" }));
  assert.equal(named.permission, "deny");
  assert.match(named.agent_message, /there are no harness rules for toy .* An admin runs mcp-guard harness toy --cursor\./);

  const clash = sandbox(t);
  writeRules(clash, "toy", { names: ["shared"] });
  writeRules(clash, "bank", { names: ["shared"] });
  const c = cursor(await hook(clash, ["cursor"], { mcp_server_name: "shared", tool_name: "toy_read" }));
  assert.equal(c.permission, "deny");
  assert.match(c.agent_message, /shared is named in the harness rules of bank and toy\. An admin gives each server its own name\./);
});

test("cursor: requests it cannot read are denied", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy");
  for (const [stdin, why] of [
    [{ tool_name: "toy_read" }, /does not name its MCP server/],
    [{ mcp_server_name: "", tool_name: "toy_read" }, /does not name its MCP server/],
    [{ mcp_server_name: "toy" }, /has no tool_name/],
    ["{", /not valid JSON/],
    [new Error("EPIPE"), /could not read the request on stdin \(EPIPE\)/],
  ]) {
    const a = cursor(await hook(sb, ["cursor"], stdin));
    assert.equal(a.permission, "deny", String(stdin));
    assert.match(a.user_message, why);
  }
});

test("usage errors exit 2, which both clients treat as a block", async (t) => {
  const sb = sandbox(t);
  const cases = [
    [[], /hook is mcp-guard hook claude <server>/],
    [["codex", "toy"], /hook is mcp-guard hook claude <server>/],
    [["claude"], /hook claude needs a server name/],
    [["claude", "Toy!"], /Invalid server name/],
    [["claude", "toy", "--others", "ask"], /--others is for hook cursor/],
    [["cursor", "Toy!"], /Invalid server name/],
    [["cursor", "--others", "deny"], /--others is ask or allow/],
    [["cursor", "toy", "extra"], /unexpected argument/],
  ];
  for (const [args, why] of cases) {
    const r = await hook(sb, args, "{}");
    assert.equal(r.code, 2, args.join(" "));
    assert.match(r.errText, why, args.join(" "));
  }
  const json = await hook(sb, ["claude", "toy", "--json"], "{}");
  assert.equal(json.code, 2);
  assert.match(json.json.error, /takes no --json/);
});

test("the real binary reads stdin and answers on stdout", async (t) => {
  const sb = sandbox(t);
  writeRules(sb, "toy");
  const run = (args, input) => spawnSync(process.execPath, [fileURLToPath(dist("cli/index.js")), "hook", ...args], { input, env: { ...process.env, ...sb.env }, encoding: "utf8" });
  const denied = run(["claude", "toy"], JSON.stringify({ tool_name: "mcp__toy__toy_spend", tool_input: {} }));
  assert.equal(denied.status, 0, denied.stderr);
  assert.equal(JSON.parse(denied.stdout).hookSpecificOutput.permissionDecision, "deny");
  const quiet = run(["claude", "toy"], JSON.stringify({ tool_name: "mcp__toy__toy_read" }));
  assert.equal(quiet.status, 0, quiet.stderr);
  assert.equal(quiet.stdout, "");
  const allowed = run(["cursor"], JSON.stringify({ mcp_server_name: "toy", tool_name: "toy_read", tool_input: "{}" }));
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.deepEqual(JSON.parse(allowed.stdout), { permission: "allow" });
  const empty = run(["cursor"], "");
  assert.equal(JSON.parse(empty.stdout).permission, "deny", "no request is a deny");
});

test("readAll joins chunks and refuses more than the limit", async () => {
  async function* chunks(...xs) {
    yield* xs;
  }
  assert.equal(await readAll(chunks("ab", Buffer.from("cd")), 4), "abcd");
  await assert.rejects(readAll(chunks("ab", "cde"), 4), /stdin is over 4 bytes/);
  assert.equal(STDIN_LIMIT, 8 * 1024 * 1024);
});

test("harness then hook: the rules harness writes are the rules the hook reads", async (t) => {
  const sb = sandbox(t);
  const dir = tempDir(t, "mcp-guard-hook-pkg-");
  const manifest = buildManifest({
    server: "toy",
    version: "2.0.0",
    prefix: "toy",
    operations: [
      { operationId: "list", tier: "read" },
      { operationId: "close", tier: "destructive" },
    ],
  });
  mkdirSync(join(dir, "dist"), { recursive: true });
  writeFileSync(join(dir, "dist", "guard-manifest.json"), JSON.stringify(manifest));
  const machine = tempDir(t, "mcp-guard-hook-machine-");
  const clientPaths = { claudeManaged: join(machine, "claude"), cursorHooks: join(machine, "cursor", "hooks.json"), codexAdmin: join(machine, "codex") };

  const made = await cli(["harness", "toy", "--claude", "--hook", "--package", dir, "--json"], { env: sb.env, clientPaths });
  assert.equal(made.code, 3);
  assert.equal(claude(await hook(sb, ["claude", "toy"], { tool_name: "mcp__toy__toy_read" })), null);
  assert.equal(claude(await hook(sb, ["claude", "toy"], { tool_name: "mcp__toy__toy_critical" })).decision, "deny");
  assert.match(claude(await hook(sb, ["claude", "toy"], { tool_name: "mcp__toy__toy_change" })).reason, /not in the guard manifest .* \(toy 2\.0\.0\)/, "the manifest has no change tool");

  const opened = await cli(["harness", "toy", "--cursor", "--allow-critical", "--package", dir, "--json"], { env: sb.env, clientPaths });
  assert.equal(opened.code, 3);
  assert.equal(cursor(await hook(sb, ["cursor"], { mcp_server_name: "toy", tool_name: "toy_critical" })).permission, "ask");
});
