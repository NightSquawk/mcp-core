// mcp-guard verify --watch: has any agent client's MCP, hook or permission config changed
// since the accepted baseline? The baseline and the report hold hashes and key names, never values.
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { cli, dist, fakeIo, sandbox, test } from "./cli-helpers.mjs";

const { diffPrints, parseBaseline, tomlKeys, watchTargets } = await import(dist("cli/watch.js"));

const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
const posixPerms = process.platform !== "win32";

/** A fake home, project and machine folder under one sandbox; the watch reads only these. */
function world(t) {
  const sb = sandbox(t);
  const home = join(sb.base, "home");
  const project = join(sb.base, "project");
  const machine = join(sb.base, "machine");
  mkdirSync(home, { recursive: true });
  mkdirSync(project, { recursive: true });
  const clientPaths = { claudeManaged: join(machine, "claude-code"), cursorHooks: join(machine, "cursor", "hooks.json"), codexAdmin: join(machine, "codex") };
  return {
    sb,
    home,
    project,
    machine,
    clientPaths,
    baseline: join(sb.stateDir, "_watch", "baseline.json"),
    write(path, content) {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, typeof content === "string" ? content : JSON.stringify(content, null, 2));
    },
    opts: (over = {}) => ({ env: sb.env, home, cwd: project, clientPaths, ...over }),
  };
}

const watch = (w, args = [], over = {}) => cli(["verify", "--watch", ...args, "--json"], w.opts(over));
const watchText = (w, args = [], over = {}) => cli(["verify", "--watch", ...args], w.opts(over));
const strip = (changes, w) => changes.map((c) => ({ ...c, file: c.file.slice(w.sb.base.length + 1) }));

function seed(w) {
  w.write(join(w.home, ".claude.json"), { numStartups: 5, mcpServers: { toy: { command: "node", env: { TOY_API_KEY: "secret-value-1" } } } });
  w.write(join(w.home, ".claude", "settings.json"), { model: "opus", permissions: { allow: ["Bash(ls)"] } });
  w.write(join(w.home, ".codex", "config.toml"), 'model = "gpt-5"\napproval_policy = "on-request"\n\n[mcp_servers.toy]\ncommand = "node"\n');
  w.write(join(w.project, ".mcp.json"), { mcpServers: { proj: { command: "proj-server", env: { PROJ_TOKEN: "secret-value-3" } } } });
}

test("the first run records a baseline of hashes; the next run finds no changes", async (t) => {
  const w = world(t);
  seed(w);
  const first = await watch(w);
  assert.equal(first.code, 0);
  assert.equal(first.json.recorded, true);
  assert.deepEqual(first.json.changes, []);
  assert.equal(first.json.baseline, w.baseline);
  assert.equal(first.json.files.length, 4);
  const stored = readFileSync(w.baseline, "utf8");
  for (const secret of ["secret-value-1", "secret-value-3", "TOY_API_KEY", "PROJ_TOKEN", "proj-server", "Bash(ls)"]) {
    assert.ok(!stored.includes(secret), `the baseline holds ${secret}`);
  }
  assert.ok(stored.includes('"mcpServers.toy"'), "key names are kept");
  if (posixPerms) {
    assert.equal(statSync(w.baseline).mode & 0o777, 0o600);
    assert.equal(statSync(dirname(w.baseline)).mode & 0o777, 0o700);
  }
  assert.ok(first.json.notes.some((n) => /anything running as you can rewrite it/.test(n)));

  const second = await watch(w);
  assert.equal(second.code, 0);
  assert.equal(second.json.recorded, false);
  assert.deepEqual(second.json.changes, []);
  const text = await watchText(w);
  assert.match(text.text, /^config watch: no changes since 2026-11-04T12:00:00\.000Z \(4 files, baseline .*\)\.$/);
});

test("changes are reported by file and key, never with a value", async (t) => {
  const w = world(t);
  seed(w);
  await watch(w);

  w.write(join(w.home, ".claude.json"), {
    numStartups: 6,
    mcpServers: { toy: { command: "node", env: { TOY_API_KEY: "secret-value-2" } }, evil: { command: "curl" } },
  });
  w.write(join(w.home, ".claude", "settings.json"), { model: "sonnet", permissions: { allow: ["Bash(ls)", "Bash(curl:*)"] } });
  w.write(join(w.home, ".codex", "config.toml"), 'model = "gpt-6"\napproval_policy = "on-request"\n\n[mcp_servers.toy]\ncommand = "node"\nargs = ["x"]\n\n[tui]\ntheme = "dark"\n');
  rmSync(join(w.project, ".mcp.json"));
  w.write(join(w.home, ".cursor", "mcp.json"), { mcpServers: { cur: { url: "https://example.invalid/mcp" } } });

  const r = await watch(w);
  assert.equal(r.code, 1);
  assert.equal(r.json.recorded, false);
  assert.deepEqual(strip(r.json.changes, w), [
    { file: "home/.claude.json", change: "added", key: "mcpServers.evil" },
    { file: "home/.claude.json", change: "changed", key: "mcpServers.toy" },
    { file: "home/.claude/settings.json", change: "changed", key: "permissions.allow", detail: "1 added, 0 removed" },
    { file: "home/.codex/config.toml", change: "changed", key: "[mcp_servers.toy]" },
    { file: "home/.cursor/mcp.json", change: "added", detail: "1 key" },
    { file: "project/.mcp.json", change: "removed" },
  ]);
  const text = await watchText(w);
  assert.equal(text.code, 1);
  for (const value of ["secret-value", "curl", "example.invalid", "gpt-6", "dark"]) {
    assert.ok(!text.text.includes(value) && !JSON.stringify(r.json).includes(value), `the report shows ${value}`);
  }
  assert.match(text.text, /^config watch: 6 changes since 2026-11-04T12:00:00\.000Z/);
  assert.match(text.text, /^ {4}changed {2}permissions\.allow: 1 added, 0 removed$/m);
  assert.match(text.text, /^ {4}removed {2}\(the file\)$/m);
  assert.match(text.text, /Then run mcp-guard verify --watch --accept to record the new state\.$/m);
  assert.equal((await watch(w)).json.changes.length, 6, "a check does not move the baseline");
});

test("--accept needs a person at a terminal, who types accept", async (t) => {
  const w = world(t);
  seed(w);
  await watch(w);
  w.write(join(w.project, ".mcp.json"), { mcpServers: {} });

  const agent = await watch(w, ["--accept"]);
  assert.equal(agent.code, 1);
  assert.match(agent.json.error, /asks a person to type "accept" at a terminal/);
  const wrong = await watch(w, ["--accept"], { interactive: true, answers: ["yes"] });
  assert.equal(wrong.code, 1);
  assert.match(wrong.json.error, /did not match/);
  assert.equal((await watch(w)).code, 1, "a refused accept records nothing");

  const person = await watch(w, ["--accept"], { interactive: true, answers: ["accept"] });
  assert.equal(person.code, 0);
  assert.equal(person.json.recorded, true);
  assert.match(person.asked[0], /removed {2}mcpServers\.proj/);
  assert.match(person.asked[0], /Record these as the new baseline\?/);
  assert.deepEqual((await watch(w)).json.changes, []);
  const nothing = await watchText(w, ["--accept"]);
  assert.equal(nothing.code, 0);
  assert.match(nothing.text, /Nothing to accept\.$/m);
});

test("a baseline that is gone or does not load is drift, not a first run", async (t) => {
  const w = world(t);
  seed(w);
  await watch(w);
  rmSync(w.baseline);
  const gone = await watch(w);
  assert.equal(gone.code, 1);
  assert.equal(gone.json.baseline_missing, true);
  assert.match((await watchText(w)).text, /is gone, but its folder is still there, so something removed it/);
  const back = await watch(w, ["--accept"], { interactive: true, answers: ["accept"] });
  assert.equal(back.code, 0);
  assert.equal(back.json.recorded, true);

  for (const [content, why] of [
    ["{", /not valid JSON/],
    [JSON.stringify({ mcp_guard_watch: 2, recorded_at: "x", files: {} }), /it is not an mcp-guard watch baseline/],
    [JSON.stringify({ mcp_guard_watch: 1, recorded_at: "x", files: { "/a": { kind: "nope" } } }), /its entry for \/a is malformed/],
    [JSON.stringify({ mcp_guard_watch: 1, recorded_at: "x", files: { "/a": { kind: "mcp", keys: { k: 1 } } } }), /its entry for \/a is malformed/],
  ]) {
    writeFileSync(w.baseline, content);
    const r = await watch(w);
    assert.equal(r.code, 1, content);
    assert.equal(r.json.baseline_corrupt, true);
    assert.match((await watchText(w)).text, why);
  }
  const fixed = await watch(w, ["--accept"], { interactive: true, answers: ["accept"] });
  assert.equal(fixed.code, 0);
  assert.deepEqual((await watch(w)).json.changes, []);
});

test("--baseline where you cannot write prints the admin commands; the default baseline fails instead", { skip: isRoot || !posixPerms }, async (t) => {
  const w = world(t);
  seed(w);
  const locked = join(w.sb.base, "locked");
  mkdirSync(locked);
  mkdirSync(w.sb.stateDir, { recursive: true });
  chmodSync(locked, 0o555);
  chmodSync(w.sb.stateDir, 0o555);
  try {
    const path = join(locked, "baseline.json");
    const r = await watch(w, ["--baseline", path]);
    assert.equal(r.code, 3);
    assert.equal(r.json.recorded, false);
    assert.ok(r.json.admin.commands.some((c) => c.startsWith(`sudo tee '${path}' > /dev/null <<'EOF'\n{`)));
    assert.ok(!r.json.notes.some((n) => /can rewrite it/.test(n)), "an admin-owned baseline needs no such note");

    const own = await watch(w);
    assert.equal(own.code, 1);
    assert.match(own.json.error, /Cannot write the baseline/);
  } finally {
    chmodSync(locked, 0o755);
    chmodSync(w.sb.stateDir, 0o755);
  }
});

test("an explicit --baseline is used as given, first run included", async (t) => {
  const w = world(t);
  seed(w);
  const path = join(w.sb.base, "admin", "baseline.json");
  assert.equal((await watch(w, ["--baseline", path])).json.recorded, true);
  w.write(join(w.home, ".mcp.json"), { mcpServers: { x: { command: "x" } } });
  const r = await watch(w, ["--baseline", path]);
  assert.equal(r.code, 1);
  assert.deepEqual(strip(r.json.changes, w), [{ file: "home/.mcp.json", change: "added", detail: "1 key" }]);
  assert.equal((await watch(w)).json.recorded, true, "the default baseline is separate");
});

test("--project adds a project's config; a missing one is a warning", async (t) => {
  const w = world(t);
  const other = join(w.sb.base, "other");
  w.write(join(other, ".claude", "settings.local.json"), { permissions: { allow: ["mcp__toy__toy_spend"] } });
  const r = await watch(w, ["--project", other, "--project", "nowhere"]);
  assert.ok(r.json.files.includes(join(other, ".claude", "settings.local.json")));
  assert.deepEqual(r.json.warnings, ["--project nowhere is not a folder."]);
  w.write(join(other, ".cursor", "hooks.json"), { version: 1, hooks: { beforeMCPExecution: [] } });
  const again = await watch(w, ["--project", other]);
  assert.deepEqual(strip(again.json.changes, w), [{ file: "other/.cursor/hooks.json", change: "added", detail: "1 key" }]);
});

test("what cannot change what runs is ignored, and defaults are not changes", async (t) => {
  const w = world(t);
  seed(w);
  await watch(w);
  const state = JSON.parse(readFileSync(join(w.home, ".claude.json"), "utf8"));
  state.numStartups = 99;
  state.lastCost = 1.5;
  state.projects = { "/work/x": { allowedTools: [], hasTrustDialogAccepted: false, mcpServers: {}, lastSessionId: "abc" } };
  w.write(join(w.home, ".claude.json"), state);
  w.write(join(w.home, ".claude", "settings.json"), { model: "haiku", theme: "dark", outputStyle: "x", permissions: { allow: ["Bash(ls)"] } });
  w.write(join(w.home, ".codex", "config.toml"), '# a comment\nmodel = "o9"\nmodel_reasoning_effort = "high"\napproval_policy = "on-request"\n\n[mcp_servers.toy]\n# why\ncommand = "node"\n\n[notice.hide]\nx = true\n');
  assert.deepEqual((await watch(w)).json.changes, []);

  state.projects["/work/x"].hasTrustDialogAccepted = true;
  w.write(join(w.home, ".claude.json"), state);
  assert.deepEqual(strip((await watch(w)).json.changes, w), [{ file: "home/.claude.json", change: "added", key: 'projects["/work/x"].hasTrustDialogAccepted' }]);
});

test("machine-wide files count, including a new managed-settings.d drop-in", async (t) => {
  const w = world(t);
  seed(w);
  w.write(join(w.clientPaths.codexAdmin, "requirements.toml"), 'allowed_approval_policies = ["on-request"]\n');
  const first = await watch(w);
  assert.ok(first.json.files.includes(join(w.clientPaths.codexAdmin, "requirements.toml")));
  w.write(join(w.clientPaths.claudeManaged, "managed-settings.d", "60-extra.json"), { permissions: { allow: ["mcp__toy__toy_spend"] }, disableAllHooks: true });
  w.write(join(w.clientPaths.codexAdmin, "requirements.toml"), 'allowed_approval_policies = ["on-request", "never"]\n');
  assert.deepEqual(strip((await watch(w)).json.changes, w), [
    { file: "machine/claude-code/managed-settings.d/60-extra.json", change: "added", detail: "2 keys" },
    { file: "machine/codex/requirements.toml", change: "changed", key: "allowed_approval_policies" },
  ]);
});

test("files that do not parse or cannot be read are reported, not skipped", async (t) => {
  const w = world(t);
  seed(w);
  await watch(w);
  const mcp = join(w.project, ".mcp.json");
  writeFileSync(mcp, "{ broken");
  assert.deepEqual(strip((await watch(w)).json.changes, w), [{ file: "project/.mcp.json", change: "changed", detail: "now not valid JSON" }]);
  await watch(w, ["--accept"], { interactive: true, answers: ["accept"] });
  writeFileSync(mcp, "{ still broken");
  assert.deepEqual(strip((await watch(w)).json.changes, w), [{ file: "project/.mcp.json", change: "changed", detail: "still not valid JSON, and its content changed" }]);
  await watch(w, ["--accept"], { interactive: true, answers: ["accept"] });
  writeFileSync(mcp, JSON.stringify({ mcpServers: { a: { command: "a" } } }));
  assert.deepEqual(strip((await watch(w)).json.changes, w), [{ file: "project/.mcp.json", change: "changed", detail: "readable again (was not valid JSON), 1 key" }]);

  if (!isRoot && posixPerms) {
    await watch(w, ["--accept"], { interactive: true, answers: ["accept"] });
    chmodSync(mcp, 0o000);
    try {
      assert.deepEqual(strip((await watch(w)).json.changes, w), [{ file: "project/.mcp.json", change: "changed", detail: "now unreadable (EACCES)" }]);
    } finally {
      chmodSync(mcp, 0o644);
    }
  }
});

test("__proto__ keys are counted like any other key", async (t) => {
  const w = world(t);
  w.write(join(w.home, ".claude.json"), '{"mcpServers": {"__proto__": {"command": "x"}}}');
  w.write(join(w.project, ".mcp.json"), "[1, 2]");
  await watch(w);
  assert.ok(readFileSync(w.baseline, "utf8").includes('"mcpServers.__proto__"'));
  assert.deepEqual((await watch(w)).json.changes, []);
  w.write(join(w.home, ".claude.json"), '{"mcpServers": {"__proto__": {"command": "y"}}}');
  w.write(join(w.project, ".mcp.json"), "[1, 2, 3]");
  assert.deepEqual(strip((await watch(w)).json.changes, w), [
    { file: "home/.claude.json", change: "changed", key: "mcpServers.__proto__" },
    { file: "project/.mcp.json", change: "changed", key: "(file)" },
  ]);
  assert.equal(Object.prototype.command, undefined);
});

test("usage: --watch takes no server and none of verify's own options", async (t) => {
  const w = world(t);
  const cases = [
    [["verify", "toy", "--watch"], /drop the server name/],
    [["verify", "--watch", "--strict"], /--watch does not take --strict/],
    [["verify", "--watch", "--file", "x", "--manifest", "y"], /--watch does not take --file, --manifest/],
    [["verify", "toy", "--project", "x"], /--project goes with --watch/],
    [["verify", "toy", "--baseline", "x", "--accept"], /--baseline, --accept go with --watch/],
  ];
  for (const [argv, why] of cases) {
    const r = await cli(argv, w.opts());
    assert.equal(r.code, 2, argv.join(" "));
    assert.match(r.errText, why, argv.join(" "));
  }
});

test("watchTargets: every client's files, for this user and machine", () => {
  const { io } = fakeIo({ home: "/home/tester", cwd: "/work/p", env: {} });
  const targets = new Map(watchTargets(io).map((x) => [x.path, x.kind]));
  for (const [path, kind] of [
    ["/home/tester/.claude.json", "state"],
    ["/home/tester/.mcp.json", "mcp"],
    ["/etc/claude-code/managed-settings.json", "settings"],
    ["/etc/claude-code/managed-mcp.json", "mcp"],
    ["/home/tester/.cursor/hooks.json", "hooks"],
    ["/home/tester/.cursor/permissions.json", "all"],
    ["/etc/cursor/hooks.json", "hooks"],
    ["/home/tester/.codex/config.toml", "toml"],
    ["/etc/codex/requirements.toml", "toml"],
    ["/etc/codex/managed_config.toml", "toml"],
    ["/home/tester/.config/Claude/claude_desktop_config.json", "mcp"],
    ["/work/p/.mcp.json", "mcp"],
    ["/work/p/.claude/settings.local.json", "settings"],
    ["/work/p/.codex/config.toml", "toml"],
  ]) {
    assert.equal(targets.get(path), kind, path);
  }
  const win = fakeIo({ platform: "win32", home: "C:\\Users\\tester", cwd: "C:\\work\\p", env: { APPDATA: "D:\\Roaming", ProgramData: "C:\\ProgramData", CODEX_HOME: "D:\\codex", CLAUDE_CONFIG_DIR: "D:\\claude-profile" } });
  const wt = new Map(watchTargets(win.io).map((x) => [x.path, x.kind]));
  for (const [path, kind] of [
    ["C:\\Program Files\\ClaudeCode\\managed-settings.json", "settings"],
    ["C:\\ProgramData\\Cursor\\hooks.json", "hooks"],
    ["C:\\ProgramData\\OpenAI\\Codex\\requirements.toml", "toml"],
    ["D:\\codex\\config.toml", "toml"],
    ["D:\\Roaming\\Claude\\claude_desktop_config.json", "mcp"],
    ["D:\\claude-profile\\settings.json", "settings"],
    ["C:\\work\\p\\.mcp.json", "mcp"],
  ]) {
    assert.equal(wt.get(path), kind, path);
  }
});

test("tomlKeys: one hash per top-level key and per table; comments, blank lines and ignored keys do not count", () => {
  const base = [
    "# header",
    'model = "a"',
    'approval_policy = "on-request"',
    "sandbox_permissions = [",
    '  "disk-full-read-access",',
    "]",
    "",
    "[mcp_servers.toy]",
    'command = "node"',
    "[tui]",
    'theme = "x"',
    "[notice.hide]",
    "a = true",
    "[[profiles.list]]",
    "x = 1",
  ];
  const keys = tomlKeys(base.join("\n"));
  assert.deepEqual(Object.keys(keys).sort(), ["[mcp_servers.toy]", "[profiles.list]", "approval_policy", "sandbox_permissions"]);
  const edit = (from, to) => tomlKeys(base.map((l) => (l === from ? to : l)).join("\r\n"));
  assert.deepEqual(edit("# header", "# changed"), keys, "a comment and CRLF line ends change nothing");
  assert.deepEqual(edit('model = "a"', 'model = "b"'), keys);
  assert.deepEqual(edit('theme = "x"', 'theme = "y"'), keys);
  const d = diffPrints({ f: { kind: "toml", keys } }, { f: { kind: "toml", keys: edit('  "disk-full-read-access",', '  "network-full-access",') } });
  assert.deepEqual(d, [{ file: "f", change: "changed", key: "sandbox_permissions" }], "a value over several lines belongs to its key");
});

test("diffPrints counts list items, and parseBaseline keeps keys as data", () => {
  const before = { f: { kind: "settings", keys: { "permissions.allow": ["a", "b", "b"] } } };
  const after = { f: { kind: "settings", keys: { "permissions.allow": ["b", "c", "d"] } } };
  assert.deepEqual(diffPrints(before, after), [{ file: "f", change: "changed", key: "permissions.allow", detail: "2 added, 2 removed" }]);
  assert.deepEqual(diffPrints({}, { f: { kind: "mcp", keys: { "mcpServers.a": "h" } } }), [{ file: "f", change: "added", detail: "1 key" }]);
  assert.deepEqual(diffPrints({ f: { kind: "mcp", keys: {} } }, { f: { kind: "mcp", keys: { list: ["x", "y"] } } }), [{ file: "f", change: "added", key: "list", detail: "2 items" }]);
  const parsed = parseBaseline('{"mcp_guard_watch":1,"recorded_at":"t","files":{"/f":{"kind":"mcp","keys":{"__proto__":"h","constructor":"i"}}}}');
  assert.equal(Object.getPrototypeOf(parsed.files["/f"].keys), null);
  assert.deepEqual(Object.keys(parsed.files["/f"].keys), ["__proto__", "constructor"]);
  assert.throws(() => parseBaseline("[]"), /not an mcp-guard watch baseline/);
});
