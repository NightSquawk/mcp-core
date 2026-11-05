// mcp-guard harness: client rules from a guard manifest. It prints admin commands and
// fragments to merge, and writes nothing itself but harness-<client>.json under the test override.
import assert from "node:assert/strict";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { cli, dist, sandbox, tempDir, test } from "./cli-helpers.mjs";

const { buildManifest } = await import(dist("guard/manifest.js"));
const { canonicalJson, sha256Hex } = await import(dist("guard/canonical.js"));
const { adminFileCommands, commandLine, mergeCursorHooks } = await import(dist("cli/harness.js"));
const { claudeDesktopConfig, claudeManagedDir, codexAdminDir, codexHome, cursorEnterpriseHooks } = await import(dist("cli/clients.js"));
const { parseRules } = await import(dist("cli/rules.js"));

const SCRIPT = fileURLToPath(dist("cli/index.js"));
const OPS = [
  { operationId: "list_accounts", tier: "read" },
  { operationId: "create_note", tier: "write" },
  { operationId: "close_account", tier: "destructive" },
  { operationId: "create_transfer", tier: "spend", flags: { egress: true } },
];
const toy = (over = {}) => buildManifest({ server: "toy", version: "1.0.0", prefix: "toy", operations: OPS, ...over });
const rules = (r) => Object.fromEntries(r.json.tools.map((d) => [d.tool, d.rule]));
const file = (r, pattern) => r.json.files.find((f) => pattern.test(f.path));

function pkg(t, manifest = toy(), raw) {
  const dir = tempDir(t, "mcp-guard-harness-pkg-");
  mkdirSync(join(dir, "dist"), { recursive: true });
  writeFileSync(join(dir, "dist", "guard-manifest.json"), raw ?? JSON.stringify(manifest, null, 2));
  return dir;
}

/** Stand-ins for the machine-wide client folders, so a test can prove nothing was written there. */
function machine(t) {
  const dir = tempDir(t, "mcp-guard-harness-machine-");
  return { dir, clientPaths: { claudeManaged: join(dir, "claude-code"), cursorHooks: join(dir, "cursor", "hooks.json"), codexAdmin: join(dir, "codex") } };
}

async function harness(t, args, opts = {}) {
  const sb = opts.sb ?? sandbox(t);
  const m = opts.machine ?? machine(t);
  const dir = opts.pkg ?? pkg(t, opts.manifest);
  const json = opts.text ? [] : ["--json"];
  const r = await cli(["harness", ...args, "--package", dir, ...json], { env: opts.env ?? sb.env, clientPaths: m.clientPaths, ...opts.io });
  return { ...r, sb, m, dir };
}

test("claude: read runs, change asks, critical and spend are denied; the drop-in is an admin's to install", async (t) => {
  const r = await harness(t, ["toy", "--claude"]);
  assert.equal(r.code, 3);
  assert.equal(r.json.client, "claude");
  assert.deepEqual(r.json.names, ["toy"]);
  assert.deepEqual(rules(r), { toy_read: "allow", toy_change: "ask", toy_critical: "deny", toy_spend: "deny" });
  assert.equal(r.json.manifest.sha256, sha256Hex(canonicalJson(toy())));

  const dropIn = join(r.m.clientPaths.claudeManaged, "managed-settings.d", "50-mcp-guard-toy.json");
  assert.equal(r.json.files.length, 1);
  assert.deepEqual({ ...r.json.files[0], content: undefined }, { path: dropIn, scope: "admin", install: "write", format: "json", purpose: "permission rules for toy", content: undefined });
  assert.deepEqual(JSON.parse(r.json.files[0].content), {
    permissions: { allow: ["mcp__toy__toy_read"], ask: ["mcp__toy__toy_change"], deny: ["mcp__toy__toy_critical", "mcp__toy__toy_spend"] },
  });
  assert.equal(r.json.admin.shell, "sh");
  assert.deepEqual(r.json.admin.commands, [
    `sudo install -d -m 0755 -o 0 -g 0 '${join(r.m.clientPaths.claudeManaged, "managed-settings.d")}'`,
    `sudo tee '${dropIn}' > /dev/null <<'EOF'\n${r.json.files[0].content}EOF`,
    `sudo chown 0:0 '${dropIn}'`,
    `sudo chmod 0644 '${dropIn}'`,
  ]);
  assert.ok(r.json.notes.some((n) => /in bypassPermissions mode it runs without asking\. --hook denies/.test(n)));
  assert.ok(r.json.notes.some((n) => n === "Rules use the server's name in your MCP config. They assume it is toy; pass --name when it is not."));
  assert.deepEqual(r.json.warnings, []);
  assert.deepEqual(readdirSync(r.m.dir), [], "harness wrote into a client folder");
});

test("--allow-critical and --allow-spend make those groups ask instead of deny", async (t) => {
  const r = await harness(t, ["toy", "--claude", "--allow-critical", "--allow-spend"]);
  assert.deepEqual(rules(r), { toy_read: "allow", toy_change: "ask", toy_critical: "ask", toy_spend: "ask" });
  assert.equal(JSON.parse(r.json.files[0].content).permissions.deny, undefined);
  const text = await harness(t, ["toy", "--claude", "--allow-critical"], { text: true });
  assert.doesNotMatch(text.text, /--allow-critical makes critical ask/);
  assert.match(text.text, /--allow-spend makes spend ask/);
});

test("--name: one rule per client name, duplicates dropped, bad names refused", async (t) => {
  const r = await harness(t, ["toy", "--claude", "--name", "toy-dev", "--name", "toy-prod", "--name", "toy-dev"]);
  assert.deepEqual(r.json.names, ["toy-dev", "toy-prod"]);
  assert.deepEqual(JSON.parse(r.json.files[0].content).permissions.allow, ["mcp__toy-dev__toy_read", "mcp__toy-prod__toy_read"]);
  assert.ok(!r.json.notes.some((n) => /They assume it is toy/.test(n)));
  for (const bad of ["bad name", "-toy", "toy.dev", "", "x".repeat(65)]) {
    const b = await harness(t, ["toy", "--claude", `--name=${bad}`]);
    assert.equal(b.code, 2, `--name ${JSON.stringify(bad)}`);
  }
});

test("claude --hook: a PreToolUse hook that runs mcp-guard hook claude, and harness-claude.json in the test policy folder", async (t) => {
  const r = await harness(t, ["toy", "--claude", "--hook", "--name", "toy-dev", "--name", "toy-prod"]);
  assert.equal(r.code, 3, "the drop-in still needs an admin");
  const settings = JSON.parse(r.json.files[0].content);
  const [entry] = settings.hooks.PreToolUse;
  assert.equal(entry.matcher, "^mcp__(?:toy-dev|toy-prod)__.*");
  assert.deepEqual(entry.hooks, [{ type: "command", command: "/usr/bin/node", args: [SCRIPT, "hook", "claude", "toy"], timeout: 10, onFailure: "block" }]);
  const matcher = new RegExp(entry.matcher);
  assert.ok(matcher.test("mcp__toy-dev__toy_read") && matcher.test("mcp__toy-prod__anything"));
  assert.ok(!matcher.test("mcp__toy__toy_read") && !matcher.test("mcp__toy-devx__toy_read") && !matcher.test("Bash"));

  const rulesFile = join(r.sb.policyDir, "toy", "harness-claude.json");
  const f = file(r, /harness-claude\.json$/);
  assert.equal(f.path, rulesFile);
  assert.equal(f.install, "written");
  assert.deepEqual(readdirSync(join(r.sb.policyDir, "toy")), ["harness-claude.json"]);
  const written = parseRules(JSON.parse(readFileSync(rulesFile, "utf8")), "toy", "claude");
  assert.deepEqual(written.names, ["toy-dev", "toy-prod"]);
  assert.equal(written.manifest.sha256, r.json.manifest.sha256);
  assert.deepEqual({ ...written.tools }, { toy_read: { group: "read", rule: "allow" }, toy_change: { group: "change", rule: "ask" }, toy_critical: { group: "critical", rule: "deny" }, toy_spend: { group: "spend", rule: "deny" } });
  assert.deepEqual({ ...written.operations }, {
    list_accounts: { tool: "toy_read", group: "read" },
    create_note: { tool: "toy_change", group: "change" },
    close_account: { tool: "toy_critical", group: "critical" },
    create_transfer: { tool: "toy_spend", group: "spend", egress: true },
  });
  assert.deepEqual(written.taint, { from: [] }, "the taint check is on by default");
  assert.equal(settings.hooks.PostToolUse, undefined, "no toy operation returns outside text, and no --taint-from: nothing to mark");
  assert.ok(!r.json.admin.commands.some((c) => c.includes("harness-claude.json")), "the override file needs no admin");
  assert.ok(r.json.notes.some((n) => /v2\.1\.295 or later/.test(n)));
  assert.deepEqual(readdirSync(r.m.dir), []);
});

test("claude --hook: outside text in the manifest or --taint-from adds a PostToolUse hook that marks the session", async (t) => {
  const manifest = toy({ operations: [...OPS, { operationId: "list_messages", tier: "read", flags: { untrusted_output: true } }] });
  const r = await harness(t, ["toy", "--claude", "--hook", "--taint-from", "WebFetch", "--taint-from", "mcp__gmail", "--taint-from", "WebFetch", "--taint-from", "mcp__drive__read_file"], { manifest });
  assert.equal(r.code, 3);
  const settings = JSON.parse(r.json.files[0].content);
  const [entry] = settings.hooks.PostToolUse;
  assert.equal(entry.matcher, "^(?:mcp__(?:toy)__.*|WebFetch|mcp__gmail(?:__.*)?|mcp__drive__read_file(?:__.*)?)$");
  assert.deepEqual(entry.hooks, settings.hooks.PreToolUse[0].hooks, "the same command answers both events");
  const matcher = new RegExp(entry.matcher);
  for (const yes of ["mcp__toy__toy_read", "WebFetch", "mcp__gmail__search", "mcp__drive__read_file"]) assert.ok(matcher.test(yes), yes);
  for (const no of ["WebFetchX", "XWebFetch", "mcp__gmailx__search", "mcp__drive__list", "Bash", "mcp__toyx__toy_read"]) assert.ok(!matcher.test(no), no);

  const written = parseRules(JSON.parse(readFileSync(join(r.sb.policyDir, "toy", "harness-claude.json"), "utf8")), "toy", "claude");
  assert.deepEqual(written.taint, { from: ["WebFetch", "mcp__gmail", "mcp__drive__read_file"] }, "duplicates dropped, order kept");
  assert.deepEqual({ ...written.operations.list_messages }, { tool: "toy_read", group: "read", untrusted_output: true });
  assert.ok(r.json.notes.some((n) => n.startsWith("Cross-server taint (7.9): after a result with text from outside parties (1 toy operation and every result of WebFetch, mcp__gmail, mcp__drive__read_file), the PostToolUse hook marks the session in ")));
  assert.ok(r.json.notes.some((n) => /a call to toy that can send data out \(1 operation\) asks first, with the reason, or is denied when the toy policy sets taint\.egress_after_untrusted to deny\. A deny rule still wins\./.test(n)));
  assert.ok(!r.json.notes.some((n) => /Name them with --taint-from/.test(n)), "the hint is for runs without --taint-from");

  const plain = await harness(t, ["toy", "--claude", "--hook"]);
  assert.ok(plain.json.notes.some((n) => /no toy operation returns outside text, so toy marks no session; other servers' hooks can\./.test(n)));
  assert.ok(plain.json.notes.some((n) => /Name them with --taint-from: WebFetch, WebSearch, or mcp__<server>/.test(n)));
});

test("claude --hook --no-taint: no PostToolUse hook, and rules without the operations or taint data", async (t) => {
  const manifest = toy({ operations: [...OPS, { operationId: "list_messages", tier: "read", flags: { untrusted_output: true } }] });
  const r = await harness(t, ["toy", "--claude", "--hook", "--no-taint"], { manifest });
  assert.equal(r.code, 3);
  const settings = JSON.parse(r.json.files[0].content);
  assert.equal(settings.hooks.PostToolUse, undefined);
  assert.equal(settings.hooks.PreToolUse.length, 1);
  const raw = JSON.parse(readFileSync(join(r.sb.policyDir, "toy", "harness-claude.json"), "utf8"));
  assert.equal(raw.operations, undefined);
  assert.equal(raw.taint, undefined);
  assert.ok(r.json.notes.some((n) => n.startsWith("--no-taint: no cross-server taint check.")));
});

test("claude --hook without the override prints the commands that put harness-claude.json in the policy root", async (t) => {
  const r = await harness(t, ["toy", "--claude", "--hook"], { env: {} });
  assert.equal(r.code, 3);
  const f = file(r, /harness-claude\.json$/);
  assert.equal(f.path, "/etc/nightsquawk-mcp/toy/harness-claude.json");
  assert.equal(f.install, "write");
  assert.ok(r.json.admin.commands.includes(`sudo tee '/etc/nightsquawk-mcp/toy/harness-claude.json' > /dev/null <<'EOF'\n${f.content}EOF`));
  assert.ok(r.json.admin.commands.includes("sudo chmod 0644 '/etc/nightsquawk-mcp/toy/harness-claude.json'"));
});

test("claude --sandbox: deny rules, the shell sandbox, and bypass mode off", async (t) => {
  const r = await harness(t, [
    "toy",
    "--claude",
    "--sandbox",
    "--deny-read",
    "~/secrets/**",
    "--deny-read",
    "**/.env",
    "--deny-read",
    "~/keys/*.pem",
    "--deny-write",
    "//etc/app/**",
    "--deny-write",
    "**/release.json",
    "--allow-domain",
    "registry.npmjs.org",
    "--allow-domain",
    "*.github.com",
  ]);
  assert.equal(r.code, 3);
  const dir = join(r.m.clientPaths.claudeManaged, "managed-settings.d");
  const f = file(r, /45-mcp-guard-sandbox\.json$/);
  assert.equal(f.path, join(dir, "45-mcp-guard-sandbox.json"));
  const profile = JSON.parse(f.content);
  for (const rule of [
    "Read(~/.ssh/**)",
    "Read(~/secrets/**)",
    "Read(**/.env)",
    "Read(~/keys/*.pem)",
    "Edit(//etc/app/**)",
    "Edit(**/.mcp.json)",
    "Edit(~/.claude/settings.json)",
    // A **/ pattern stops at the folder Claude Code starts in, so the home-folder config is named by path.
    "Read(~/.mcp.json)",
    "Edit(~/.mcp.json)",
    "Read(**/.mcp.json)",
    "Read(**/.codex/config.toml)",
    "Read(**/.cursor/mcp.json)",
    // Only a **/ Read rule reaches shell commands, so the project hook files get one too.
    "Read(**/.claude/settings.json)",
    "Read(**/.claude/settings.local.json)",
    "Read(**/.codex/hooks.json)",
    "Read(**/.cursor/hooks.json)",
    "Edit(**/.cursor/hooks.json)",
    "Edit(**/release.json)",
  ]) {
    assert.ok(profile.permissions.deny.includes(rule), rule);
  }
  assert.equal(profile.permissions.disableBypassPermissionsMode, "disable");
  assert.deepEqual({ ...profile.sandbox, filesystem: undefined, network: undefined }, { enabled: true, failIfUnavailable: true, allowUnsandboxedCommands: false, filesystem: undefined, network: undefined });
  assert.ok(profile.sandbox.filesystem.denyRead.includes("~/secrets") && profile.sandbox.filesystem.denyRead.includes("~/.ssh"));
  assert.ok(profile.sandbox.filesystem.denyRead.includes("~/.mcp.json") && profile.sandbox.filesystem.denyWrite.includes("~/.mcp.json"));
  assert.ok(![...profile.sandbox.filesystem.denyRead, ...profile.sandbox.filesystem.denyWrite].some((p) => /[*?[\]]/.test(p)), "the sandbox lists hold plain paths");
  assert.ok(profile.sandbox.filesystem.denyWrite.includes("/etc/app"));
  assert.ok(profile.permissions.deny.includes(`Edit(/${r.sb.stateDir}/**)`), "the guard's state folder: ledger, audit log, taint markers");
  assert.ok(profile.sandbox.filesystem.denyWrite.includes(r.sb.stateDir));
  assert.ok(r.json.notes.some((n) => n.includes(`The guard's state folder (/${r.sb.stateDir}/**) is in the Edit and denyWrite lists`)));
  assert.deepEqual(profile.sandbox.network, { allowedDomains: ["registry.npmjs.org", "*.github.com"], allowManagedDomainsOnly: true });
  assert.equal(r.json.admin.commands.filter((c) => c === `sudo install -d -m 0755 -o 0 -g 0 '${dir}'`).length, 1, "one folder, created once");
  const anyDepthReads = r.json.notes.find((n) => n.startsWith("These **/ patterns match only under the folder Claude Code starts in"));
  assert.ok(anyDepthReads && ["**/.env", "**/.mcp.json", "**/.cursor/hooks.json"].every((p) => anyDepthReads.includes(p)), anyDepthReads);
  assert.ok(!anyDepthReads.includes("~/keys/*.pem") && !anyDepthReads.includes("**/release.json"), anyDepthReads);
  const anyDepthEdits = r.json.notes.find((n) => n.startsWith("These **/ Edit patterns cover Claude's file tools only"));
  assert.ok(anyDepthEdits && anyDepthEdits.endsWith(": **/release.json."), anyDepthEdits);
  const wildcards = r.json.notes.find((n) => n.startsWith("The sandbox lists hold plain paths"));
  assert.ok(wildcards && wildcards.endsWith(": ~/keys/*.pem."), wildcards);
  assert.ok(r.json.notes.some((n) => /can reach only registry\.npmjs\.org, \*\.github\.com/.test(n)));

  assert.ok(r.json.notes.some((n) => /45-mcp-guard-sandbox\.json is one file for the whole machine: a later harness --sandbox run for any server replaces it/.test(n)));
  assert.ok(r.json.notes.some((n) => /does not write managed-mcp\.json\. .* It is the only way to pin env; --mcp-command pins the command and args\./.test(n)));
  assert.equal(profile.allowedMcpServers, undefined, "the allowlist goes in each server's drop-in, not the shared profile");

  const quiet = await harness(t, ["toy", "--claude", "--sandbox"]);
  assert.deepEqual(JSON.parse(file(quiet, /sandbox/).content).sandbox.network.allowedDomains, []);
  assert.ok(quiet.json.notes.some((n) => /get no network/.test(n)));
});

test("claude --mcp-command: the server's launch commands go into its own drop-in, with the managed-only lock", async (t) => {
  const r = await harness(t, ["toy", "--claude", "--mcp-command", '["node","/opt/toy/dist/index.js"]', "--mcp-command", '[ "node", "/opt/toy/dist/index.js" ]', "--mcp-command", '["/usr/local/bin/toy-mcp","--stdio"]']);
  assert.equal(r.code, 3);
  const settings = JSON.parse(r.json.files[0].content);
  assert.match(r.json.files[0].path, /50-mcp-guard-toy\.json$/);
  assert.deepEqual(settings.allowedMcpServers, [{ serverCommand: ["node", "/opt/toy/dist/index.js"] }, { serverCommand: ["/usr/local/bin/toy-mcp", "--stdio"] }], "duplicates dropped");
  assert.equal(settings.allowManagedMcpServersOnly, true);
  assert.deepEqual(Object.keys(settings.permissions), ["allow", "ask", "deny"], "the permission rules are still there");
  assert.ok(r.json.notes.some((n) => n.startsWith("allowedMcpServers: Claude Code starts a stdio MCP server only when its command and args match one of these 2 entries exactly, in order.")));
  assert.ok(r.json.notes.some((n) => /Remote servers, plugin servers and claude\.ai connectors are blocked as well unless a serverUrl entry admits them/.test(n)));
  assert.ok(r.json.notes.some((n) => /The env block is not compared: .*NODE_OPTIONS.* Only managed-mcp\.json pins env\./.test(n)));
  assert.ok(r.json.notes.some((n) => /^allowManagedMcpServersOnly: allowlists in user, project and local settings are ignored/.test(n)));
  assert.deepEqual(r.json.warnings, []);

  const one = await harness(t, ["toy", "--claude", "--hook", "--sandbox", "--mcp-command", '["${HOME}/bin/toy-mcp"]']);
  assert.deepEqual(JSON.parse(one.json.files[0].content).allowedMcpServers, [{ serverCommand: ["${HOME}/bin/toy-mcp"] }]);
  assert.ok(one.json.notes.some((n) => /args match this entry exactly, in order\./.test(n)));
  assert.deepEqual(one.json.warnings, ['--mcp-command ["${HOME}/bin/toy-mcp"]: ${VAR} expands from the environment Claude Code starts with, so the entry can mean another path under another environment. Use literal paths for entries you rely on.']);

  const none = await harness(t, ["toy", "--claude"]);
  assert.equal(JSON.parse(none.json.files[0].content).allowedMcpServers, undefined, "no --mcp-command, no allowlist");
});

test("--sandbox refuses patterns Claude would read differently, and hosts that are not domains", async (t) => {
  const cases = [
    ["--deny-read", "/etc/x"],
    ["--deny-read", "secrets"],
    ["--deny-read", "~"],
    ["--deny-write", "~/a(b)"],
    ["--deny-write", "~/a\nb"],
    ["--allow-domain", "https://example.com"],
    ["--allow-domain", "localhost"],
    ["--allow-domain", "a..b.com"],
  ];
  for (const [option, value] of cases) {
    const r = await harness(t, ["toy", "--claude", "--sandbox", option, value]);
    assert.equal(r.code, 2, `${option} ${JSON.stringify(value)}`);
  }
});

test("codex: a config.toml fragment and the requirements.toml floor; nothing for an admin to run", async (t) => {
  const r = await harness(t, ["toy", "--codex"]);
  assert.equal(r.code, 0);
  assert.equal(r.json.admin, undefined);
  const [config, floor] = r.json.files;
  assert.deepEqual([config.path, config.scope, config.install, config.format], ["/home/tester/.codex/config.toml", "user", "merge", "toml"]);
  assert.deepEqual([floor.path, floor.scope, floor.install], [join(r.m.clientPaths.codexAdmin, "requirements.toml"), "admin", "merge"]);
  const body = config.content.split("\n").filter((l) => !l.startsWith("#"));
  assert.deepEqual(body, [
    "",
    "[mcp_servers.toy]",
    'default_tools_approval_mode = "prompt"',
    'enabled_tools = ["toy_read", "toy_change"]',
    'disabled_tools = ["toy_critical", "toy_spend"]',
    "",
    "[mcp_servers.toy.tools.toy_read]",
    'approval_mode = "approve"',
    "",
    "[mcp_servers.toy.tools.toy_change]",
    'approval_mode = "prompt"',
    "",
  ]);
  assert.match(floor.content, /^allowed_sandbox_modes = \["read-only", "workspace-write"\]$/m);
  assert.match(floor.content, /^allowed_approvals_reviewers = \["user"\]$/m);
  // "never" refuses MCP tools that ask, and codex exec runs with it, so the floor keeps it.
  assert.doesNotMatch(floor.content, /allowed_approval_policies/);
  assert.deepEqual(readdirSync(r.m.dir), []);

  const open = await harness(t, ["toy", "--codex", "--allow-critical", "--allow-spend"], { env: { ...sandbox(t).env, CODEX_HOME: "/opt/codex-home" } });
  assert.equal(open.json.files[0].path, "/opt/codex-home/config.toml");
  assert.match(open.json.files[0].content, /^enabled_tools = \["toy_read", "toy_change", "toy_critical", "toy_spend"\]$/m);
  assert.doesNotMatch(open.json.files[0].content, /disabled_tools/);
  assert.match(open.json.files[0].content, /\[mcp_servers\.toy\.tools\.toy_spend\]\napproval_mode = "prompt"/);

  const text = await harness(t, ["toy", "--codex"], { text: true });
  assert.match(text.text, /^Merge into your \/home\/tester\/\.codex\/config\.toml:$/m);
  assert.match(text.text, /^An admin merges into .*requirements\.toml:$/m);
});

test("cursor: harness-cursor.json, a new hooks.json and the read allowlist", async (t) => {
  const r = await harness(t, ["toy", "--cursor"]);
  assert.equal(r.code, 3);
  const command = commandLine("linux", ["/usr/bin/node", SCRIPT, "hook", "cursor"]);
  assert.equal(file(r, /harness-cursor\.json$/).install, "written");
  const cursorRules = parseRules(JSON.parse(file(r, /harness-cursor\.json$/).content), "toy", "cursor");
  assert.equal(cursorRules.operations, undefined, "the taint check is Claude-only for now");
  const hooks = file(r, /hooks\.json$/);
  assert.deepEqual([hooks.path, hooks.scope, hooks.install], [r.m.clientPaths.cursorHooks, "admin", "write"]);
  assert.deepEqual(JSON.parse(hooks.content), { version: 1, hooks: { beforeMCPExecution: [{ command, timeout: 10, failClosed: true }] } });
  assert.ok(r.json.admin.commands.includes(`sudo tee '${r.m.clientPaths.cursorHooks}' > /dev/null <<'EOF'\n${hooks.content}EOF`));
  const allow = file(r, /permissions\.json$/);
  assert.deepEqual([allow.path, allow.scope, allow.install], ["/home/tester/.cursor/permissions.json", "user", "merge"]);
  assert.deepEqual(JSON.parse(allow.content), { mcpAllowlist: ["toy:toy_read"] });
  assert.deepEqual(r.json.test, [`printf '%s' '{"mcp_server_name":"toy","tool_name":"toy_critical","tool_input":"{}"}' | ${command}`]);
  assert.ok(r.json.notes.some((n) => /For a server without rules the hook answers ask/.test(n)));
  assert.deepEqual(readdirSync(r.m.dir), [], "harness wrote into a client folder");

  const others = await harness(t, ["toy", "--cursor", "--others", "allow"]);
  assert.equal(JSON.parse(file(others, /hooks\.json$/).content).hooks.beforeMCPExecution[0].command, `${command} --others allow`);
  assert.ok(others.json.notes.some((n) => /For a server without rules the hook answers allow\./.test(n)));
});

test("cursor: an existing hooks.json keeps everything else; a current entry needs no command", async (t) => {
  const m = machine(t);
  mkdirSync(join(m.dir, "cursor"));
  const original = `${JSON.stringify({ version: 1, hooks: { beforeMCPExecution: [{ command: "/opt/audit/log.sh", timeout: 5 }], afterFileEdit: [{ command: "fmt" }] }, note: "kept" }, null, 2)}\n`;
  writeFileSync(m.clientPaths.cursorHooks, original);
  const sb = sandbox(t);

  const r = await harness(t, ["toy", "--cursor"], { machine: m, sb });
  const hooks = file(r, /hooks\.json$/);
  assert.equal(hooks.install, "write");
  assert.match(hooks.purpose, /with the mcp-guard hook added/);
  const merged = JSON.parse(hooks.content);
  assert.equal(merged.note, "kept");
  assert.deepEqual(merged.hooks.afterFileEdit, [{ command: "fmt" }]);
  assert.equal(merged.hooks.beforeMCPExecution.length, 2);
  assert.equal(merged.hooks.beforeMCPExecution[0].command, "/opt/audit/log.sh");
  assert.equal(readFileSync(m.clientPaths.cursorHooks, "utf8"), original, "harness changed hooks.json");

  writeFileSync(m.clientPaths.cursorHooks, hooks.content); // what the admin commands install
  const again = await harness(t, ["toy", "--cursor"], { machine: m, sb });
  assert.equal(again.code, 0, "harness-cursor.json is written under the override and hooks.json is current: nothing for an admin");
  assert.equal(file(again, /hooks\.json$/).install, "none");
  assert.equal(again.json.admin, undefined);
});

test("cursor: an older mcp-guard entry is replaced, not kept beside the new one", async (t) => {
  const m = machine(t);
  mkdirSync(join(m.dir, "cursor"));
  const stale = { command: "/old/node /old/mcp-guard/dist/cli/index.js hook cursor", timeout: 10, failClosed: true };
  writeFileSync(m.clientPaths.cursorHooks, JSON.stringify({ version: 1, hooks: { beforeMCPExecution: [stale, { command: "/opt/x.sh" }, stale] } }));
  const r = await harness(t, ["toy", "--cursor"], { machine: m });
  const hooks = file(r, /hooks\.json$/);
  assert.match(hooks.purpose, /with the mcp-guard hook updated/);
  const list = JSON.parse(hooks.content).hooks.beforeMCPExecution;
  assert.deepEqual(list.map((e) => e.command), [commandLine("linux", ["/usr/bin/node", SCRIPT, "hook", "cursor"]), "/opt/x.sh"]);
});

test("cursor: a broken hooks.json stops the run; one mcp-guard cannot read becomes an entry to merge", async (t) => {
  for (const [content, why] of [
    ["{ not json", /is not valid JSON/],
    ["[]", /is not a JSON object/],
    ['{"hooks": []}', /hooks is not an object/],
    ['{"hooks": {"beforeMCPExecution": {}}}', /hooks\.beforeMCPExecution is not a list/],
  ]) {
    const m = machine(t);
    mkdirSync(join(m.dir, "cursor"));
    writeFileSync(m.clientPaths.cursorHooks, content);
    const r = await harness(t, ["toy", "--cursor"], { machine: m });
    assert.equal(r.code, 1, content);
    assert.match(r.json.error, why);
  }
  const m = machine(t);
  mkdirSync(m.clientPaths.cursorHooks, { recursive: true }); // a folder: readable as nothing
  const r = await harness(t, ["toy", "--cursor"], { machine: m });
  const hooks = file(r, /hooks\.json$/);
  assert.deepEqual([hooks.scope, hooks.install], ["admin", "merge"]);
  assert.match(hooks.purpose, /cannot read the file/);
  assert.equal(JSON.parse(hooks.content).failClosed, true);
});

test("mergeCursorHooks", () => {
  const entry = { command: "/usr/bin/node /opt/mcp-guard/dist/cli/index.js hook cursor", timeout: 10, failClosed: true };
  const listOf = (text) => JSON.parse(text).hooks.beforeMCPExecution;
  assert.equal(mergeCursorHooks(null, entry).status, "new");
  assert.equal(mergeCursorHooks(" \n", entry).status, "new");
  const fresh = mergeCursorHooks(null, entry).text;
  assert.deepEqual(JSON.parse(fresh), { version: 1, hooks: { beforeMCPExecution: [entry] } });
  assert.equal(mergeCursorHooks(`\uFEFF${fresh}`, entry).status, "present", "a byte-order mark is not an error");
  assert.equal(mergeCursorHooks(JSON.stringify({ version: 1, hooks: { beforeMCPExecution: [entry, entry] } }), entry).status, "replaced");
  assert.equal(listOf(mergeCursorHooks(JSON.stringify({ hooks: { beforeMCPExecution: [entry, entry] } }), entry).text).length, 1);
  assert.equal(JSON.parse(mergeCursorHooks(JSON.stringify({ version: 2, hooks: {} }), entry).text).version, 2, "a version that is there is kept");
  const near = { command: "/opt/tool hook cursorx" };
  const added = mergeCursorHooks(JSON.stringify({ hooks: { beforeMCPExecution: [near] } }), entry);
  assert.equal(added.status, "added");
  assert.deepEqual(listOf(added.text), [near, entry]);
  assert.throws(() => mergeCursorHooks("null", entry), /not a JSON object/);
});

test("commandLine quotes what a shell would split, and refuses what it cannot quote", () => {
  assert.equal(commandLine("linux", ["/usr/bin/node", "/opt/mcp-guard/index.js", "hook", "cursor"]), "/usr/bin/node /opt/mcp-guard/index.js hook cursor");
  assert.equal(commandLine("linux", ["/opt/My Tools/node", "it's"]), "'/opt/My Tools/node' 'it'\\''s'");
  assert.equal(commandLine("linux", ["/opt/$HOME/x"]), "'/opt/$HOME/x'");
  assert.equal(commandLine("win32", ["C:\\Program Files\\nodejs\\node.exe", "C:\\mcp\\index.js", "hook"]), '"C:\\Program Files\\nodejs\\node.exe" C:\\mcp\\index.js hook');
  assert.equal(commandLine("win32", ["C:\\a&b\\node.exe"]), '"C:\\a&b\\node.exe"');
  assert.throws(() => commandLine("win32", ['C:\\a"b']), /holds " or %/);
  assert.throws(() => commandLine("win32", ["C:\\%TEMP%\\x"]), /holds " or %/);
  assert.throws(() => commandLine("linux", ["/opt/a\nb"]), /control character/);
  assert.throws(() => commandLine("linux", ["/opt/a\u2028b"]), /line separator/);
});

test("usage errors exit 2", async (t) => {
  const cases = [
    [["toy"], /Pick one client/],
    [["toy", "--claude", "--codex"], /Pick one client/],
    [["--claude"], /needs a server name/],
    [["Toy!", "--claude"], /Invalid server name/],
    [["toy", "--codex", "--hook"], /--hook is for --claude/],
    [["toy", "--cursor", "--hook"], /--hook is for --claude/],
    [["toy", "--cursor", "--sandbox"], /--sandbox is for --claude/],
    [["toy", "--claude", "--deny-read", "~/x/**"], /go with --sandbox/],
    [["toy", "--claude", "--allow-domain", "example.com"], /go with --sandbox/],
    [["toy", "--claude", "--others", "ask"], /--others is for --cursor/],
    [["toy", "--cursor", "--others", "deny"], /--others is ask or allow/],
    [["toy", "--claude", "--hook-script", "/opt/x.js"], /--hook-script goes with/],
    [["toy", "--codex", "--hook-script", "/opt/x.js"], /--hook-script goes with/],
    [["toy", "--claude", "--taint-from", "WebFetch"], /--no-taint and --taint-from go with --claude --hook/],
    [["toy", "--claude", "--no-taint"], /--no-taint and --taint-from go with --claude --hook/],
    [["toy", "--cursor", "--taint-from", "WebFetch"], /Claude-only for now/],
    [["toy", "--codex", "--no-taint"], /Claude-only for now/],
    [["toy", "--claude", "--hook", "--no-taint", "--taint-from", "WebFetch"], /pick one/],
    [["toy", "--claude", "--hook", "--taint-from", "gmail"], /--taint-from "gmail": write mcp__<server> for all of a server's tools/],
    [["toy", "--claude", "--hook", "--taint-from", "mcp__"], /--taint-from "mcp__"/],
    [["toy", "--claude", "--hook", "--taint-from", "mcp__a b"], /--taint-from "mcp__a b"/],
    [["toy", "--claude", "--hook", "--taint-from", "mcp__(a|b)"], /--taint-from "mcp__\(a\|b\)"/],
    [["toy", "--claude", "--hook", "--taint-from", "Web.*"], /--taint-from "Web\.\*"/],
    [["toy", "--codex", "--mcp-command", '["node","x.js"]'], /--mcp-command is for --claude/],
    [["toy", "--cursor", "--mcp-command", '["node","x.js"]'], /--mcp-command is for --claude/],
    ...["node x.js", "[]", '[""]', '["  "]', "[1]", '["node", 2]', '{"command":"node"}', '["a\\nb"]', '["a\\u0000"]', JSON.stringify(["x".repeat(4097)]), JSON.stringify(Array(65).fill("a"))].map((v) => [
      ["toy", "--claude", "--mcp-command", v],
      /--mcp-command .*: write the command and args as your MCP config gives them, as a JSON list of strings/,
    ]),
  ];
  for (const [args, why] of cases) {
    const r = await harness(t, args);
    assert.equal(r.code, 2, args.join(" "));
    assert.match(r.json.error, why, args.join(" "));
  }
  const both = await cli(["harness", "toy", "--claude", "--manifest", "a.json", "--package", "b", "--json"], { env: sandbox(t).env });
  assert.equal(both.code, 2);
});

test("a manifest that is missing, broken, failing or for another server is refused", async (t) => {
  const other = await harness(t, ["toy", "--claude"], { manifest: buildManifest({ server: "other", version: "1.0.0", prefix: "other", operations: OPS }) });
  assert.equal(other.code, 1);
  assert.match(other.json.error, /is for other, not toy/);

  const edited = toy();
  edited.tools.find((x) => x.name === "toy_change").annotations.readOnlyHint = true;
  const failing = await harness(t, ["toy", "--claude"], { manifest: edited });
  assert.equal(failing.code, 1);
  assert.match(failing.json.error, /fails the manifest check/);
  assert.ok(failing.json.issues.some((i) => i.level === "fail" && /readOnlyHint/.test(i.message)));

  const broken = await harness(t, ["toy", "--claude"], { pkg: pkg(t, null, "{ nope") });
  assert.equal(broken.code, 1);
  assert.match(broken.json.error, /is not valid JSON/);

  const empty = tempDir(t, "mcp-guard-harness-empty-");
  const missing = await harness(t, ["toy", "--claude"], { pkg: empty });
  assert.equal(missing.code, 1);
  assert.match(missing.json.error, /Cannot read .*guard-manifest\.json/);

  const here = await cli(["harness", "toy", "--claude", "--json"], { env: sandbox(t).env, cwd: empty, clientPaths: machine(t).clientPaths });
  assert.equal(here.code, 1, "the default ./dist/guard-manifest.json must exist too");
  assert.match(here.json.error, /Cannot read .*dist.guard-manifest\.json/);

  const viaFile = await cli(["harness", "toy", "--claude", "--json", "--manifest", join(pkg(t), "dist", "guard-manifest.json")], { env: sandbox(t).env, clientPaths: machine(t).clientPaths });
  assert.equal(viaFile.code, 3);
});

test("warnings: root, a hook script that is missing, and Node or the script under home", async (t) => {
  const root = await harness(t, ["toy", "--claude"], { io: { uid: 0 } });
  assert.ok(root.json.warnings.some((w) => /running as root/.test(w)));

  const missing = await harness(t, ["toy", "--claude", "--hook", "--hook-script", "/opt/nowhere/index.js"]);
  assert.ok(missing.json.warnings.some((w) => w === "/opt/nowhere/index.js does not exist, so the hook fails and blocks every call to these servers until it does."));
  assert.deepEqual(JSON.parse(missing.json.files[0].content).hooks.PreToolUse[0].hooks[0].args[0], "/opt/nowhere/index.js");

  const home = await harness(t, ["toy", "--cursor", "--hook-script", "/home/tester/mcp/dist/cli/index.js"], { io: { execPath: "/home/tester/.nvm/node" } });
  const underHome = home.json.warnings.filter((w) => /under your home folder/.test(w));
  assert.equal(underHome.length, 2);
  assert.match(underHome[0], /runs Node from \/home\/tester\/\.nvm\/node/);
  assert.match(underHome[1], /runs mcp-guard from \/home\/tester\/mcp\/dist\/cli\/index\.js/);

  const unattended = await harness(t, ["toy", "--claude"], { manifest: toy({ unattended: { critical: true } }) });
  assert.equal(unattended.code, 3, "a manifest warning does not stop the run");
  assert.ok(unattended.json.warnings.some((w) => /^manifest tools\[\d\] toy_critical: /.test(w)));
});

test("warnings (POSIX): a file the hook runs that someone other than root can change, as written and through links", async (t) => {
  const dir = (uid = 0, mode = 0o40755) => ({ isFile: false, isDirectory: true, isSymbolicLink: false, uid, mode });
  const file = (uid = 0, mode = 0o100644) => ({ isFile: true, isDirectory: false, isSymbolicLink: false, uid, mode });
  const link = { isFile: false, isDirectory: false, isSymbolicLink: true, uid: 1000, mode: 0o120777 };
  const tree = {
    "/": dir(),
    "/usr": dir(),
    "/usr/bin": dir(),
    "/usr/bin/node": file(0, 0o100755),
    "/usr/local": dir(),
    "/usr/local/bin": dir(),
    "/usr/local/bin/guard.js": link,
    "/opt": dir(),
    "/opt/root": dir(),
    "/opt/root/index.js": file(),
    "/opt/root/link.js": link,
    "/opt/mine": dir(1000),
    "/opt/mine/index.js": file(1000),
    "/opt/mine/node": file(1000, 0o100755),
    "/opt/shared": dir(0, 0o40775),
    "/opt/shared/index.js": file(),
    "/opt/root/hop.js": link,
    "/opt/mine/hop.js": link,
    "/tmp": dir(0, 0o41777),
    "/tmp/index.js": file(),
    "/tmp/mine.js": link,
    "/tmp/root.js": { ...link, uid: 0 },
  };
  const links = {
    "/opt/root/link.js": "/opt/root/index.js",
    "/usr/local/bin/guard.js": "/opt/mine/index.js",
    "/opt/root/hop.js": "../mine/hop.js",
    "/opt/mine/hop.js": "/opt/root/index.js",
    "/tmp/mine.js": "/opt/root/index.js",
    "/tmp/root.js": "/opt/root/index.js",
  };
  const pathProbes = { lstat: (p) => tree[p] ?? null, readlink: (p) => links[p] ?? null };
  const owned = async (script, execPath = "/usr/bin/node") => {
    const r = await harness(t, ["toy", "--claude", "--hook", "--hook-script", script], { io: { pathProbes, execPath } });
    return r.json.warnings.filter((w) => /may be able to change what the hook does/.test(w));
  };

  for (const ok of ["/opt/root/index.js", "/opt/root/link.js", "/tmp/index.js", "/tmp/root.js"]) assert.deepEqual(await owned(ok), [], ok);
  assert.deepEqual(await owned("/opt/mine/index.js"), [
    "The hook runs mcp-guard from /opt/mine/index.js, but /opt/mine/index.js is owned by uid 1000, not root, so the agent's user may be able to change what the hook does. Install Node and mcp-guard where only an admin can write, then pass --hook-script <that dist/cli/index.js>.",
  ]);
  assert.match((await owned("/opt/shared/index.js"))[0], /, but \/opt\/shared is writable by its group or others \(mode 775\), so /);
  assert.match((await owned("/usr/local/bin/guard.js"))[0], /^The hook runs mcp-guard from \/usr\/local\/bin\/guard\.js, but \/opt\/mine\/index\.js is owned by uid 1000/, "a link is judged by its target");
  assert.match((await owned("/opt/root/hop.js"))[0], /, but \/opt\/mine is owned by uid 1000, not root, so /, "every hop of a chain of links is checked");
  assert.match((await owned("/tmp/mine.js"))[0], /, but \/tmp\/mine\.js is a symlink owned by uid 1000 in a folder others can write, so /, "in a sticky folder the link's owner can replace it");
  assert.match((await owned("/opt/root/index.js", "/opt/mine/node"))[0], /^The hook runs Node from \/opt\/mine\/node, but \/opt\/mine\/node is owned by uid 1000, not root/);
  assert.deepEqual(await owned("/opt/nowhere/index.js"), [], "a missing script has its own warning, not this one");

  // The real file system: a script in a temp folder belongs to whoever runs the tests.
  if (typeof process.getuid === "function" && process.getuid() !== 0) {
    const script = join(tempDir(t, "mcp-guard-hook-script-"), "index.js");
    writeFileSync(script, "");
    const real = await harness(t, ["toy", "--claude", "--hook", "--hook-script", script], { io: { pathProbes: null } });
    assert.ok(real.json.warnings.some((w) => w.includes(`but ${script} is owned by uid ${process.getuid()}, not root`)), JSON.stringify(real.json.warnings));
  }
});

test("windows: PowerShell commands for an admin-owned file, and where each client keeps its config", () => {
  // The whole harness on win32 needs win32 paths it can read, so it runs on the Windows CI job (cli-windows.test.mjs).
  const text = '{\n  "permissions": {}\n}\n';
  const dropIn = "C:\\Program Files\\ClaudeCode\\managed-settings.d\\50-mcp-guard-toy.json";
  assert.deepEqual(adminFileCommands("win32", dropIn, text), [
    "New-Item -ItemType Directory -Force -Path 'C:\\Program Files\\ClaudeCode\\managed-settings.d' | Out-Null",
    `$content = @'\n${text}'@`,
    `[System.IO.File]::WriteAllText('${dropIn}', $content)`,
    `icacls '${dropIn}' /setowner '*S-1-5-32-544' /C`,
    `icacls '${dropIn}' /reset /C`,
    `icacls '${dropIn}' /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' '*S-1-5-32-545:RX'`,
  ]);
  assert.deepEqual(adminFileCommands("linux", "/etc/cursor/hooks.json", text), [
    "sudo install -d -m 0755 -o 0 -g 0 '/etc/cursor'",
    `sudo tee '/etc/cursor/hooks.json' > /dev/null <<'EOF'\n${text}EOF`,
    "sudo chown 0:0 '/etc/cursor/hooks.json'",
    "sudo chmod 0644 '/etc/cursor/hooks.json'",
  ]);
  assert.throws(() => adminFileCommands("win32", "C:\\a\nb.json", text), /control character/);

  assert.equal(claudeManagedDir("win32"), "C:\\Program Files\\ClaudeCode");
  assert.equal(claudeManagedDir("darwin"), "/Library/Application Support/ClaudeCode");
  assert.equal(claudeManagedDir("linux"), "/etc/claude-code");
  assert.equal(cursorEnterpriseHooks("win32", { ProgramData: "D:\\PD" }), "D:\\PD\\Cursor\\hooks.json");
  assert.equal(cursorEnterpriseHooks("win32", { ProgramData: "relative" }), "C:\\ProgramData\\Cursor\\hooks.json", "a ProgramData that is not a drive path is not trusted");
  assert.equal(cursorEnterpriseHooks("darwin", {}), "/Library/Application Support/Cursor/hooks.json");
  assert.equal(codexAdminDir("win32", {}), "C:\\ProgramData\\OpenAI\\Codex");
  assert.equal(codexAdminDir("darwin", {}), "/etc/codex");
  const io = (platform, home, env = {}) => ({ platform, home, env });
  assert.equal(codexHome(io("win32", "C:\\Users\\t")), "C:\\Users\\t\\.codex");
  assert.equal(codexHome(io("linux", "/home/t", { CODEX_HOME: "/opt/codex" })), "/opt/codex");
  assert.equal(claudeDesktopConfig(io("win32", "C:\\Users\\t")), "C:\\Users\\t\\AppData\\Roaming\\Claude\\claude_desktop_config.json");
  assert.equal(claudeDesktopConfig(io("win32", "C:\\Users\\t", { APPDATA: "E:\\Roam" })), "E:\\Roam\\Claude\\claude_desktop_config.json");
  assert.equal(claudeDesktopConfig(io("darwin", "/Users/t")), "/Users/t/Library/Application Support/Claude/claude_desktop_config.json");
  assert.equal(claudeDesktopConfig(io("linux", "/home/t", { XDG_CONFIG_HOME: "/x" })), "/x/Claude/claude_desktop_config.json");
});

test("text output: the decision table, the file list, unindented heredocs and the notes", async (t) => {
  const r = await harness(t, ["toy", "--claude", "--hook"], { text: true });
  assert.equal(r.code, 3);
  assert.match(r.text, /^toy: Claude Code rules from .*guard-manifest\.json \(toy 1\.0\.0, guard /);
  assert.match(r.text, /^ {2}tool {10}group {5}rule$/m);
  assert.match(r.text, /^ {2}toy_read {6}read {6}allow$/m);
  assert.match(r.text, /^ {2}toy_critical {2}critical {2}deny$/m);
  assert.match(r.text, /^ {2}admin {2}write {4}\S+50-mcp-guard-toy\.json: permission rules for toy$/m);
  assert.match(r.text, /^ {2}admin {2}written {2}\S+harness-claude\.json: /m);
  assert.ok(r.out.includes("EOF"), "a heredoc terminator must start its line");
  const notes = r.out.indexOf("notes:");
  assert.ok(notes > 0 && r.out[notes - 1] === "", "a blank line before the notes");
  assert.equal(r.err.length, 0);
});
