// The CLI on a real Windows host. The other cli-*.test.mjs files drive it with
// POSIX paths and skip on Windows; this one reads and writes real win32 paths,
// runs the PowerShell that harness prints through Windows PowerShell, and asks
// the hook through the real binary, the way each client starts it. It also runs
// the guard's owner probe for real. It runs only on Windows (the Windows CI job).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, parse } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { cli, dist, openPolicy, tempDir } from "./cli-helpers.mjs";

const { buildManifest } = await import(dist("guard/manifest.js"));
const { commandLine } = await import(dist("cli/harness.js"));
const { realProbes, TRUSTED_OWNER_SIDS } = await import(dist("guard/protection.js"));
const { programDataDir } = await import(dist("guard/paths.js"));
const { starterPolicyText, windowsPolicyCommands } = await import(dist("cli/init.js"));

const windows = process.platform === "win32";
const skip = !windows && "a Windows-host test; the other cli-*.test.mjs files cover POSIX hosts";
const SCRIPT = fileURLToPath(dist("cli/index.js"));
const OPS = [
  { operationId: "list_accounts", tier: "read" },
  { operationId: "create_note", tier: "write" },
  { operationId: "close_account", tier: "destructive" },
  { operationId: "create_transfer", tier: "spend", flags: { egress: true } },
];

/** The environment without PSModulePath, as in a Windows PowerShell window an admin opens. */
const withoutModulePath = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => k.toUpperCase() !== "PSMODULEPATH"));

/**
 * Windows PowerShell, with the script as -EncodedCommand so no command-line quoting gets in the way.
 * It starts on its own module path: a PowerShell 7 parent, such as the CI step's shell, passes its
 * module folders down, and Windows PowerShell cannot load Get-Acl from them.
 */
function powershell(script, env = {}) {
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  const r = spawnSync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], {
    env: { ...withoutModulePath(), ...env },
    encoding: "utf8",
    timeout: 120_000,
  });
  if (r.error) throw r.error;
  return r;
}

/** Admin commands as a script that stops at the first failure, native commands included. */
const asScript = (commands) => ["$ErrorActionPreference = 'Stop'", ...commands.flatMap((c) => [c, "if ($LASTEXITCODE) { exit $LASTEXITCODE }"])].join("\n");

// icacls /setowner needs an elevated shell. GitHub's Windows runners are elevated; a developer's shell may not be.
const elevated =
  windows &&
  powershell("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)").stdout.trim() === "True";
const skipUnelevated = skip || (!elevated && "icacls /setowner needs an elevated shell");

const ADMINS = "S-1-5-32-544";
/** SYSTEM and Administrators full control and Users read, the only entries the commands leave. */
const adminOnly = (inherited) =>
  ["S-1-5-18 Allow FullControl", `${ADMINS} Allow FullControl`, "S-1-5-32-545 Allow ReadAndExecute, Synchronize"].map((r) => `${r} inherited=${inherited ? "True" : "False"}`);

function icacls(...args) {
  const r = spawnSync("icacls", args, { encoding: "utf8" });
  assert.equal(r.status, 0, `icacls ${args.join(" ")}: ${r.stdout}${r.stderr}`);
}

/** A machine in a temp folder: the policy and state overrides, a home, a project, and the client folders. */
function world(t) {
  // By its long name: Windows runners name %TEMP% with an 8.3 short name (RUNNER~1).
  const base = realpathSync.native(tempDir(t, "mcp-guard-win-"));
  const w = {
    policy: join(base, "policy"),
    state: join(base, "state"),
    home: join(base, "home"),
    project: join(base, "project"),
    machine: join(base, "machine"),
    pkg: join(base, "pkg"),
  };
  for (const d of [w.home, w.project, join(w.pkg, "dist")]) mkdirSync(d, { recursive: true });
  const manifest = buildManifest({ server: "toy", version: "1.0.0", prefix: "toy", operations: OPS });
  writeFileSync(join(w.pkg, "dist", "guard-manifest.json"), JSON.stringify(manifest, null, 2));
  w.env = { NST_MCP_POLICY_DIR: w.policy, NST_MCP_STATE_DIR: w.state };
  w.clientPaths = {
    claudeManaged: join(w.machine, "ClaudeCode"),
    cursorHooks: join(w.machine, "Cursor", "hooks.json"),
    codexAdmin: join(w.machine, "OpenAI", "Codex"),
  };
  w.io = { env: w.env, platform: "win32", home: w.home, cwd: w.project, clientPaths: w.clientPaths, execPath: process.execPath };
  w.write = (path, value) => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`);
  };
  return w;
}

/** Owner, inheritance and access rules of a file, by SID. */
function acl(path) {
  const r = powershell(
    [
      `$acl = Get-Acl -LiteralPath '${path.replaceAll("'", "''")}'`,
      "$sid = [Security.Principal.SecurityIdentifier]",
      "[pscustomobject]@{",
      "  owner = $acl.GetOwner($sid).Value",
      "  protected = $acl.AreAccessRulesProtected",
      "  rules = @($acl.GetAccessRules($true, $true, $sid) | ForEach-Object { '{0} {1} {2} inherited={3}' -f $_.IdentityReference.Value, $_.AccessControlType, $_.FileSystemRights, $_.IsInherited } | Sort-Object)",
      "} | ConvertTo-Json -Compress",
    ].join("\n"),
  );
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
}

test("harness --claude --hook: the printed PowerShell installs the drop-in as printed, and the hook denies through the real binary", { skip }, async (t) => {
  const w = world(t);
  const r = await cli(["harness", "toy", "--claude", "--hook", "--package", w.pkg, "--json"], w.io);
  assert.equal(r.code, 3, JSON.stringify(r.json));
  assert.deepEqual(r.json.warnings, []);
  assert.equal(r.json.admin.shell, "powershell");

  const dropIn = join(w.clientPaths.claudeManaged, "managed-settings.d", "50-mcp-guard-toy.json");
  const f = r.json.files.find((x) => x.path === dropIn);
  assert.ok(f, `no drop-in among ${r.json.files.map((x) => x.path).join(", ")}`);
  const [entry] = JSON.parse(f.content).hooks.PreToolUse;
  assert.deepEqual(entry.hooks, [{ type: "command", command: process.execPath, args: [SCRIPT, "hook", "claude", "toy"], timeout: 10, onFailure: "block" }]);
  assert.equal(r.json.files.find((x) => x.path.endsWith("harness-claude.json")).path, join(w.policy, "toy", "harness-claude.json"));

  // What an admin pastes, minus the ACL change unless this shell is elevated.
  const commands = elevated ? r.json.admin.commands : r.json.admin.commands.filter((c) => !c.startsWith("icacls "));
  const ps = powershell(asScript(commands));
  assert.equal(ps.status, 0, ps.stderr || ps.stdout);
  const installed = readFileSync(dropIn, "utf8");
  assert.ok(!installed.startsWith("\uFEFF"), "the drop-in starts with a BOM");
  assert.equal(installed.replaceAll("\r\n", "\n"), f.content.replace(/\n$/, ""), "the here-string holds the file as printed");
  if (elevated) {
    assert.deepEqual(acl(dropIn), {
      owner: "S-1-5-32-544",
      protected: true,
      rules: [
        "S-1-5-18 Allow FullControl inherited=False",
        "S-1-5-32-544 Allow FullControl inherited=False",
        "S-1-5-32-545 Allow ReadAndExecute, Synchronize inherited=False",
      ],
    });
    // ClaudeCode stops inheriting; managed-settings.d takes what it hands down.
    assert.deepEqual(acl(w.clientPaths.claudeManaged), { owner: ADMINS, protected: true, rules: adminOnly(false) });
    assert.deepEqual(acl(dirname(dropIn)), { owner: ADMINS, protected: false, rules: adminOnly(true) });
  } else {
    t.diagnostic("not elevated: the icacls lines were not run");
  }

  // Claude Code starts exec-form hooks without a shell: command, then args.
  const ask = (request) =>
    spawnSync(entry.hooks[0].command, entry.hooks[0].args, { input: JSON.stringify(request), env: { ...process.env, ...w.env }, encoding: "utf8", timeout: 60_000 });
  const denied = ask({ hook_event_name: "PreToolUse", tool_name: "mcp__toy__toy_critical", tool_input: {} });
  assert.equal(denied.status, 0, denied.stderr);
  const answer = JSON.parse(denied.stdout).hookSpecificOutput;
  assert.equal(answer.permissionDecision, "deny");
  assert.match(answer.permissionDecisionReason, /toy_critical is in the critical group/);
  const allowed = ask({ hook_event_name: "PreToolUse", tool_name: "mcp__toy__toy_read", tool_input: {} });
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.equal(allowed.stdout, "", "an allowed tool gets no answer, so Claude's own rules decide");
});

test("harness --cursor: hooks.json installs as printed, and the printed test line denies in PowerShell", { skip }, async (t) => {
  const w = world(t);
  const r = await cli(["harness", "toy", "--cursor", "--package", w.pkg, "--json"], w.io);
  assert.equal(r.code, 3, JSON.stringify(r.json));
  assert.deepEqual(r.json.warnings, []);
  const command = commandLine("win32", [process.execPath, SCRIPT, "hook", "cursor"]);
  const hooks = r.json.files.find((x) => x.path === w.clientPaths.cursorHooks);
  assert.deepEqual(JSON.parse(hooks.content), { version: 1, hooks: { beforeMCPExecution: [{ command, timeout: 10, failClosed: true }] } });

  const commands = elevated ? r.json.admin.commands : r.json.admin.commands.filter((c) => !c.startsWith("icacls "));
  const ps = powershell(asScript(commands));
  assert.equal(ps.status, 0, ps.stderr || ps.stdout);
  assert.deepEqual(JSON.parse(readFileSync(w.clientPaths.cursorHooks, "utf8")), JSON.parse(hooks.content));
  if (elevated) {
    assert.deepEqual(acl(dirname(w.clientPaths.cursorHooks)), { owner: ADMINS, protected: true, rules: adminOnly(false) });
    assert.deepEqual(acl(w.clientPaths.cursorHooks), { owner: ADMINS, protected: true, rules: adminOnly(false) });
  }

  // The line an admin runs once the files are in place.
  assert.equal(r.json.test.length, 1);
  assert.equal(r.json.test[0], `'{"mcp_server_name":"toy","tool_name":"toy_critical","tool_input":"{}"}' | & ${command}`);
  const line = powershell(r.json.test[0], w.env);
  assert.equal(line.status, 0, line.stderr);
  const denied = JSON.parse(line.stdout.trim());
  assert.equal(denied.permission, "deny");
  assert.match(denied.user_message, /toy_critical is in the critical group/);

  const read = powershell(`'{"mcp_server_name":"toy","tool_name":"toy_read","tool_input":"{}"}' | & ${command}`, w.env);
  assert.equal(JSON.parse(read.stdout.trim()).permission, "allow");
  const change = powershell(`'{"mcp_server_name":"toy","tool_name":"toy_change","tool_input":"{}"}' | & ${command}`, w.env);
  assert.equal(JSON.parse(change.stdout.trim()).permission, "ask");
  const other = powershell(`'{"mcp_server_name":"github","tool_name":"create_issue","tool_input":"{}"}' | & ${command}`, w.env);
  assert.equal(JSON.parse(other.stdout.trim()).permission, "ask", "a server without rules asks");
});

test("harness --cursor: a Cursor folder a user made first, open to everyone and already holding the entry, is taken over", { skip: skipUnelevated }, async (t) => {
  const w = world(t);
  const folder = dirname(w.clientPaths.cursorHooks);
  // What any user may do first in ProgramData: make the folder, open it to everyone, and put the entry there.
  const first = await cli(["harness", "toy", "--cursor", "--package", w.pkg, "--json"], w.io);
  const content = first.json.files.find((x) => x.path === w.clientPaths.cursorHooks).content;
  w.write(w.clientPaths.cursorHooks, content);
  icacls(folder, "/grant", "*S-1-1-0:(OI)(CI)F");
  icacls(w.clientPaths.cursorHooks, "/grant", "*S-1-1-0:F");
  assert.ok(acl(folder).rules.includes("S-1-1-0 Allow FullControl inherited=False"));

  const r = await cli(["harness", "toy", "--cursor", "--package", w.pkg, "--json"], w.io);
  assert.equal(r.code, 3, JSON.stringify(r.json));
  const hooks = r.json.files.find((x) => x.path === w.clientPaths.cursorHooks);
  assert.equal(hooks.install, "write", "on Windows a file that already has the entry is written again");
  assert.match(hooks.purpose, /^already has the mcp-guard hook; written again/);
  const ps = powershell(asScript(r.json.admin.commands));
  assert.equal(ps.status, 0, ps.stderr || ps.stdout);
  assert.deepEqual(acl(folder), { owner: ADMINS, protected: true, rules: adminOnly(false) });
  assert.deepEqual(acl(w.clientPaths.cursorHooks), { owner: ADMINS, protected: true, rules: adminOnly(false) });
  assert.deepEqual(JSON.parse(readFileSync(w.clientPaths.cursorHooks, "utf8")), JSON.parse(content));
});

test("harness --cursor: a junction in place of the Cursor folder is refused, and nothing changes where it leads", { skip }, async (t) => {
  const w = world(t);
  const folder = dirname(w.clientPaths.cursorHooks);
  const elsewhere = join(w.machine, "elsewhere");
  mkdirSync(elsewhere, { recursive: true });
  const mk = powershell(`New-Item -ItemType Junction -Path '${folder}' -Target '${elsewhere}' | Out-Null`);
  assert.equal(mk.status, 0, mk.stderr);
  const before = acl(elsewhere);

  const r = await cli(["harness", "toy", "--cursor", "--package", w.pkg, "--json"], w.io);
  assert.equal(r.code, 3, JSON.stringify(r.json));
  const commands = elevated ? r.json.admin.commands : r.json.admin.commands.filter((c) => !c.startsWith("icacls "));
  const ps = powershell(asScript(commands));
  assert.notEqual(ps.status, 0, "the commands stop at the junction");
  assert.match(`${ps.stderr}${ps.stdout}`.replace(/\s+/g, " "), /is a junction or symbolic link/);
  assert.equal(existsSync(join(elsewhere, "hooks.json")), false, "nothing was written through the junction");
  assert.deepEqual(acl(elsewhere), before, "icacls /L changed the junction, not the folder it leads to");
});

test("harness --codex on Windows says to check who owns the ProgramData folders", { skip }, async (t) => {
  const w = world(t);
  const r = await cli(["harness", "toy", "--codex", "--package", w.pkg, "--json"], w.io);
  assert.equal(r.code, 0, JSON.stringify(r.json));
  assert.ok(
    r.json.notes.some((n) => n.startsWith("Any user may create folders in ProgramData.") && n.includes(w.clientPaths.codexAdmin) && n.includes(dirname(w.clientPaths.codexAdmin))),
    JSON.stringify(r.json.notes)
  );
});

test("init: the printed PowerShell takes over a ProgramData-like folder chain one folder at a time", { skip: skipUnelevated }, (t) => {
  const base = realpathSync.native(tempDir(t, "mcp-guard-init-"));
  const pd = join(base, "ProgramData");
  mkdirSync(pd);
  // ProgramData's own entries: Users may create folders and files in everything that inherits them.
  icacls(pd, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", `*${ADMINS}:(OI)(CI)F`, "*S-1-3-0:(OI)(CI)(IO)F", "*S-1-5-32-545:(OI)(CI)RX", "*S-1-5-32-545:(CI)(WD,AD,WEA,WA)");
  const parent = join(pd, "NightSquawk");
  const root = join(parent, "mcp");
  const dir = join(root, "toy");
  const file = join(dir, "policy.json");
  // A user made NightSquawk first and opened it to everyone.
  mkdirSync(parent);
  icacls(parent, "/grant", "*S-1-1-0:(OI)(CI)F");

  const text = starterPolicyText("toy");
  const ps = powershell(asScript(windowsPolicyCommands(root, "toy", text)));
  assert.equal(ps.status, 0, ps.stderr || ps.stdout);
  assert.equal(readFileSync(file, "utf8").replaceAll("\r\n", "\n"), text.replace(/\n$/, ""), "the here-string holds the policy as printed");
  assert.deepEqual(acl(root), { owner: ADMINS, protected: true, rules: adminOnly(false) });
  assert.deepEqual(acl(dir), { owner: ADMINS, protected: false, rules: adminOnly(true) });
  assert.deepEqual(acl(file), { owner: ADMINS, protected: false, rules: adminOnly(true) });
  const top = acl(parent);
  assert.equal(top.owner, ADMINS);
  assert.equal(top.protected, false, "NightSquawk keeps what ProgramData hands down");
  assert.ok(top.rules.length > 0 && top.rules.every((r) => r.endsWith("inherited=True")), `the entry for everyone is gone: ${JSON.stringify(top.rules)}`);
  // The owner probe the policy check runs agrees.
  const owners = realProbes().windowsOwners([file, dir, root, parent]);
  assert.ok(owners, "the probe answered");
  for (const p of [file, dir, root, parent]) {
    const o = owners.find((x) => x.path.toLowerCase() === p.toLowerCase());
    assert.deepEqual(o && [o.owner, o.reparse], [ADMINS, false], p);
  }
});

test("harness on Windows refuses a hook path that cmd would expand", { skip }, async (t) => {
  const w = world(t);
  const r = await cli(["harness", "toy", "--cursor", "--hook-script", "C:\\Users\\%USERNAME%\\mcp-guard\\dist\\cli\\index.js", "--package", w.pkg, "--json"], w.io);
  assert.equal(r.code, 1);
  assert.match(r.json.error, /holds " or %/);
});

test("verify --watch: the Windows client files get a baseline, and a change in them is found", { skip }, async (t) => {
  const w = world(t);
  const desktop = join(w.home, "AppData", "Roaming", "Claude", "claude_desktop_config.json");
  const dropIn = join(w.clientPaths.claudeManaged, "managed-settings.d", "50-mcp-guard-toy.json");
  w.write(join(w.home, ".claude.json"), { mcpServers: { toy: { command: "node" } } });
  w.write(desktop, { mcpServers: { toy: { command: "node" } } });
  w.write(join(w.home, ".codex", "config.toml"), '[mcp_servers.toy]\ncommand = "node"\n');
  w.write(dropIn, { permissions: { deny: ["mcp__toy__toy_critical"] } });
  w.write(join(w.project, ".mcp.json"), { mcpServers: {} });
  const watch = () => cli(["verify", "--watch", "--json"], w.io);

  const first = await watch();
  assert.equal(first.code, 0, JSON.stringify(first.json));
  assert.equal(first.json.recorded, true);
  assert.equal(first.json.baseline, join(w.state, "_watch", "baseline.json"));
  assert.deepEqual(
    [...first.json.files].sort(),
    [join(w.home, ".claude.json"), join(w.home, ".codex", "config.toml"), desktop, dropIn, join(w.project, ".mcp.json")].sort(),
  );
  const second = await watch();
  assert.equal(second.code, 0);
  assert.deepEqual(second.json.changes, []);

  w.write(desktop, { mcpServers: { toy: { command: "node" }, evil: { command: "curl" } } });
  rmSync(dropIn);
  const third = await watch();
  assert.equal(third.code, 1);
  assert.deepEqual(third.json.changes, [
    { file: desktop, change: "added", key: "mcpServers.evil" }, // <base>\home\... sorts before <base>\machine\...
    { file: dropIn, change: "removed" },
  ]);
});

test("kill and status: the marker in a Windows policy folder", { skip }, async (t) => {
  const w = world(t);
  w.write(join(w.policy, "toy", "policy.json"), openPolicy("toy"));
  const k = await cli(["kill", "toy", "--note", "maintenance", "--json"], w.io);
  assert.equal(k.code, 0, JSON.stringify(k.json));
  assert.equal(k.json.marker, join(w.policy, "toy", "KILL"));
  assert.equal(readFileSync(k.json.marker, "utf8"), "maintenance (2026-11-04T12:00:00.000Z)\n");
  const s = await cli(["status", "toy", "--json"], w.io);
  assert.equal(s.json.kill.manual.server, true);
});

test("the guard's owner probe reads real owners when the parent hands down a module path Windows PowerShell cannot use", { skip }, (t) => {
  const dir = realpathSync.native(tempDir(t, "mcp-guard-owner-"));
  const file = join(dir, "policy.json");
  writeFileSync(file, "{}\n");
  // First on the inherited path: a PowerShell 7-only Microsoft.PowerShell.Security, as a PowerShell 7 parent hands down.
  const mod = join(dir, "modules", "Microsoft.PowerShell.Security");
  mkdirSync(mod, { recursive: true });
  writeFileSync(join(mod, "Microsoft.PowerShell.Security.psd1"), "@{ ModuleVersion = '7.9.0'; CompatiblePSEditions = @('Core'); CmdletsToExport = @('Get-Acl') }\r\n");
  const saved = process.env.PSModulePath;
  process.env.PSModulePath = [join(dir, "modules"), saved].filter(Boolean).join(";");
  t.after(() => {
    if (saved === undefined) delete process.env.PSModulePath;
    else process.env.PSModulePath = saved;
  });

  const owners = realProbes().windowsOwners([file]);
  assert.ok(owners, "the probe answered");
  assert.equal(owners.length, 1);
  assert.match(String(owners[0].owner), /^S-1-5-/, JSON.stringify(owners));
  assert.equal(owners[0].owner, acl(file).owner);
});

test("ProgramData and its drive root have owners the policy check accepts, and neither is a link", { skip }, () => {
  // windowsPart1 checks owners all the way up to the drive root, so a stock install must pass there.
  const pd = programDataDir(process.env);
  const chain = [pd, parse(pd).root];
  const owners = realProbes().windowsOwners(chain);
  assert.ok(owners, "the probe answered");
  for (const p of chain) {
    const o = owners.find((x) => x.path.toLowerCase() === p.toLowerCase());
    assert.ok(o && TRUSTED_OWNER_SIDS.includes(o.owner), `${p}: ${JSON.stringify(o)}`);
    assert.equal(o.reparse, false, `${p} is a link`);
  }
});
