// mcp-guard init: writes only under the test override; otherwise prints admin commands.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { cli, dist, sandbox, test } from "./cli-helpers.mjs";

const { starterPolicyText, windowsPolicyCommands, posixPolicyCommands } = await import(dist("cli/init.js"));
const { basePolicySchema } = await import(dist("guard/policy.js"));

// A name no real install uses, so the standard-path tests never meet a real policy.
const SERVER = "cli-test-init-zz";

test("the starter policy enables reads only and passes the base schema", () => {
  const p = JSON.parse(starterPolicyText("column"));
  assert.deepEqual(p.groups, { read: true, change: false, critical: false, spend: false });
  assert.equal(p.environment.allow_live, false);
  assert.equal(p.server, "column");
  basePolicySchema.parse(p);
  assert.ok(starterPolicyText("column").endsWith("}\n"));
});

test("with the override, init writes the file, refuses to replace it, and --force replaces it", async (t) => {
  const sb = sandbox(t);
  const r = await cli(["init", "column", "--json"], { env: sb.env });
  assert.equal(r.code, 0);
  assert.equal(r.json.written, true);
  assert.equal(r.json.override, true);
  assert.equal(readFileSync(sb.policyFile("column"), "utf8"), starterPolicyText("column"));

  const status = await cli(["status", "column", "--json"], { env: sb.env });
  assert.equal(status.json.policy.source, "file");
  assert.equal(status.json.policy.error, undefined);

  const again = await cli(["init", "column"], { env: sb.env });
  assert.equal(again.code, 1);
  assert.match(again.errText, /already exists/);

  sb.policy("column", { version: 1, server: "column", groups: { change: true } });
  const forced = await cli(["init", "column", "--force", "--json"], { env: sb.env });
  assert.equal(forced.code, 0);
  assert.equal(forced.json.replaced, true);
  assert.equal(readFileSync(sb.policyFile("column"), "utf8"), starterPolicyText("column"));
});

test("--print prints the policy and writes nothing", async (t) => {
  const sb = sandbox(t);
  const r = await cli(["init", "column", "--print"], { env: sb.env });
  assert.equal(r.code, 0);
  assert.deepEqual(JSON.parse(r.text), JSON.parse(starterPolicyText("column")));
  assert.equal(existsSync(sb.policyDir), false);
});

test("standard paths on Linux: exit 3 with sudo tee commands, nothing written", async (t) => {
  const target = `/etc/nightsquawk-mcp/${SERVER}/policy.json`;
  if (existsSync(target)) return t.skip(`${target} exists on this machine`);
  const r = await cli(["init", SERVER, "--json"], { env: {}, platform: "linux", home: "/home/tester" });
  assert.equal(r.code, 3);
  assert.equal(r.json.written, false);
  assert.equal(r.json.path, target);
  assert.equal(r.json.admin.shell, "sh");
  const cmds = r.json.admin.commands;
  assert.equal(cmds[0], `sudo install -d -m 0755 -o 0 -g 0 '/etc/nightsquawk-mcp' '/etc/nightsquawk-mcp/${SERVER}'`);
  assert.ok(cmds.includes(`sudo chmod 0644 '${target}'`));
  assert.equal(existsSync(target), false);

  const text = await cli(["init", SERVER], { env: {}, platform: "linux" });
  assert.equal(text.code, 3);
  assert.ok(text.text.includes(`sudo tee '${target}' > /dev/null <<'EOF'`), text.text);
  // The heredoc body is the policy, and its terminator starts its own line.
  const lines = text.out;
  const start = lines.findIndex((l) => l.startsWith("sudo tee "));
  const end = lines.indexOf("EOF", start);
  assert.ok(end > start, "EOF terminator on its own line");
  assert.deepEqual(JSON.parse(lines.slice(start + 1, end).join("\n")), JSON.parse(starterPolicyText(SERVER)));
  assert.match(text.text, /sudoedit '/);
  assert.doesNotMatch(text.text, /sudo mcp-guard/);
  assert.doesNotMatch(text.text, /running as root/);
});

test("init as root warns that mcp-guard never needs root", async (t) => {
  const target = `/etc/nightsquawk-mcp/${SERVER}/policy.json`;
  if (existsSync(target)) return t.skip(`${target} exists on this machine`);
  const r = await cli(["init", SERVER], { env: {}, platform: "linux", uid: 0 });
  assert.equal(r.code, 3);
  assert.match(r.text, /running as root\. It never needs root/);
  assert.match(r.text, /do not run it with sudo/);
  assert.doesNotMatch(r.text, /sudo mcp-guard/);
});

test("standard paths on Windows: each folder is taken over, top first, before the file is written; owners set before each reset", async () => {
  const r = await cli(["init", SERVER, "--json"], { env: { ProgramData: "C:\\ProgramData" }, platform: "win32", home: "C:\\Users\\tester" });
  if (r.code === 1) return; // a real C:\ProgramData policy exists on this Windows runner
  assert.equal(r.code, 3);
  assert.equal(r.json.admin.shell, "powershell");
  const parent = "C:\\ProgramData\\NightSquawk";
  const root = `${parent}\\mcp`;
  const dir = `${root}\\${SERVER}`;
  const file = `${dir}\\policy.json`;
  assert.deepEqual(r.json.admin.commands, windowsPolicyCommands(root, SERVER, starterPolicyText(SERVER)));
  const cmds = r.json.admin.commands;
  const at = (s) => {
    const i = cmds.indexOf(s);
    assert.ok(i >= 0, s);
    return i;
  };
  const write = cmds.findIndex((c) => c.includes("[System.IO.File]::WriteAllText("));
  let last = -1;
  for (const p of [parent, root, dir, file]) {
    const set = at(`icacls '${p}' /setowner '*S-1-5-32-544' /L /C`);
    const reset = at(`icacls '${p}' /reset /L /C`);
    assert.ok(last < set && set < reset, `top first, and the owner before /reset: ${p}`);
    assert.ok(p === file ? set > write : reset < write, `${p} is taken over ${p === file ? "after" : "before"} the write`);
    assert.ok(cmds[write].includes(`'${p}'`), `the write refuses a link at ${p}`);
    last = reset;
  }
  assert.deepEqual(
    cmds.filter((c) => c.includes("/inheritance:r")),
    [`icacls '${root}' /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /L /C`],
    "only the policy root stops inheriting; NightSquawk keeps ProgramData's permissions"
  );
  assert.ok(!cmds.some((c) => /\/T\b/.test(c)), "never recursive: /T can follow a junction planted inside");
  const policy = cmds.findIndex((c) => c.startsWith("$policy = @'\n"));
  assert.ok(policy > 0 && policy < write && cmds[policy].endsWith("\n'@"), "here-string terminator at the start of its line");
  assert.match(cmds[write], /ReparsePoint\) \{ throw "\$p is a junction or symbolic link, so nothing was written\./);
  assert.equal(cmds.at(-1), `icacls '${file}'`, "the result is shown last");
  assert.deepEqual(r.json.warnings, []);

  const text = await cli(["init", SERVER], { env: { ProgramData: "C:\\ProgramData" }, platform: "win32" });
  assert.match(text.text, /elevated PowerShell/);
  assert.match(text.text, /elevated editor/);
  assert.doesNotMatch(text.text, /sudo/);
});

test("Windows: a moved ProgramData is warned about and every quote character is doubled", async () => {
  const r = await cli(["init", SERVER, "--json"], { env: { ProgramData: "D:\\Pro\u2019gram Data" }, platform: "win32" });
  if (r.code === 1) return;
  assert.equal(r.code, 3);
  assert.ok(r.json.warnings.some((w) => w.includes("D:\\Pro\u2019gram Data") && w.includes("C:\\ProgramData")));
  assert.ok(r.json.admin.commands.includes("icacls 'D:\\Pro\u2019\u2019gram Data\\NightSquawk' /reset /L /C"), "U+2019 is doubled like an ASCII quote");
});

test("the POSIX commands quote paths with single quotes", () => {
  const cmds = posixPolicyCommands("/opt/it's here", "column", "{}\n");
  assert.equal(cmds[0], "sudo install -d -m 0755 -o 0 -g 0 '/opt/it'\\''s here' '/opt/it'\\''s here/column'");
});

test("init needs a valid server name", async (t) => {
  const sb = sandbox(t);
  assert.equal((await cli(["init"], { env: sb.env })).code, 2);
  assert.equal((await cli(["init", "Bad Name"], { env: sb.env })).code, 2);
});
