// The PowerShell block mcp-guard prints for a Windows admin, read by a real PowerShell: pwsh where it
// is installed (GitHub's Ubuntu and macOS runners have it), Windows PowerShell on Windows. Every block
// must parse as one statement, a step that fails must stop it before anything is written, and files
// are written as printed. cli-windows.test.mjs runs the icacls steps for real on the Windows job.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, openSync, closeSync, readFileSync, readSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { dist, tempDir } from "./foundation-helpers.mjs";

const { adminFileCommands } = await import(dist("cli/harness.js"));
const { starterPolicyText, windowsFolderCommands, windowsPolicyCommands } = await import(dist("cli/init.js"));
const { adminCommands, powershellBlock, psHereString, psQuote, shHereDoc } = await import(dist("cli/shell.js"));

const windows = process.platform === "win32";
const exe = windows ? "powershell.exe" : "pwsh";
/** Without PSModulePath, as in a PowerShell window an admin opens (a PowerShell 7 parent passes its module folders down). */
const env = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => k.toUpperCase() !== "PSMODULEPATH"));

/** Run a script. `error` is the message of the error that stopped it, on one line (PowerShell's own display wraps). */
function ps(script, extra = {}) {
  const wrapped = `try {\n${script}\n} catch { [Console]::Error.WriteLine("ERROR: " + $_.Exception.Message); exit 1 }`;
  const r = spawnSync(exe, ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(wrapped, "utf16le").toString("base64")], {
    env: { ...env(), ...extra },
    encoding: "utf8",
    timeout: 120_000,
  });
  if (r.error) throw r.error;
  return { ...r, out: `${r.stdout}${r.stderr}`, error: /^ERROR: (.*)$/m.exec(r.stderr)?.[1] ?? null };
}

const found = (() => {
  try {
    return ps("exit 7").status === 7;
  } catch {
    return false;
  }
})();
const skip = !found && `${exe} is not installed`;

const TEXT = '{\n  "permissions": {}\n}\n';
const BLOCKS = {
  init: powershellBlock(windowsPolicyCommands("C:\\ProgramData\\NightSquawk\\mcp", "toy", starterPolicyText("toy"))),
  claude: powershellBlock([
    ...adminFileCommands("win32", "C:\\Program Files\\ClaudeCode\\managed-settings.d\\50-mcp-guard-toy.json", TEXT, "C:\\Program Files\\ClaudeCode"),
    ...adminFileCommands("win32", "C:\\Program Files\\ClaudeCode\\managed-settings.d\\45-mcp-guard-sandbox.json", TEXT, "C:\\Program Files\\ClaudeCode"),
  ]),
  cursor: powershellBlock(adminFileCommands("win32", "C:\\ProgramData\\Cursor\\hooks.json", TEXT, "C:\\ProgramData\\Cursor")),
  baseline: powershellBlock(adminFileCommands("win32", "D:\\Admin\\watch\\baseline.json", TEXT)),
  quotes: powershellBlock(windowsPolicyCommands("D:\\Pro\u2019gram Data\\NightSquawk\\mcp", "it's", starterPolicyText("toy"))),
};

test("the helpers a block defines are the ones its statements call", () => {
  const defined = (block) => [...block.matchAll(/^function ([\w.-]+)/gm)].map((m) => m[1]);
  assert.deepEqual(defined(BLOCKS.init), ["icacls", "Get-Attributes", "Assert-NoLink", "Set-AdminFolder", "Write-NewFile", "Set-AdminFile"]);
  assert.deepEqual(defined(BLOCKS.baseline), ["icacls", "Get-Attributes", "Assert-NoLink", "Write-NewFile", "Set-AdminFile"]);
  // A kill marker needs none of them, and still stops at the first error.
  const [kill] = adminCommands("win32", ["New-Item -ItemType Directory -Force -Path 'C:\\x' | Out-Null", "[System.IO.File]::WriteAllText('C:\\x\\stop', 'stop')"]).commands;
  assert.deepEqual(defined(kill), []);
  assert.equal(kill, "& {\n# mcp-guard: one block, which stops at the first step that fails.\n$ErrorActionPreference = 'Stop'\nNew-Item -ItemType Directory -Force -Path 'C:\\x' | Out-Null\n[System.IO.File]::WriteAllText('C:\\x\\stop', 'stop')\n}");
  assert.deepEqual(adminCommands("win32", []).commands, []);
  assert.deepEqual(adminCommands("linux", ["sudo true"]).commands, ["sudo true"], "POSIX commands stay one per line");
});

test("here-strings and here-documents refuse text that would end them early", () => {
  assert.equal(psHereString("x", "a\n"), "$x = @'\na\n'@");
  assert.equal(psHereString("x", "a"), "$x = @'\na\n'@", "the same value: the last newline is never part of it");
  for (const bad of ["a\r\nb\n", "a\n'@\nWrite-Output 1\n", "a\n\u2019@ x\n", "'@\n"]) assert.throws(() => psHereString("x", bad), /Refusing to print a PowerShell here-string/, JSON.stringify(bad));
  assert.equal(psHereString("x", "it's 'quoted' @' and '@ mid-line\n"), "$x = @'\nit's 'quoted' @' and '@ mid-line\n'@");
  assert.equal(shHereDoc("sudo tee x", "a\n"), "sudo tee x <<'EOF'\na\nEOF");
  for (const bad of ["a", "a\nEOF\nb\n", "EOF\n"]) assert.throws(() => shHereDoc("sudo tee x", bad), /Refusing to print a here-document/, JSON.stringify(bad));
});

test("every Windows admin block parses as one statement", { skip }, (t) => {
  const dir = tempDir(t, "mcp-guard-ps-");
  const script = [
    "$errors = $null; $tokens = $null",
    "$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:BLOCK, [ref]$tokens, [ref]$errors)",
    "[pscustomobject]@{ errors = @($errors | ForEach-Object { \"$($_.Extent.StartLineNumber): $($_.Message)\" }); statements = $ast.EndBlock.Statements.Count } | ConvertTo-Json -Compress",
  ].join("\n");
  for (const [name, block] of Object.entries(BLOCKS)) {
    const file = join(dir, `${name}.ps1`);
    // With a BOM, as Windows PowerShell reads a file without one as the ANSI code page.
    writeFileSync(file, `\uFEFF${block}\n`);
    const r = ps(script, { BLOCK: file });
    assert.equal(r.status, 0, r.out);
    assert.deepEqual(JSON.parse(r.stdout), { errors: [], statements: 1 }, `${name}:\n${block}`);
  }
});

test("a step that fails stops the block: nothing after it runs and nothing is written", { skip }, (t) => {
  const base = tempDir(t, "mcp-guard-ps-");
  const top = join(base, "Top");
  const sub = join(top, "sub");
  const file = join(sub, "hooks.json");
  const block = powershellBlock([
    ...windowsFolderCommands([top, sub], (d) => d === top),
    psHereString("content", TEXT),
    `Write-NewFile ${psQuote(file)} $content`,
    `Set-AdminFile ${psQuote(file)} -Protect`,
  ]);
  // icacls that fails, in place of the real one (a function comes before a program of the same name).
  const r = ps(`function global:icacls.exe { $global:LASTEXITCODE = 5 }\n${block}\n'still running'`);
  assert.notEqual(r.status, 0, r.out);
  assert.equal(r.error, `icacls ${top} /setowner *S-1-5-32-544 /L failed (exit code 5).`);
  assert.doesNotMatch(r.out, /still running/, "nothing after the block ran either");
  assert.ok(existsSync(top), "the first folder was made");
  assert.equal(existsSync(sub), false, "the next folder was not");
  assert.equal(existsSync(file), false, "and the file was not written");
});

test("Write-NewFile writes the text as printed, deletes a file already there first, and refuses a link or a folder", { skip }, (t) => {
  const base = tempDir(t, "mcp-guard-ps-");
  const write = (path, text) => ps(powershellBlock([psHereString("content", text), `Write-NewFile ${psQuote(path)} $content`]));
  const file = join(base, "policy.json");
  const text = "{\n  \"note\": \"it's \u2019quoted\u2019 '@ and @' mid-line, caf\u00e9\"\n}\n";
  let r = write(file, text);
  assert.equal(r.status, 0, r.out);
  assert.equal(readFileSync(file, "utf8").replaceAll("\r\n", "\n"), text.replace(/\n$/, ""), "the here-string holds the text as printed");
  assert.notEqual(readFileSync(file)[0], 0xef, "no BOM");

  writeFileSync(file, "old");
  // Someone holds the old file open: deleted first, their handle keeps the old file, not the new one.
  // (Windows deletes an open file only with POSIX semantics, so the handle is checked elsewhere.)
  const fd = windows ? null : openSync(file, "r");
  if (fd !== null) t.after(() => closeSync(fd));
  r = write(file, "new\n");
  assert.equal(r.status, 0, r.out);
  assert.equal(readFileSync(file, "utf8"), "new");
  if (fd !== null) {
    const buf = Buffer.alloc(8);
    assert.equal(buf.toString("utf8", 0, readSync(fd, buf, 0, 8, 0)), "old", "an overwrite would have reached the open handle");
  }

  const folder = join(base, "folder");
  mkdirSync(folder);
  r = write(folder, "x\n");
  assert.notEqual(r.status, 0);
  assert.equal(r.error, `${folder} is a folder.`);

  const target = join(base, "target.json");
  writeFileSync(target, "target");
  const link = join(base, "link.json");
  try {
    symlinkSync(target, link);
  } catch (e) {
    if (e.code === "EPERM") return t.diagnostic("symbolic links need Developer Mode or an elevated shell here");
    throw e;
  }
  r = write(link, "x\n");
  assert.notEqual(r.status, 0);
  assert.equal(r.error, `${link} is a junction or symbolic link. Remove the link (not what it points to) and run these commands again.`);
  assert.equal(readFileSync(target, "utf8"), "target", "nothing was written through the link");
});
