/**
 * Quoting for the admin commands mcp-guard prints. A printed command must run
 * exactly as an admin reads it, so text holding a control character or a line
 * separator is refused rather than quoted (a CR or LF would split one command
 * into two). PowerShell quoting is the guard's own psSingleQuoted, which doubles
 * every character PowerShell treats as a single quote.
 *
 * On Windows the commands are printed as one PowerShell block (powershellBlock), so
 * the first step that fails stops the rest, pasted or not.
 */
import { hasUnsafePathChar, POWERSHELL_SINGLE_QUOTES, psSingleQuoted, TRUSTED_OWNER_SIDS } from "../guard/protection.js";
import { CliError } from "./io.js";

export type Shell = "sh" | "powershell";

export function shellFor(platform: NodeJS.Platform): Shell {
  return platform === "win32" ? "powershell" : "sh";
}

function refuseUnsafe(text: string): void {
  if (hasUnsafePathChar(text)) {
    throw new CliError(`Refusing to print a command for ${JSON.stringify(text)}: it holds a control character or line separator.`);
  }
}

/** A POSIX sh single-quoted word. */
export function shQuote(text: string): string {
  refuseUnsafe(text);
  return `'${text.replace(/'/g, "'\\''")}'`;
}

/** A PowerShell single-quoted literal. */
export function psQuote(text: string): string {
  refuseUnsafe(text);
  return psSingleQuoted(text);
}

/**
 * `$variable = @'...'@`: a PowerShell here-string holding `text` as it is, without its last newline.
 * Text that would end it early is refused: a CR (PowerShell ends a line there too) or a line that
 * starts with a single quote, or a character PowerShell reads as one, followed by @.
 */
export function psHereString(variable: string, text: string): string {
  const quotes = String.fromCharCode(...POWERSHELL_SINGLE_QUOTES);
  if (text.includes("\r") || new RegExp(`(^|\\n)[${quotes}]@`).test(text)) {
    throw new CliError(`Refusing to print a PowerShell here-string for $${variable}: the text holds a CR, or a line that would end the here-string.`);
  }
  return `$${variable} = @'\n${text}${text.endsWith("\n") ? "" : "\n"}'@`;
}

/** `command <<'EOF'`: a POSIX sh here-document holding `text`, which must end with a newline and have no line that is only EOF. */
export function shHereDoc(command: string, text: string): string {
  if (!text.endsWith("\n") || /(^|\n)EOF(\n|$)/.test(text)) {
    throw new CliError("Refusing to print a here-document: the text must end with a newline and have no line that is only EOF.");
  }
  return `${command} <<'EOF'\n${text}EOF`;
}

export function quoteFor(shell: Shell): (text: string) => string {
  return shell === "powershell" ? psQuote : shQuote;
}

/** Admin commands, as printed and as --json returns them. */
export interface AdminCommands {
  shell: Shell;
  /** Where to run them. */
  run_as: string;
  commands: string[];
}

/** Windows: the statements become one block; see powershellBlock. */
export function adminCommands(platform: NodeJS.Platform, commands: string[]): AdminCommands {
  const shell = shellFor(platform);
  return {
    shell,
    // -NoProfile: the agent's user may be able to edit the profile script, which an elevated PowerShell runs as admin.
    run_as: shell === "powershell" ? "an elevated PowerShell started with -NoProfile (Run as administrator)" : "a shell, as a user who may use sudo",
    commands: shell === "powershell" && commands.length ? [powershellBlock(commands)] : commands,
  };
}

/** SIDs the Windows commands name. */
const SID = Object.freeze({ system: "*S-1-5-18", administrators: "*S-1-5-32-544", users: "*S-1-5-32-545" });

interface PsHelper {
  name: string;
  /** Helpers it calls. */
  needs: readonly string[];
  lines: readonly string[];
}

const trusted = TRUSTED_OWNER_SIDS.map((s) => `'${s}'`).join(", ");

/** The functions the Windows statements call. A block defines only those its statements use. */
const PS_HELPERS: readonly PsHelper[] = [
  {
    name: "icacls",
    needs: [],
    lines: [
      "# icacls that fails does not stop PowerShell by itself, so this one throws.",
      "function icacls { $ErrorActionPreference = 'Continue'; icacls.exe @args; if ($LASTEXITCODE -ne 0) { throw \"icacls $args failed (exit code $LASTEXITCODE).\" } }",
    ],
  },
  {
    name: "Get-Attributes",
    needs: [],
    lines: [
      "# The path's own attributes, never those of where a link leads; nothing when it does not exist.",
      "function Get-Attributes([string]$Path) { try { [IO.File]::GetAttributes($Path) } catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] {} }",
    ],
  },
  {
    name: "Assert-NoLink",
    needs: ["Get-Attributes"],
    lines: [
      "function Assert-NoLink([string]$Path) {",
      "  if ((Get-Attributes $Path) -band [IO.FileAttributes]::ReparsePoint) { throw \"$Path is a junction or symbolic link. Remove the link (not what it points to) and run these commands again.\" }",
      "}",
    ],
  },
  {
    name: "Set-AdminFolder",
    needs: ["icacls", "Get-Attributes", "Assert-NoLink"],
    lines: [
      "# Take over one folder, top folder first: make it if it is missing, then Administrators own it and the entries anyone",
      "# else added are gone (one folder, never /T; /L changes a link itself, never where it leads). -Protect: it stops",
      "# inheriting, and SYSTEM and Administrators have full control and Users read. Then check that nobody but SYSTEM,",
      "# Administrators and TrustedInstaller can change, delete or take it over. -UsersMayCreate: Users may still add",
      "# files and folders to it, as ProgramData lets everyone do.",
      "function Set-AdminFolder([string]$Path, [switch]$Protect, [switch]$UsersMayCreate) {",
      "  Assert-NoLink $Path",
      "  if ($null -eq (Get-Attributes $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }",
      `  icacls $Path /setowner '${SID.administrators}' /L`,
      "  icacls $Path /reset /L",
      `  if ($Protect) { icacls $Path /inheritance:r /grant:r '${SID.system}:(OI)(CI)F' '${SID.administrators}:(OI)(CI)F' '${SID.users}:(OI)(CI)RX' /L }`,
      "  $acl = Get-Acl -LiteralPath $Path",
      "  Assert-NoLink $Path",
      "  if (-not ((Get-Attributes $Path) -band [IO.FileAttributes]::Directory)) { throw \"$Path is not a folder.\" }",
      `  $trusted = ${trusted}`,
      "  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value",
      "  if ($owner -notin $trusted) { throw \"$Path belongs to $owner, not Administrators.\" }",
      "  $change = [int64][Security.AccessControl.FileSystemRights]'DeleteSubdirectoriesAndFiles, Delete, ChangePermissions, TakeOwnership' -bor 0x10000000",
      "  if (-not $UsersMayCreate) { $change = $change -bor [int64][Security.AccessControl.FileSystemRights]'CreateFiles, CreateDirectories, WriteExtendedAttributes, WriteAttributes' -bor 0x40000000 }",
      "  foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {",
      "    # An inherit-only entry is for what the folder holds, not for the folder.",
      "    if ($r.AccessControlType -eq 'Allow' -and -not ($r.PropagationFlags -band 2) -and $r.IdentityReference.Value -notin $trusted -and ([int64]$r.FileSystemRights -band $change)) {",
      "      throw \"$($r.IdentityReference.Value) can still change $Path ($($r.FileSystemRights)).\"",
      "    }",
      "  }",
      "}",
    ],
  },
  {
    name: "Write-NewFile",
    needs: ["Get-Attributes", "Assert-NoLink"],
    lines: [
      "# A file already there is deleted first, not overwritten: whoever made it may still hold it open, and an open",
      "# handle keeps its access through an overwrite and an ACL change.",
      "function Write-NewFile([string]$Path, [string]$Text) {",
      "  Assert-NoLink $Path",
      "  $a = Get-Attributes $Path",
      "  if ($a -band [IO.FileAttributes]::Directory) { throw \"$Path is a folder.\" }",
      "  if ($null -ne $a) { Remove-Item -LiteralPath $Path -Force }",
      "  [IO.File]::WriteAllText($Path, $Text)",
      "}",
    ],
  },
  {
    name: "Set-AdminFile",
    needs: ["icacls"],
    lines: [
      "# Administrators own the file, and it has only what its folder hands down. -Protect: it stops inheriting,",
      "# and SYSTEM and Administrators have full control and Users read.",
      "function Set-AdminFile([string]$Path, [switch]$Protect) {",
      `  icacls $Path /setowner '${SID.administrators}' /L`,
      "  icacls $Path /reset /L",
      `  if ($Protect) { icacls $Path /inheritance:r /grant:r '${SID.system}:F' '${SID.administrators}:F' '${SID.users}:RX' /L }`,
      "}",
    ],
  },
];

const calls = (text: string, name: string) => new RegExp(`(^|[\\s;{(|])${name.replace(/[-$]/g, "\\$&")}(?=[\\s;)}]|$)`, "m").test(text);

/**
 * Windows: admin statements as one PowerShell block. PowerShell runs a pasted block as one unit,
 * so the first step that fails (a cmdlet error under ErrorActionPreference Stop, an icacls that
 * exits non-zero, a check that throws) stops everything after it, and no file is written unless
 * every step before it worked. The block defines the helpers its statements call, first.
 * Statements are never indented: a here-string's closing '@ must start its line.
 */
export function powershellBlock(statements: readonly string[]): string {
  const used = new Set<string>();
  const use = (name: string) => {
    if (used.has(name)) return;
    used.add(name);
    for (const n of PS_HELPERS.find((h) => h.name === name)!.needs) use(n);
  };
  const body = statements.join("\n");
  for (const h of PS_HELPERS) if (calls(body, h.name)) use(h.name);
  return [
    "& {",
    "# mcp-guard: one block, which stops at the first step that fails.",
    "$ErrorActionPreference = 'Stop'",
    ...PS_HELPERS.filter((h) => used.has(h.name)).flatMap((h) => h.lines),
    ...statements,
    "}",
  ].join("\n");
}

/** The text block for admin commands. Never indented: a heredoc terminator must start its line. */
export function renderAdmin(admin: AdminCommands, intro: string): string[] {
  return [intro, `Run these in ${admin.run_as}:`, "", ...admin.commands, ""];
}
