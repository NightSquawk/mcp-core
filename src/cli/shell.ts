/**
 * Quoting for the admin commands mcp-guard prints. A printed command must run
 * exactly as an admin reads it, so text holding a control character or a line
 * separator is refused rather than quoted (a CR or LF would split one command
 * into two). PowerShell quoting is the guard's own psSingleQuoted, which doubles
 * every character PowerShell treats as a single quote.
 */
import { hasUnsafePathChar, psSingleQuoted } from "../guard/protection.js";
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

export function adminCommands(platform: NodeJS.Platform, commands: string[]): AdminCommands {
  const shell = shellFor(platform);
  return {
    shell,
    run_as: shell === "powershell" ? "an elevated PowerShell (Run as administrator)" : "a shell, as a user who may use sudo",
    commands,
  };
}

/** The text block for admin commands. Never indented: a heredoc terminator must start its line. */
export function renderAdmin(admin: AdminCommands, intro: string): string[] {
  return [intro, `Run these in ${admin.run_as}:`, "", ...admin.commands, ""];
}
