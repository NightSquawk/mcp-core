/**
 * Where Claude Code, Codex, Cursor and Claude Desktop keep their config, per the
 * clients' docs (harness-formats research, 2026-11-04). harness writes rules for
 * these; verify --watch fingerprints them.
 */
import { win32 } from "node:path";
import { programDataDir } from "../guard/paths.js";
import { pathLib } from "./context.js";
import type { ClientPaths, CliIo } from "./io.js";

export function claudeManagedDir(platform: NodeJS.Platform): string {
  if (platform === "win32") return "C:\\Program Files\\ClaudeCode";
  if (platform === "darwin") return "/Library/Application Support/ClaudeCode";
  return "/etc/claude-code";
}

export function cursorEnterpriseHooks(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string {
  if (platform === "win32") return win32.join(programDataDir(env), "Cursor", "hooks.json");
  if (platform === "darwin") return "/Library/Application Support/Cursor/hooks.json";
  return "/etc/cursor/hooks.json";
}

export function codexAdminDir(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string {
  return platform === "win32" ? win32.join(programDataDir(env), "OpenAI", "Codex") : "/etc/codex";
}

/** The machine-wide locations, or the test overrides in io.clientPaths. */
export function clientPaths(io: CliIo): ClientPaths {
  return {
    claudeManaged: io.clientPaths?.claudeManaged ?? claudeManagedDir(io.platform),
    cursorHooks: io.clientPaths?.cursorHooks ?? cursorEnterpriseHooks(io.platform, io.env),
    codexAdmin: io.clientPaths?.codexAdmin ?? codexAdminDir(io.platform, io.env),
  };
}

export function codexHome(io: CliIo): string {
  return io.env.CODEX_HOME || pathLib(io.platform).join(io.home, ".codex");
}

export function claudeDesktopConfig(io: CliIo): string {
  const lib = pathLib(io.platform);
  if (io.platform === "win32") return lib.join(io.env.APPDATA || lib.join(io.home, "AppData", "Roaming"), "Claude", "claude_desktop_config.json");
  if (io.platform === "darwin") return lib.join(io.home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  return lib.join(io.env.XDG_CONFIG_HOME || lib.join(io.home, ".config"), "Claude", "claude_desktop_config.json");
}
