/**
 * The CLI's view of the world: output, environment, platform and the terminal.
 * Commands never touch process.* directly, so tests drive them with a fake.
 */
import { homedir } from "node:os";
import { createInterface } from "node:readline/promises";
import { checkProtection, type ProtectionProbes, type ProtectionReport, type StatInfo } from "../guard/protection.js";

export interface CliIo {
  /** One line to stdout. */
  out(line: string): void;
  /** One line to stderr. */
  err(line: string): void;
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  cwd: string;
  home: string;
  /** stdin and stdout are both terminals, so a person can answer a prompt. */
  interactive: boolean;
  /** Ask on the terminal (the question goes to stderr, so --json output stays clean). */
  ask(question: string): Promise<string>;
  /** All of stdin, as UTF-8 (the hook command reads its request here). */
  readStdin(): Promise<string>;
  /** The Node binary running mcp-guard (harness writes it into hook commands). */
  execPath: string;
  clock: () => Date;
  /** Effective uid, or null where there is none (Windows). */
  uid: number | null;
  pid: number;
  /** OS probes for the protection check (tests inject fakes). */
  probes?: ProtectionProbes;
  /** Replaces the protection check (tests). */
  protect?: (policyPath: string, override: boolean) => ProtectionReport;
  /** Moves the machine-wide client config folders (tests). Real runs leave it unset. */
  clientPaths?: Partial<ClientPaths>;
  /** lstat and readlink for harness's check of the files a hook runs (tests inject fakes; real runs use the file system). */
  pathProbes?: PathProbes;
}

export interface PathProbes {
  /** null when the path does not exist or cannot be read. */
  lstat(path: string): StatInfo | null;
  /** A symlink's target as stored, or null when it cannot be read. */
  readlink(path: string): string | null;
}

/** Machine-wide client config, outside any home folder. clients.ts has the real locations. */
export interface ClientPaths {
  /** Claude Code's managed settings folder (managed-settings.json, managed-settings.d, managed-mcp.json). */
  claudeManaged: string;
  /** Cursor's enterprise hooks.json. */
  cursorHooks: string;
  /** Codex's admin folder (requirements.toml, managed_config.toml). */
  codexAdmin: string;
}

export function realIo(): CliIo {
  return {
    out: (line) => void process.stdout.write(`${line}\n`),
    err: (line) => void process.stderr.write(`${line}\n`),
    env: process.env,
    platform: process.platform,
    cwd: process.cwd(),
    home: homedir(),
    interactive: Boolean(process.stdin.isTTY && process.stdout.isTTY),
    ask: async (question) => {
      const rl = createInterface({ input: process.stdin, output: process.stderr });
      try {
        return await rl.question(question);
      } finally {
        rl.close();
      }
    },
    readStdin: () => readAll(process.stdin, STDIN_LIMIT),
    execPath: process.execPath,
    clock: () => new Date(),
    uid: typeof process.getuid === "function" ? process.getuid() : null,
    pid: process.pid,
  };
}

/** A hook request is a few kilobytes; anything past this is refused, not buffered. */
export const STDIN_LIMIT = 8 * 1024 * 1024;

export async function readAll(stream: AsyncIterable<Buffer | string>, limit: number): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    const b = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
    size += b.length;
    if (size > limit) throw new Error(`stdin is over ${limit} bytes`);
    chunks.push(b);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** The protection report for a policy path, as the user running the CLI sees it. */
export function protectionFor(io: CliIo, policyPath: string, override: boolean): ProtectionReport {
  return io.protect ? io.protect(policyPath, override) : checkProtection(policyPath, { override, probes: io.probes, now: io.clock() });
}

export const EXIT = Object.freeze({ ok: 0, fail: 1, usage: 2, admin: 3 });

/** What a command produced: an exit code, the --json body and the text lines. */
export interface Outcome {
  code: number;
  data: Record<string, unknown>;
  text: string[];
}

export class CliError extends Error {
  constructor(
    message: string,
    readonly code: number = EXIT.fail,
    readonly data?: Record<string, unknown>
  ) {
    super(message);
    this.name = "CliError";
  }
}

/**
 * A typed confirmation. It needs a terminal on both ends: an agent's shell tool
 * normally has none, so it cannot answer. This is a speed bump, not a security
 * boundary (an agent that drives a pseudo-terminal gets past it; HARDENING.md).
 */
export async function confirmTyped(io: CliIo, what: string, expected: string): Promise<void> {
  if (!io.interactive) {
    throw new CliError(`${what}\nThis step asks a person to type ${JSON.stringify(expected)} at a terminal (stdin and stdout must both be a TTY). Run it yourself.`);
  }
  const answer = (await io.ask(`${what}\nType ${expected} to continue, anything else to stop: `)).trim();
  if (answer !== expected) throw new CliError("Stopped: the answer did not match. Nothing was changed.");
}

/** Shown wherever mcp-guard prints admin commands, when it runs as root. */
export function rootWarning(io: CliIo): string[] {
  if (io.uid !== 0) return [];
  return [
    "Warning: mcp-guard is running as root. It never needs root: it prints the admin commands for you to read and run.",
    "A copy of mcp-guard in a folder a user can write is that user's to change, so do not run it with sudo.",
  ];
}

export function errnoCode(e: unknown): string | undefined {
  return (e as NodeJS.ErrnoException | null)?.code;
}

/** A write the user lacks the rights for (or whose admin folder is missing). */
export function needsAdmin(e: unknown): boolean {
  const code = errnoCode(e);
  return code === "EACCES" || code === "EPERM" || code === "EROFS" || code === "ENOENT";
}
