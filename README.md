# @nightsquawktech/mcp-core

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/NightSquawk/mcp-core/badge)](https://scorecard.dev/viewer/?uri=github.com/NightSquawk/mcp-core)

Shared runtime for NightSquawk's catalog-backed [MCP](https://modelcontextprotocol.io) servers: a stdio bootstrap, the primitives used by the `list_endpoints` / `describe_endpoint` / `call_endpoint` tool pattern, and a guard that runs every tool call through one machine policy, with its `mcp-guard` CLI.

Used by:

- [@nightsquawktech/proxmox-mcp-server](https://github.com/NightSquawk/proxmox-mcp-server)
- [@nightsquawktech/appfolio-mcp-server](https://github.com/NightSquawk/appfolio-mcp-server)
- [@nightsquawktech/invoiceninja-mcp-server](https://github.com/NightSquawk/invoiceninja-mcp-server)

See the [mcp-servers](https://github.com/NightSquawk/mcp-servers) index for the full catalog.

## The catalog pattern

Instead of registering one MCP tool per API operation (which floods the model's context with dozens of tool definitions per server), each server generates an on-disk JSON catalog of its API at build time and exposes just three generic tools:

- `list_endpoints`: search and filter the catalog
- `describe_endpoint`: full parameter schema for one operation
- `call_endpoint`: execute an operation, with write operations gated

This package holds the parts of that pattern that are identical across servers. The list/describe/call tool factories themselves stay per-server: spec shapes and write-gate semantics differ too much to share.

## Install

```bash
npm install @nightsquawktech/mcp-core
```

Peer dependencies (bring your own versions): `@modelcontextprotocol/sdk` >=1.18.0 <2 and `zod` ^3.24. Node 20 or later.

## API

### Main entry: `@nightsquawktech/mcp-core`

```ts
import { createMcpServer, runStdioServer } from "@nightsquawktech/mcp-core";

const server = createMcpServer({ name: "my-server", version: "1.0.0" });
// ...register tools...
await runStdioServer(server, { banner: "my-server running on stdio" });
```

- `createMcpServer({ name, version })`: thin wrapper over the SDK's `McpServer`.
- `runStdioServer(server, { banner? })`: connects a stdio transport. The banner goes to stderr because stdout is reserved for the MCP protocol.

### Catalog entry: `@nightsquawktech/mcp-core/catalog`

```ts
import {
  createCatalogStore,
  RegisterTool,
  formatError,
  type ToolDefinition,
  type ToolResponse,
  type CatalogStore,
} from "@nightsquawktech/mcp-core/catalog";
```

- `createCatalogStore<I>(catalogDir, options?)`: cached loader for a catalog directory containing an aggregate `index.json` plus one JSON file per entry under a subdirectory (default `endpoints/`). Returns `{ index(), entry(id, subdir?), has(id, subdir?) }`. Entry ids are validated against `^[a-z0-9_]+$` to prevent path traversal.
- `RegisterTool(server, toolDefinition)`: registers a `ToolDefinition` with the SDK's `registerTool()`, under a single `{ params }` input schema, passing on the definition's `title`, `annotations` and `_meta` when it has them.
- `formatError(error)`: normalizes unknown thrown values into a readable string.
- `ToolDefinition<T>` / `ToolResponse<T>` / `CatalogStore<I>` / `CatalogStoreOptions`: the shared types.

### Path resolution rule

`createCatalogStore` never derives the catalog location from its own module path. The **server** resolves its catalog directory (relative to the server's own module location) and passes the absolute path in:

```ts
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const store = createCatalogStore<MyIndex>(join(here, "..", "catalog"));
```

This matters because once the loader lives in `node_modules/@nightsquawktech/mcp-core`, resolving from the library's own location would point at the wrong place. It compiles either way; it only fails at runtime.

### Guard entry: `@nightsquawktech/mcp-core/guard`

The guard runs every tool call through one policy before the provider sees it. Each operation has a tier, and the tiers map to four groups: `read`, `change`, `critical` and `spend`. A machine policy that only an admin can write turns groups on and sets limits and approvers. The guard records every non-read call (and reads, if the policy asks for them or limits them) in a hash-chained audit log, counts calls in a daily ledger, and has a kill switch that stops everything but `read`.

- `createGuard(...)`, `registerCatalogGroups(...)` and `guard.toolConfig(group)`: create the guard and register the group tools with their annotations and `_meta`.
- `buildManifest(...)`: the `dist/guard-manifest.json` that `mcp-guard harness` turns into client rules.
- `checkTiers(...)`: checks a server's `tiers.json` against its operations.
- `@nightsquawktech/mcp-core/guard/testing`: `runConformance(...)`, the suite every adopting server runs.

[docs/ADOPTING.md](docs/ADOPTING.md) covers adopting the guard in a server. [docs/HARDENING.md](docs/HARDENING.md) covers installing one on a machine: the protected policy, client rules, the sandbox profile and the kill switch.

## mcp-guard CLI

The package installs `mcp-guard`, which inspects and operates a guard install. It never elevates: where a step needs an admin, it prints the commands and exits 3.

| Command | What it does |
|---|---|
| `status [<server>]` | What the guard would enable for a server, and why each group is off, including whether the policy is protected. Without a server: the servers found. |
| `init <server>` | A starting policy, and the admin commands that install it. `--print` prints only the policy. |
| `canary add <server>` | Add decoy records to the policy as salted hashes, and print the admin commands that install it. Ids come from the arguments or stdin; the salt is `NST_MCP_CANARY_SALT`. |
| `kill`, `unkill` | Stop every group but `read`, or remove the manual kill marker. `kill --soft` trips your own state instead. |
| `reset` | Clear automatic kill-switch trips, and move an unreadable idempotency store aside. Refuses while an audit chain is broken. |
| `cancel` | Mark a pending or unknown call failed so a retry can run it, and stop its amount counting against the caps. Cancels nothing at the provider. |
| `manifest` | Check a guard manifest. |
| `verify <server>` | Pass, warn and fail checks of one install. `--strict` fails an unprotected policy. `--watch` reports changes to any client's MCP, hook or permission config since a baseline. |
| `harness <server>` | Client rules for Claude Code, Codex and Cursor from the server's manifest: `read` runs, `change` asks, `critical` and `spend` are denied. Optionally a permission hook, a sandbox profile and an MCP server allowlist. Prints what to install; writes nothing. |
| `hook` | The permission hook that `harness` installs. Clients run it. |

Every command takes `--json`. Exit codes: 0 ok, 1 failed or refused, 2 usage error, 3 an admin has to run the printed commands. `mcp-guard <command> --help` lists a command's options.

## Client enforcement checks

The guard relies on client behaviour that is partly undocumented, so these checks run against real clients and are recorded here. Run them again after client upgrades.

Last run: 2026-11-04 on Linux x86-64 (kernel 7.2, bubblewrap 0.13.0), against a toy MCP server with one tool per group:
- **Claude Code 2.1.317** in non-interactive sessions (`claude -p`, `bypassPermissions` requested). The rules were passed with `--settings` (command-line scope) in place of managed settings, which need an admin install; *flag scope* marks those results. *Prompt path* means Claude Code handed the call to the host's permission prompt handler (`--permission-prompt-tool`, the path SDK hosts use).
- **Codex 0.166.0** in `codex exec` sessions, without the user's `config.toml` (`--ignore-user-config`), with the harness keys passed as `-c` overrides. `codex exec` uses approval policy `never`, so a tool that asks is refused there.

| # | Client / mode | Check | Result |
|---|---|---|---|
| 1 | Claude Code, `bypassPermissions` | a `requiresUserInteraction` tool prompts | **Pass** (prompt path): the `critical` and `spend` tools went to the prompt handler; `read` ran without one. The terminal dialog itself is not yet observed. |
| 2 | same | `deny` on `<prefix>_spend` blocks | **Pass** (flag scope): denied tools are dropped from the session and never reach the server. |
| 3 | same | `ask` on `<prefix>_change` prompts | **Pass** (prompt path, flag scope): the `change` tool went to the prompt handler; `read` ran. |
| 4 | same | hook exit 2 blocks; a timeout with `onFailure: "block"` blocks | **Pass** (flag scope): exit 2, a missing hook script and a 3 s timeout all block. Without `onFailure`, a missing script fails open (the control). |
| 5 | same, `-p` | a `requiresUserInteraction` tool is denied, not hung | **Pass**: refused, not hung; the whole run took about 5 s. |
| 6 | T3 Code (Claude Code underneath) | rows 1-3 prompt in the T3 UI | Not run. Rows 1 and 3 show Claude Code handing these calls to the host's prompt handler; whether the T3 UI shows them is not yet observed. |
| 7 | Codex, `--dangerously-bypass-approvals-and-sandbox` | `approval_mode = "approve"` still prompts; `disabled_tools` hides | **Fails as written; harness changed.** `approve` means pre-approved: it ran even a destructive tool without asking, so harness gives it to read tools only. In this mode a `prompt` tool ran without asking. It did the same with `-s danger-full-access` alone, and with `--approve-for-me`, where Codex's automatic reviewer approved it. The `requirements.toml` floor now rules out both. `disabled_tools` held in every mode: the tools were gone, and calls by name failed. |
| 8 | Cursor | a `beforeMCPExecution` deny blocks | Not run (Cursor was not installed). |
| 12 | Linux workstation with passwordless sudo and the `docker` and `libvirt` groups | `mcp-guard status` reports the policy unprotected and names all three | **Pass**. |
| 13 | Windows workstation | `mcp-guard status` reports the admin and UAC state; an elevated session reads unprotected | Not run. |
| 14 | Claude Code sandbox profile, Linux | `curl` to an outside host fails; `/var/run/docker.sock` is unreachable; `dangerouslyDisableSandbox` is ignored; another process's `/proc/<pid>/environ` is unreadable | **Pass** (flag scope). The network is denied, Docker's socket cannot be reached, and the unsandboxed retry is ignored. Other processes are invisible inside the sandbox (their `/proc/<pid>` does not exist there), and Claude Code's Bash and Read tools refuse `/proc/*/environ` paths before that. |
| 15 | same | Read/Edit/Write deny on `.mcp.json` and Edit/Write deny on install paths hold in `bypassPermissions`; an added MCP server is blocked | **Pass** (flag scope), with `allowedMcpServers` in place of `managed-mcp.json`. The file tools are denied in `bypassPermissions`. Shell reads and writes of `.mcp.json` fail, and shell writes to the install path hit a read-only file system. An added stdio server is "blocked by enterprise policy". With the full profile, `bypassPermissions` is refused and the session runs in default mode. |
| 17 | Codex, `workspace-write` | whether stdio MCP servers run inside Codex's sandbox | **Answered: they do not.** A stdio server wrote outside the workspace and reached the network; it had no seccomp filter and ran as a direct child of `codex`. The model's shell commands in the same session could not write outside the workspace or resolve a host name. |

The `mcp-guard hook` alone, with no rules, blocked the `critical` and `spend` tools in `bypassPermissions` while `read` and `change` ran. With the full `harness --claude --hook` output, `read` ran, `change` was refused (a `-p` session has no one to ask), and the denied tools were not in the session. Rows 9-11 (URL elicitation, Duo) and 16 (credential broker) belong to later releases.

Found in these runs, and now handled by `harness`. [HARDENING.md](docs/HARDENING.md) describes them in section 6 (the Claude Code sandbox profile) and section 4 (Codex):
- `**/` rules match only under the folder Claude Code starts in, so `~/.mcp.json` is listed by path.
- `**/` Read rules reach shell commands, checked again before each command. `**/` Edit rules reach Claude's file tools only. So the project hook and settings files get Read rules too: nothing else keeps shell commands from writing them.
- The project's own `.claude/settings.json` is read-only to shell commands even without a rule.
- Codex's full-access sandbox and its automatic reviewer both let tools that ask run without a person. The `requirements.toml` floor rules them out. It no longer rules out approval policy `never`, which refuses those tools and is the policy `codex exec` uses.

## License

Licensed under the [GNU AGPL v3.0](./LICENSE). Free for personal and open-source use.

Organizations that cannot comply with the AGPL can purchase a commercial license. See [COMMERCIAL.md](./COMMERCIAL.md) or contact hello@nightsquawk.tech.
