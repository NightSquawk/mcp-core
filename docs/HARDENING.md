# Hardening an mcp-core guard install

This is the install and hardening procedure for machines that run MCP servers built on
`@nightsquawktech/mcp-core` with the guard. It covers the policy, the OS protection the guard
checks for, client rules, the cross-server taint hooks, the operator sandbox profile, the server
allowlist, the config watch, the kill switch, and supply chain. The Duo approver comes later
(section 11).

Steps marked **UNVERIFIED** follow the vendors' docs but have not been run end to end yet. The
harness verification matrix in the README records what has been confirmed, per client version.

## 0. What each layer stops

The guard inside each server is the boundary: it refuses whatever the server's policy does not
allow, whatever the client decides. Everything else here either keeps the agent from changing
the guard's inputs, or closes a path around the server.

| Layer | Stops | Does not stop | Section |
|---|---|---|---|
| Guard in each server | calls its policy does not allow; approvals, limits, kill switch, audit | an agent that can change the policy, the server's code or the server's env | 2 |
| Policy protection | the agent's OS user changing the policy or the kill marker | remote paths to admin (SSH keys, RMM keys); servers installed where the agent can write | 3 |
| Client rules | the client calling a denied tool, in every permission mode | anything outside the client: scripts, `curl` | 4 |
| Taint hooks | a call that can send data out, after the session read text from outside parties | a deliberate agent: outside the sandbox it can delete its own markers | 5 |
| Sandbox profile | shell commands reaching a provider API or reading credential files | MCP servers, hooks and file tools (they run outside it); native Windows | 6 |
| Server allowlist | the client starting an MCP server you did not list | a listed server started with other env (only `managed-mcp.json` pins env) | 7 |
| Config watch | a silent change to MCP, hook or permission config | a change made and reverted between runs; a watch the agent can switch off | 8 |
| Kill switch and revocation | further calls after an incident | a provider key the agent already copied, until you revoke it | 9 |
| Supply chain | a bad release reaching your machine the day it ships | a compromised build with valid provenance | 10 |

`mcp-guard` never writes client config and never elevates. For admin-owned files it prints the
commands (exit code 3) and you run them yourself, in your own terminal, after reading them. On
Windows, where any user may create folders in ProgramData, the commands first make Administrators
own the client's folder (`%ProgramData%\Cursor`, `C:\Program Files\ClaudeCode`) and each folder below
it, and write nothing through a junction or symbolic link. A file already there is deleted and
written again: whoever made it may still hold it open.
**Never run `sudo mcp-guard`** or an elevated `mcp-guard`: it reports what the user running it
can do, so as root it checks root's view, and files it writes into a state folder become root's.
It warns when it runs as root.

## 1. Install mcp-guard and the servers where only an admin can write

If the agent's user can edit a server's code, the hook script or the Node binary that runs them,
it can switch the guard off. Install all of them where only an admin can write, at pinned versions.

**Linux and macOS.** Use a Node whose global prefix is root-owned (a distribution package, or
the official installer). Node from nvm, fnm, volta, asdf or a per-user Homebrew lives in a
folder you own, so it does not qualify.

```sh
npm prefix -g                         # must be root-owned, such as /usr or /usr/local
sudo npm install -g --ignore-scripts @nightsquawktech/mcp-core@<x.y.z>
sudo npm install -g --ignore-scripts <server package>@<x.y.z>
npm root -g                           # the hook script is <this>/@nightsquawktech/mcp-core/dist/cli/index.js
```

`--ignore-scripts` keeps package install scripts from running as root. mcp-core and its peer
dependencies need none.

**Windows (UNVERIFIED).** Install Node with the official MSI (it goes to `C:\Program Files\nodejs`).
npm's default global prefix, `%APPDATA%\npm`, is in your profile, so the agent's user can change
anything installed there. From an elevated PowerShell:

```powershell
npm install -g --ignore-scripts --prefix "$env:ProgramFiles\NightSquawk\mcp-guard" '@nightsquawktech/mcp-core@<x.y.z>'
# hook script: $env:ProgramFiles\NightSquawk\mcp-guard\node_modules\@nightsquawktech\mcp-core\dist\cli\index.js
```

Folders under `C:\Program Files` let Users read and run, not write. A folder on another drive
or a new folder under `C:\ProgramData` often lets every user write, so don't use those.

**Check.** `mcp-guard harness ... --hook` warns when the hook would run Node or mcp-guard from a
file someone other than root could change. On Linux and macOS it looks each file up one name at a
time and checks the file and every folder and link on the way, however many links deep. On Windows
it only flags paths under your home folder. Run harness with the admin-owned Node and script, or pass `--hook-script`:

```sh
/usr/bin/node "$(npm root -g)/@nightsquawktech/mcp-core/dist/cli/index.js" harness <server> --claude --hook
```

## 2. Write the policy

Each server reads one policy file:

| OS | Path |
|---|---|
| Linux, macOS | `/etc/nightsquawk-mcp/<server>/policy.json` |
| Windows | `%ProgramData%\NightSquawk\mcp\<server>\policy.json` |

`NST_MCP_POLICY_DIR` and `NST_MCP_STATE_DIR` move these folders for tests. A policy read through
`NST_MCP_POLICY_DIR` never counts as protected, so an agent that points a server's env at a policy
of its own gets reads and changes at most.

```sh
mcp-guard init <server>       # a read-only starter policy, and the admin commands that install it
mcp-guard init <server> --print   # the policy only
```

`init` prints the commands and exits 3. Read them, then run them in your own terminal.
- **Linux:** they create root-owned folders (0755) and the file (0644) through `sudo tee`. Edit
  the policy later with `sudoedit`: your editor runs as you, and sudo writes the file as root.
- **Windows (UNVERIFIED):** they first take over the folders, one at a time with `icacls`:
  Administrators own `NightSquawk`, the policy root and the server's folder. The policy root stops
  inheriting from ProgramData (where Users may create folders): only SYSTEM and Administrators get
  full control, and Users read. `NightSquawk` keeps ProgramData's permissions, for other software's
  folders. Then they write the file, and write nothing if one of those folders or the file is a
  junction or symbolic link. They never change a folder's contents recursively: that could follow a
  junction planted inside. Edit the policy from an elevated editor.

Paste the commands as printed. A path holding a typographic single quote (`‘ ’ ‚ ‛`) is quoted for
PowerShell, which treats those as quote characters too. A chat client or word processor that
"smartens" quotes in transit breaks the commands, so copy straight from the terminal.

Then, **as the agent's user**:

```sh
mcp-guard status <server>     # each group per mode (live, sandbox, none), and why it is off
mcp-guard verify <server> --strict
```

The starter enables `read` only. Enable `change`, then `critical` and `spend`, one at a time, and
only after section 3 passes. The server's README lists its own policy keys. `status` names keys the
base schema does not know, which catches typos.

**Canaries (optional).** A canary is a decoy record that no real task touches, such as a VM, a
contact or a counterparty with a plausible name. A change that targets one is refused and trips
the kill switch (section 9); a read of one is written to the audit log as a `canary_read` alert.
The policy lists only salted hashes of the ids, so it does not say which records are decoys. Put a
random salt (for example from `openssl rand -hex 32`) in the server's environment as
`NST_MCP_CANARY_SALT`, then, with the same salt in your shell:

```sh
read -rs NST_MCP_CANARY_SALT && export NST_MCP_CANARY_SALT   # typed, so not in shell history
mcp-guard canary add <server>     # type one id per line, then Ctrl-D; prints the admin commands
```

In PowerShell 7, set the salt with `$env:NST_MCP_CANARY_SALT = Read-Host -MaskInput 'Salt'`, and
end the ids with Ctrl-Z and Enter. Typing the ids keeps them out of shell history and off the disk;
ids passed as arguments work too. Give each id exactly as it appears in the API (a VM id as
`100`): the match is exact, case included. The commands rewrite the policy with the hashes added
and the rest unchanged. While the policy lists canaries and the server has no salt, every call but
reads is refused. Canaries are an alarm, not a boundary: an agent that can read the salt can work
out which records are decoys.

## 3. Make the policy protected

At start, each server checks whether its policy is **protected**. Both parts below must pass.
While it is unprotected, the policy can enable `read` and `change` only: `critical` and `spend` stay
off. The one exception is a server reporting sandbox mode, such as a provider test key.

**Part 1: the agent's OS user cannot change the policy.**
- Linux, macOS: the file is a regular file (not a link), owned by root, with no group or other
  write bit. So is every folder the path passes through, looked up one name at a time the way the
  system does it: each folder above the file and, where the path goes through symlinks, the folder
  holding each link and every folder it leads to, however many links deep. Inside a user namespace
  (rootless containers, `unshare -Ur`) owners can be forged, so it fails there.
- Windows: opening the file for writing fails, and creating a probe file fails in each folder from
  the policy's folder up to the policy root, `%ProgramData%\NightSquawk\mcp`. The file, those
  folders and every folder above them up to the drive root (`NightSquawk`, `%ProgramData%` and `C:\`)
  are owned by Administrators, SYSTEM or TrustedInstaller, and none of them is a junction or symbolic
  link. A ProgramData moved to another drive through a junction fails this.

**Part 2: the agent's OS user cannot become admin without a factor it lacks.**

| OS | Fails when | Fix |
|---|---|---|
| Linux | `sudo -n true` or `doas -n true` succeeds (NOPASSWD, or a cached credential), or `sudo -n -l` lists a NOPASSWD rule | Remove the NOPASSWD rule. Keep sudo's default `timestamp_type=tty`, so a sudo you ran in another terminal does not carry over to an agent's shell; never set `timestamp_type=global` or `!tty_tickets`. Optionally put MFA on sudo (pam_duo). |
| Linux | doas has a `permit nopass` rule for the user, its uid, or one of its groups, even for a single command; or the check cannot read or parse the doas configuration (`/etc/doas.conf`, Alpine's `/etc/doas.d/*.conf`, and the BSD, MacPorts and Homebrew paths) | Remove the rule; a `deny` rule after it does not count, so remove the `permit nopass` itself. doas cannot list one user's rules, so the check reads the files. If they are mode 0400 or 0600, either make them readable (`chmod 0644`; doas requires only that root owns them and nobody else can write them), or let only admins run doas (`chgrp wheel` and `chmod 4750` on the doas binary). |
| Linux | the user is in `docker`, `lxd`, `incus-admin`, `libvirt` or `disk` (each is root-equivalent) | Take the user out of them. Use rootless Docker or Podman, and run libvirt through `sudo`. |
| Windows | the process is elevated | Never run the agent, its terminal or its client elevated. |
| Windows | UAC is off (`EnableLUA=0`) | Turn UAC on. |
| Windows | the user is an administrator and elevation asks for no credential: `ConsentPromptBehaviorAdmin` other than 1 or 3, or `PromptOnSecureDesktop=0` | Best: Windows 11 Administrator protection on a current build. Otherwise use a standard daily account plus a separate admin account, or set a credential prompt (`ConsentPromptBehaviorAdmin=1`, `PromptOnSecureDesktop=1`). The default (5) auto-elevates Windows binaries, which is what most UAC bypasses use. |

A sudo ticket belongs to a terminal, or, where there is none, to the parent process. So:
- Run `sudo -k` before you start an agent in a terminal where you used sudo. The agent's commands
  may share that terminal, and with it the ticket. The check at server start sees a ticket only
  while it is still valid.
- Don't run `sudo` from inside an agent session, such as through a client's shell escape. The
  agent's later commands can share its parent process.
- Run `sudo -k` when you finish admin work.

**Paths to admin that the check cannot see.** The agent's user must not be able to read any of
these. List them for each machine during install:
- SSH keys, or keys in a reachable agent, that log in as root or an admin account, including
  Tailscale SSH rules that admit root;
- remote management API keys (RMM, MDM, configuration management) that can run scripts, which
  usually run as root or SYSTEM;
- cloud or hypervisor API tokens that can open a console, reset passwords or mount disks;
- password manager or secret store sessions that hold admin credentials.

Both parts protect the policy, not the server's code. That is why section 1 matters. A hard
guarantee against a deliberate agent needs the credential broker (plan section 7.7), which runs
somewhere the agent cannot administer.

## 4. Client rules (`mcp-guard harness`)

`harness` turns the server's guard manifest into rules for one client:
- `read` runs;
- `change` asks;
- `critical` and `spend` are denied. `--allow-critical` and `--allow-spend` make them ask instead,
  and the guard's own approval still applies.

It reads the manifest from `--package <dir>` (`<dir>/dist/guard-manifest.json`) or `--manifest <file>`.
Pass `--name` when your MCP config calls the server something other than its own name.

These rules are a second fence. Run `harness` again whenever the server adds, renames or regroups
tools, which is any new manifest version.

### Claude Code

```sh
mcp-guard harness <server> --claude --hook [--mcp-command '["node","/abs/path/dist/index.js"]']
```

- **Managed settings drop-in.** `managed-settings.d/50-mcp-guard-<server>.json` goes in Claude
  Code's managed folder: `/etc/claude-code` on Linux, `/Library/Application Support/ClaudeCode` on
  macOS, `C:\Program Files\ClaudeCode` on Windows. Deny rules block in every permission mode, and
  ask rules still prompt in `bypassPermissions`. Matrix rows 1 to 3 confirm this per Claude Code version.
- **The hook (`--hook`).** It adds PreToolUse and PostToolUse hooks with `onFailure: "block"`, which
  needs Claude Code v2.1.295 or later: older versions run the call when a hook fails. The hook reads
  `harness-claude.json`, which harness also prints for the admin to install next to the policy. It
  denies the server's tools that are not in the manifest, so a tool a server update adds is refused
  until you run harness again.
- **The admin console.** Files in `managed-settings.d` merge with each other. But Claude Code
  ignores the file-based managed policy when policy also comes from the admin console or MDM,
  unless `managedSourcesBehavior` is `"merge"` (v2.1.242 or later). Check this before relying on
  the drop-in.
- **Non-interactive sessions (`-p`).** An ask is denied there (matrix row 5), so a `change` tool
  cannot run in an unattended session unless you allow it.

### Codex

```sh
mcp-guard harness <server> --codex
```

It prints two fragments:
- **`~/.codex/config.toml`, for you to merge:** `enabled_tools` lists every tool this run allows or
  asks for, so a tool the server adds later stays hidden until you run harness again;
  `disabled_tools` removes the denied groups' tools. This file is yours, so the agent's user can
  change it too.
- **`requirements.toml`, an admin floor** (`/etc/codex`; `%ProgramData%\OpenAI\Codex` on
  Windows): it rules out the full-access sandbox (and with it `--yolo`) and Codex's automatic
  reviewer for everyone. On Windows any user may create folders in ProgramData, so check that
  Administrators own `OpenAI`, `Codex` and the file, and that Users can only read `Codex` and the
  file. The floor is UNVERIFIED until an admin installs it: then
  `codex exec -s danger-full-access` and `codex exec --approve-for-me` should be refused.
  `allowed_approvals_reviewers` is in Codex 0.166.0's requirements keys, but no Codex doc
  describes it yet.

What the approval modes do, tested with Codex 0.166.0 in `codex exec`:
- **`approve` runs a tool without asking, even a destructive one.** So harness gives it to read
  tools only.
- **`prompt` asks for every call, even a read tool's.** Unset, `auto` and `writes` ask for tools
  that are not marked read-only.
- **When no one can answer** (approval policy `never`, which `codex exec` uses), a tool that asks is
  refused. The floor leaves `never` allowed for that reason.
- **In the full-access sandbox, or with `--approve-for-me`,** a tool that asks runs without asking:
  `-s danger-full-access` alone did it, and so did Codex's automatic reviewer. Hence the floor.
- **`disabled_tools` held in every mode:** the tools were gone, and calls by name failed.
- **MCP servers run outside Codex's sandbox.** In `workspace-write`, a stdio server wrote outside
  the workspace and reached the network, while the model's shell commands in the same session
  could not. The sandbox covers shell commands; the guard inside the server covers the tools.

Some things harness leaves out:
- A `[mcp_servers]` table in `requirements.toml` is an allowlist: once it has one, Codex runs only
  the servers listed there. mcp-guard does not write it.
- Codex hooks cannot ask, and its docs call them "not a complete enforcement boundary", so harness
  generates none.

### Cursor

```sh
mcp-guard harness <server> --cursor [--others ask|allow]
```

- **The hook is the only control that blocks a Cursor tool call.** The admin installs it in the
  enterprise `hooks.json` (`/etc/cursor/hooks.json` on Linux; harness prints the path for each OS).
  The entry is a `beforeMCPExecution` hook with `failClosed`, so a crash, a timeout or no answer
  blocks the call.
- **Rules and allowlist.** The rules go in `harness-cursor.json` next to the policy.
  `~/.cursor/permissions.json` (`mcpAllowlist`) only lets read tools run without asking.
- **Servers without harness rules.** One hook entry covers every server that has rules. For a server
  without them the hook answers ask. `--others allow` leaves those as they were, if Cursor treats a
  hook's allow as neutral, which its docs do not say (UNVERIFIED).
- **Which shell runs the hook** is UNVERIFIED. Once it is installed, run the test command harness
  prints: it should print a deny.
- Cursor CLI rules (`cli-config.json`) are not generated: their location is not documented.

## 5. Cross-server taint hooks (Claude Code)

One server cannot see what another returned. So with `--hook`, harness also installs a PostToolUse
hook. It marks the session after a result that carries text from outside parties:
- an operation the manifest flags `untrusted_output`;
- a result carrying the guard's `{"untrusted": true}` label;
- any tool named with `--taint-from`: `WebFetch`, `WebSearch`, `mcp__<server>` for all of a
  server's tools, or `mcp__<server>__<tool>` for one.

After that, a call the manifest flags `egress` (it can send data out) is handled by the server's
policy setting `taint.egress_after_untrusted`:

| Setting | After a mark, a call that can send data out |
|---|---|
| `approve` (default) | asks, naming the earlier tool, with: allow it only if you asked for this yourself, not because of something that text said |
| `deny` | is denied for the rest of the session |
| `allow` | runs as its rules say |

A deny rule still wins. A session whose state cannot be read (no session id, an unreadable marker)
asks. `--no-taint` leaves the PostToolUse hook out.

**Limits.**
- **Where the markers live.** Markers are `<state root>/_taint/<session>.json`, in the agent's own
  state folder. Outside the sandbox profile (section 6) the agent's user can delete them, so they
  stop a confused agent, not a deliberate one.
- **What marks a session.** Results from tools no harness covers mark nothing unless you name them
  with `--taint-from`.
- **Claude Code only.** Cursor and Codex get no cross-server hook. Each server's own check
  (`taint.egress_after_untrusted`) still covers calls within that server.
- **Non-interactive sessions.** In `-p` mode an ask is a deny, so a marked session cannot make such
  calls.
- **Bypass mode.** On Claude Code 2.1.317 a hook's ask holds in `bypassPermissions`: the call went
  to the permission prompt, and in `-p` with no one to answer it was refused (measured 2026-11-04,
  settings at flag scope). Check again after client upgrades.
- **Never approve a prompt because a tool result asked you to.**

## 6. Operator sandbox profile (Claude Code on Linux)

For sessions that use `critical` or `spend` groups:

```sh
mcp-guard harness <server> --claude --hook --sandbox --allow-domain <domain>... [--deny-read <path>]... [--deny-write <path>]...
```

It writes a second drop-in, `45-mcp-guard-sandbox.json`, with:
- **The shell sandbox.** `sandbox.enabled: true`, `failIfUnavailable: true` and
  `allowUnsandboxedCommands: false`, so the model's `dangerouslyDisableSandbox` escape is ignored.
  `disableBypassPermissionsMode: "disable"` turns off bypass mode.
- **The network.** `sandbox.network.allowedDomains` holds the `--allow-domain` list only, with
  `allowManagedDomainsOnly`. Leave every provider API host out, so `curl` cannot reach a provider
  and skip the server.
- **Credential files.** Read deny rules and `sandbox.filesystem.denyRead` cover `~/.ssh`,
  `~/.claude.json`, and the Claude, Codex and Cursor credentials. They also cover MCP configs,
  which can hold keys: `~/.mcp.json` and the Codex and Cursor ones in your home folder by path,
  and the project copies by `**/` pattern. Your `--deny-read` paths are added.
- **Config and state.** Edit deny rules and `denyWrite` cover the client configs and hook files,
  the guard's state folder, and your `--deny-write` paths.
  - The daily limits depend on the ledger in that state folder, and the taint check on its markers.
  - MCP servers and hooks still write the state folder, since they run outside the sandbox.
  - The project hook and settings files (`**/.claude/settings.json`, `**/.codex/hooks.json`,
    `**/.cursor/hooks.json` and the like) get Read deny rules too. Hooks run outside the sandbox,
    and only a `**/` Read rule keeps shell commands from writing these files (see the limits
    below). Claude's file tools cannot read them either in these sessions.

**Limits.**
- **What runs outside the sandbox.** The sandbox covers shell commands only. MCP servers, hooks and
  Claude's own file tools run outside it. The Read and Edit deny rules cover the file tools, and
  some of them reach shell commands as well (next item). Neither covers a script that an MCP
  server or a hook runs.
- **How rules reach shell commands.** These held in testing with Claude Code 2.1.317 on Linux.
  Check them again when Claude Code changes:
  - **Plain paths** reach shell commands, whether they are in the rules or in the sandbox lists.
    A denied read fails, and a denied write hits a read-only file system.
  - **`**/` Read rules** reach shell commands too. Claude Code matches them again before each
    command, so a file that the same command creates is not covered. A matching file can be
    neither read nor written.
  - **`**/` Edit rules** cover Claude's file tools only, at any depth. A `**/` pattern placed in
    `sandbox.filesystem.denyWrite` itself did nothing: shell commands could still write the
    matching files. Name such files by path with `--deny-write`, or give the pattern to
    `--deny-read` as well.
  - **`**/` patterns match only under the folder Claude Code starts in**, for the file tools and
    the shell alike. A `.mcp.json` in another project, or anywhere else outside that folder,
    needs a `~/` or `//` path.
  - **The project's own `.claude/settings.json`** is read-only to shell commands even without a
    rule. Nested copies, and the Codex and Cursor hook files, are not.
- **What it breaks.** Bubblewrap sets no-new-privileges, so `sudo` cannot work inside it. Sessions
  that need SSH or a password manager CLI break too, so this is a profile for some sessions, not
  the default.
- **Native Windows has no sandbox.**
- **One file per machine.** `45-mcp-guard-sandbox.json` serves the whole machine, and each
  `--sandbox` run replaces it. Give every run the same `--deny-read`, `--deny-write` and
  `--allow-domain` options.

## 7. Pin the MCP server set

The guard runs inside the server, so a client that starts another server, or the same server with
other code, goes around it.

**`--mcp-command` (Claude Code).** The server's drop-in gets an `allowedMcpServers` entry with the
exact command and args, plus `allowManagedMcpServersOnly: true`:
- **Exact match.** Claude Code starts a stdio server only when its command and args match an
  entry exactly, in order. Once any such entry exists, every stdio server needs one. Run
  harness with `--mcp-command` for each server, or list the others in another
  `managed-settings.d` file: the lists combine.
- **What else it blocks.** Remote servers, plugin servers and claude.ai connectors are blocked
  too, unless an entry admits them: a `serverUrl` entry, or a `serverName` entry while the list
  has no `serverUrl` entries. These are exempt from the allowlist:
  - built-in servers (the IDE server, for one);
  - `managedMcpServers` entries;
  - servers defined in `managed-mcp.json` whose entry holds no `${VAR}` outside `env`.
- **The lock.** `allowManagedMcpServersOnly` makes Claude Code ignore allowlists in user, project
  and local settings, for every user of the machine. `deniedMcpServers` always wins.
- **Env is not compared.** The same command with other environment variables still matches.
  Some of them load other code into the server (`NODE_OPTIONS`, for one).
- **Use literal paths.** `${VAR}` in an entry expands from the environment Claude Code starts
  with, so the entry can mean another path under another environment.
- **Managed sources.** Across MDM, file and console sources, `allowedMcpServers` is taken whole
  from the highest-ranked source.

**`managed-mcp.json`** is the only way to pin env. It takes exclusive control of MCP for every user
of the machine and holds each server's whole entry, env included. So it suits servers whose entry
holds no secret, such as a launcher that reads its key itself. mcp-guard does not write it.

**Codex:** a `[mcp_servers]` table in `requirements.toml` (section 4).

**Third-party servers:** scan them (for example with Cisco's MCP Scanner) before you add them.

## 8. Verify and watch

```sh
mcp-guard verify <server> [--strict] [--package <dir> | --manifest <file>] [--tiers <tiers.json> --operations <openapi.json>]
```

Read-only. Exits 1 when any check fails; `--strict` also fails an unprotected policy.

| Check | Fails or warns when |
|---|---|
| `policy` | the policy is rejected (the server then runs read-only); warns when there is no file |
| `protection` | section 3 does not pass (warn; fail with `--strict`) |
| `effective` | (informational) the groups on per mode |
| `manifest` | the manifest is invalid or is for another server |
| `tiers` | an operation in the OpenAPI document has no known tier (with `--tiers`/`--operations`) |
| `kill` | the kill marker is set or unreadable, or there are automatic trips |
| `audit` | an audit hash chain is broken (the server then trips its kill switch at start) |
| `ledger` | the ledger is not valid JSON (the guard rebuilds it from the audit log) |
| `idempotency` | the idempotency store cannot be read |
| `state-permissions` | other users can read or change the state folder (POSIX; the guard writes 0700 and 0600) |

**Config watch.**

```sh
mcp-guard verify --watch [--project <dir>]... [--baseline <file>] [--accept]
```

It reads the client configs that can add an MCP server, a hook or a permission rule:
- Claude Code: `~/.claude.json`, each `~/.claude*` profile's settings and state, the managed
  settings and drop-ins, and `managed-mcp.json`;
- Cursor: `~/.cursor/` `mcp.json`, `hooks.json`, `permissions.json` and `cli-config.json`, and the
  enterprise `hooks.json`;
- Codex: `config.toml`, `hooks.json`, `requirements.toml` and `managed_config.toml`;
- Claude Desktop: `claude_desktop_config.json`;
- `.mcp.json` and the `.claude/`, `.cursor/` and `.codex/` configs in the working folder and in each
  `--project`.

It exits 0 when nothing changed and 1 when something did. The report names files, keys and counts
only: the baseline holds a hash per key, never a value. The files themselves hold secrets, so look
at a change in the file, don't paste it anywhere, then run `--accept`.

- **Where the baseline lives.** It defaults to the agent's own state folder, where anything
  running as that user can rewrite it. Keep it in an admin-owned file with `--baseline`. With an
  admin-owned baseline, `--accept` prints the commands that update it (exit 3).
- **How to run it.** Run it on a timer the agent cannot switch off, and alert on a non-zero exit.
  On Linux that means a system unit (not a `systemctl --user` one) running as the agent's user,
  because it reads that user's home. On Windows it means a scheduled task an admin creates
  (UNVERIFIED: check that the agent's user cannot change or delete the task).
- **What it cannot see.** A change made and reverted between two runs.

## 9. Kill switch and revocation

| Command | Effect |
|---|---|
| `mcp-guard kill <server>` / `kill --all` `[--note <text>]` | Writes the admin marker (`KILL`) next to the policy, or prints the commands to (exit 3). While it is set, every call but `read` is refused. Only an admin can clear it. |
| `mcp-guard kill <server> --soft` | Trips the kill switch in your own state folder. Instant, but anything running as you can clear it. |
| `mcp-guard unkill <server>` / `unkill --all` | Removes the manual marker. Asks you to type the server name, or `all`, at a terminal. |
| `mcp-guard reset <server>` | Clears automatic trips and moves an unreadable idempotency store aside. Asks first. Does not clear the manual marker. |
| `mcp-guard cancel <key> [--server <server>]` | Marks a pending or unknown call failed, so a retry can run it, and releases its ledger reservation so its amount stops counting against the caps. Cancels nothing at the provider. |
| `mcp-guard status [<server>]` | Shows the markers, trips and audit totals. |

The guard trips the kill switch by itself on any of these:
- a broken audit chain, found at start;
- an audit log it cannot write;
- a canary hit (section 2);
- a call made under the external approver that the provider did not hold for a human;
- the denial breaker: two human denials within 30 minutes.

Without the broker, an automatic trip lives in the agent's own state folder.

**Revocation list.** Killing the server does not revoke a provider key the agent already copied
(OWASP ASI10). Keep this table for each machine, in the admin's records, not in a place the agent
reads:

| Server | Provider credential | Where to revoke it | Who can | How to issue a new one | Last tested |
|---|---|---|---|---|---|
| `<server>` | `<key name, never the key>` | `<dashboard or API>` | `<role>` | `<steps>` | `<date>` |

Test one revocation each quarter.

## 10. Supply chain

- **Install at pinned versions** (`npm install -g <pkg>@x.y.z`), never `npm update -g` or `npx -y`
  of a moving version.
- **Set a minimum release age,** so a new release waits a few days before it can install: npm
  `min-release-age` (days, npm 11.10 or later), or pnpm `minimumReleaseAge` (minutes).
- **Check signatures and provenance** after install with `npm audit signatures`. Provenance shows
  where a package was built, not that the build was clean.
- **Gate releases.** This package's `publish.yml` job runs in the `npm-publish` GitHub
  environment. Create it before the first release, because GitHub creates a missing environment
  on first use with no protection rules. Give it a required reviewer, turn on "prevent
  self-review", limit deployments to `v*` tags, and name the environment in the package's npm
  trusted publisher settings. This holds only while no agent has a token that can approve the
  deployment. An agent using an admin's `gh` login can approve its own release unless a second
  person reviews.
- **No install scripts where a publish token can be minted.** The publish job runs
  `npm ci --ignore-scripts`, so a dependency's install script never runs next to the OIDC token.
  The same goes for any server's own publish workflow.

## 11. Duo approver (later)

Not built yet. When it ships, its setup goes here:
- one Auth API application, its keys in a vault no agent can read;
- a separate Duo user per approver, used only for approvals;
- Verified Push required, and every other method off;
- "Frequent attempts" on;
- NTP on every machine that calls Duo;
- no Admin API keys on any machine an agent runs on.

## Install checklist

1. mcp-core, the servers and Node are installed at pinned versions where only an admin can write (section 1).
2. `mcp-guard init <server>` was run, and you read and ran its commands (section 2).
3. Run as the agent's user, `mcp-guard status <server>` shows "protected" (section 3).
4. The paths to admin the check cannot see are listed and out of the agent's reach (section 3).
5. `mcp-guard harness` was run for each client in use, and you read and installed its files. Harness gave no warnings, or you understand each one (section 4).
6. `--hook` and taint are on for Claude Code; `--taint-from` names the web and mail tools in use (section 5).
7. Sessions that use `critical` or `spend` use the sandbox profile (section 6).
8. `--mcp-command` lists every stdio server (or `managed-mcp.json` is in place), and the remote servers you need have `serverUrl` entries (section 7).
9. `mcp-guard verify <server> --strict` passes, and `verify --watch` runs on a timer the agent cannot switch off, with an admin-owned baseline (section 8).
10. The revocation list is filled in and was tested (section 9).
11. A minimum release age is set, and `npm audit signatures` passes (section 10).
