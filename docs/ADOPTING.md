# Adopting the guard in a server

What a server built on `@nightsquawktech/mcp-core` does to run its tools through the guard
(`@nightsquawktech/mcp-core/guard`). [HARDENING.md](HARDENING.md) covers installing the result on
a machine.

## 1. Tier every operation

Give each provider operation one tier. The tier decides its group, and the group decides its tool
and whether the policy lets it run:

| Tier | Group | Default |
|---|---|---|
| `read` | read | on |
| `reducing`, `write`, `sandbox` | change | off |
| `destructive`, `sensitive` | critical | off |
| `spend` | spend | off |
| `blocked` | none: never registered, never callable | |

Without protection (HARDENING.md section 3), a policy can turn on `read` and `change` only.

Add flags where they apply:
- `untrusted_output`: returns text other people wrote, such as CRM notes, emails or payment
  descriptions;
- `egress`: sends data out, such as a message, an email, a webhook or a share link;
- `idempotencyKey`: the provider honours an idempotency key.

Keep the tiers in a `tiers.json` the build checks against the provider's OpenAPI document, and tier
by what the call can do, not by its HTTP method. A non-GET read needs a `read_reason` in `tiers.json`.

## 2. Create the guard and register the tools

- `createGuard({ server, version, policySchema, mode, secrets, ... })`:
  - `policySchema` is `basePolicySchema.extend({...})` with the server's own keys;
  - `mode` is `"sandbox"` for test keys and `"live"` for live ones; when the server cannot tell,
    leave it at the default (`none`), which counts as live: every group but `read` then needs
    `environment.allow_live` in the policy;
  - `secrets` returns the API keys to mask everywhere;
  - `redactKeys` names the server's own credential parameters that the built-in list (`password`,
    `secret`, `token`, `api_key` and similar) misses, so their values are masked in dry runs,
    pre-images and errors, at any depth. A name that also appears outside requests, such as a
    response wrapper called `data`, goes in `redactRequestKeys` instead: it is masked only in the
    request a dry run shows and a pre-image stores. `notSecretKeys` takes exact names that only
    look like credentials, such as `lock-token` or a list of token ids called `tokens`, out of the
    built-in rule;
  - `serverCheck(group, policy)` turns a group off for a reason only the server knows, such as a
    live key it has not verified yet: return `{ reason_code, reason, how_to_enable }`, or `null`
    to leave the group as it is. A server whose provider cannot hold a call for a person to approve
    should turn off every group whose approval names `external`, so its tool is not offered. The
    guard refuses such a call anyway (`approver_unavailable`) when the server passes no
    `hooks.external`;
  - `idempotencyWindowMs` (default 10 minutes) is how long an identical call returns the first
    call's result when the provider takes no idempotency key. Shorten it where repeating a call is
    normal, such as starting a machine, stopping it and starting it again. When the provider takes
    one (`idempotencyKey`), an identical call returns the first call's result for three days, the
    time the guard keeps it; a genuine repeat must differ in a body field, such as the description.
- **Catalog servers:** `registerCatalogGroups(server, { guard, operations, resolve, handler, extract, ... })`
  registers list/describe plus one tool per group (`<prefix>_read`, `<prefix>_change`, ...). It
  also registers `guard://manifest` and `guard://status`.
  - `extract` reports amount, currency, targets and client for non-read calls, for limits,
    allowlists and approvals. On reads it is optional and reports targets and client, for client
    scope and canary alerts. Canaries match target values and path parameters only, so report
    every record id a call touches as a target, ids in the request body included.
  - `untrustedFields` names the fields holding other people's text, so they come back labelled
    from every group's tool. Without a list, the whole result of an `untrusted_output` operation
    is treated as untrusted.
- **Hand-written tools:**
  - each tool calls `guard.read(...)` or `guard.execute(...)` with its operation;
  - each tool is registered with `guard.toolConfig(group)`, which supplies its annotations and
    `_meta`;
  - list every tool in the manifest's `extraTools`, with `groupTools: false`.
- **Provider calls:** send every one through the guard's `handler`. A direct client call skips
  the policy, the audit log and the kill switch.

## 3. Ship the manifest

Write `dist/guard-manifest.json` at build time with `buildManifest(...)` (or the `manifest()` that
`registerCatalogGroups` returns), and include `dist` in the package. `mcp-guard harness` reads it
to write client rules, so a tool missing from it is denied by the hook.

- Test that the file equals the runtime manifest, so the two cannot drift.
- `mcp-guard manifest --package .` checks the file.
- Bump the server version whenever tools are added, renamed or regrouped. Users run
  `mcp-guard harness` again for each new manifest version.

## 4. Run the conformance suite

```js
// test/guard-conformance.test.mjs
import { runConformance } from "@nightsquawktech/mcp-core/guard/testing";

runConformance({
  server: "<server>",
  operations,        // every operation, blocked ones included, with methods
  tiers,             // the tiers.json operations map
  build: (ctx) => buildServer({ ...yourOptions, guardOptions: ctx.guardOptions, handler: ctx.handler }),
  samples: { change: {...}, critical: {...}, spend: {...} }, // one accepted call per non-read group
  secrets: ["<key shapes, account numbers that must never appear>"],
  untrusted: { read: {...}, field: "<a field other people write>" },
  egress: { group: "change", sample: {...} },
});
```

`build` must spread `ctx.guardOptions` last into `createGuard()` and send every provider call to
`ctx.handler`. The suite builds the server several times with policies it writes to a temp folder,
calls it over an in-memory transport, and fails on any gap: a group that runs while off, a secret
in a result or audit line, unlabelled outside text, and so on.

## 5. CI

```sh
npx mcp-guard manifest --package .
npx mcp-guard verify <server> --file policy.example.json --package . --tiers tiers.json --operations openapi.json
```

`verify` exits 1 on any failed check. Leave `--strict` off in CI: a CI runner's policy is never
protected.

`--operations` reads JSON only. If the provider publishes YAML, convert it to JSON in the build, or
leave out `--tiers` and `--operations` and run `checkTiers` from `@nightsquawktech/mcp-core/guard`
in the server's own tests.

## 6. README: the guard section

Every adopting server's README carries this section. The hard boundary is the part that matters:
what still holds if the guard itself is bypassed.

```markdown
## Safety

This server runs its tools through the NightSquawk MCP guard.

| Group | Tool | What it runs | Default |
|---|---|---|---|
| read | `<prefix>_read` | <reads> | on |
| change | `<prefix>_change` | <writes> | off |
| critical | `<prefix>_critical` | <deletes, permission changes> | off |
| spend | `<prefix>_spend` | <payments, purchases> | off |

The policy is `/etc/nightsquawk-mcp/<server>/policy.json` (Windows:
`%ProgramData%\NightSquawk\mcp\<server>\policy.json`). Start with `mcp-guard init <server>`, and see
the mcp-core hardening guide before turning on critical or spend.

Server-specific policy keys: <key: meaning>.

### Hard boundary

The guard runs in this process, and the agent's user may be able to read the provider key. What
stops a call even then: <the provider-side control: an IP allowlist, a token with separated
privileges, a transfer the provider holds for a human, a key scoped to ...>.

<If there is none:> None: the key can do everything the provider's API allows. Keep critical and
spend off until the credential broker ships.

### Revoking the key

<Where and how to revoke this server's key, and who can.>
```
