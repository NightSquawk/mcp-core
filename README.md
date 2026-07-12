# @nightsquawktech/mcp-core

Shared runtime for NightSquawk's catalog-backed [MCP](https://modelcontextprotocol.io) servers: a stdio bootstrap plus the primitives used by the `list_endpoints` / `describe_endpoint` / `call_endpoint` tool pattern.

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

Peer dependencies (bring your own versions): `@modelcontextprotocol/sdk` >= 1.6.0 and `zod` ^3.24.

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
- `RegisterTool(server, toolDefinition)`: registers a `ToolDefinition` using the SDK's single-schema `server.tool(...)` form.
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

## License

Licensed under the [GNU AGPL v3.0](./LICENSE). Free for personal and open-source use.

Organizations that cannot comply with the AGPL can purchase a commercial license. See [COMMERCIAL.md](./COMMERCIAL.md) or contact hello@nightsquawk.tech.
