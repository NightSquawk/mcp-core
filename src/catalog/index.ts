/**
 * @nightsquawktech/mcp-core/catalog — primitives for catalog-backed MCP servers.
 *
 * `RegisterTool` uses the SDK's `registerTool()` with a single `{ params }` input
 * schema, plus a generic on-disk catalog loader. The list/describe/call tool
 * factories stay per-server (their spec shapes and write-gates differ too much to share).
 */

export type { ToolDefinition } from "./tool-definition.js";
export { RegisterTool } from "./register-tool.js";
export { formatError } from "./format-error.js";
export type { ToolResponse } from "./tool-response.js";
export { createCatalogStore } from "./loader.js";
export type { CatalogStore, CatalogStoreOptions } from "./loader.js";
