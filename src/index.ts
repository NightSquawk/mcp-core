/**
 * @nightsquawk/mcp-core — shared runtime for NightSquawk catalog-backed MCP servers.
 *
 * Main entry: universal server bootstrap. The catalog primitives (tool
 * registration + the on-disk catalog loader) live under the `/catalog` subpath.
 */

export { createMcpServer, runStdioServer } from "./bootstrap.js";
