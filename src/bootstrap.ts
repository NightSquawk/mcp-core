import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

/** Create an MCP server with the given identity. Thin wrapper over the SDK. */
export function createMcpServer(opts: { name: string; version: string }): McpServer {
  return new McpServer({ name: opts.name, version: opts.version });
}

/**
 * Connect a server to stdio and (optionally) log a startup banner to stderr.
 * stdout is reserved for the MCP protocol, so banners MUST go to stderr.
 * Callers keep their own top-level error handling (e.g. main().catch(exit)).
 */
export async function runStdioServer(
  server: McpServer,
  opts: { banner?: string } = {}
): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  if (opts.banner) {
    console.error(opts.banner);
  }
}
