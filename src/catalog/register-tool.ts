import type { McpServer, RegisteredTool } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ToolDefinition } from "./tool-definition.js";

/**
 * Register a {@link ToolDefinition} on a server.
 *
 * Uses the SDK's `registerTool()` (the `server.tool()` overloads are deprecated and
 * cannot carry `annotations` or `_meta`). The input schema stays `{ params: schema }`,
 * so tools registered before 0.2 keep the same wire shape and handler argument.
 */
export function RegisterTool<T extends z.ZodType<any, any>>(
  server: McpServer,
  toolDefinition: ToolDefinition<T>
): RegisteredTool {
  return server.registerTool(
    toolDefinition.name,
    {
      ...(toolDefinition.title !== undefined ? { title: toolDefinition.title } : {}),
      description: toolDefinition.description,
      inputSchema: { params: toolDefinition.schema },
      ...(toolDefinition.annotations !== undefined ? { annotations: toolDefinition.annotations } : {}),
      ...(toolDefinition._meta !== undefined ? { _meta: toolDefinition._meta } : {}),
    },
    toolDefinition.handler as any
  );
}
