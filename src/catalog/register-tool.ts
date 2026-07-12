import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { ToolDefinition } from "./tool-definition.js";

/** Register a {@link ToolDefinition} on a server via the single-schema form. */
export function RegisterTool<T extends z.ZodType<any, any>>(
  server: McpServer,
  toolDefinition: ToolDefinition<T>
) {
  server.tool(
    toolDefinition.name,
    toolDefinition.description,
    { params: toolDefinition.schema },
    toolDefinition.handler
  );
}
