import { z } from "zod";
import { ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";

/**
 * A single-schema tool definition used by the catalog-backed servers, which
 * register tools via the SDK's `server.tool(name, desc, { params }, handler)`
 * form. `handler` receives the validated `{ params }` object.
 */
export interface ToolDefinition<T extends z.ZodType<any, any>> {
  name: string;
  description: string;
  schema: T;
  handler: ToolCallback<{ [key: string]: T }>;
}
