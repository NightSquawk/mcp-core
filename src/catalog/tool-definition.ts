import { z } from "zod";
import type { ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

/**
 * A single-schema tool definition used by the catalog-backed servers. The tool's
 * input is `{ params: <schema> }`, and `handler` receives that validated object.
 *
 * `title`, `annotations` and `_meta` are optional and passed through to the SDK's
 * `registerTool()` (the guard sets them per tool group).
 */
export interface ToolDefinition<T extends z.ZodType<any, any>> {
  name: string;
  description: string;
  schema: T;
  handler: ToolCallback<{ [key: string]: T }>;
  title?: string;
  annotations?: ToolAnnotations;
  _meta?: Record<string, unknown>;
}
