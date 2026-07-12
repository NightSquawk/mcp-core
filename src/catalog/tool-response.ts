/**
 * Client-level result envelope used inside catalog servers (distinct from the
 * MCP tool response). A client returns this; the tool layer renders it.
 */
export interface ToolResponse<T> {
  result: T | null;
  isError: boolean;
  error: string | null;
}
