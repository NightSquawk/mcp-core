/**
 * The guard's structured refusal (section 6). Every refusal has this shape, is
 * returned to the model as JSON, and is audited.
 */
export interface Refusal {
  refused: true;
  reason_code: string;
  message: string;
  how_to_enable?: string;
  /** Extra machine-readable context (limits, the conflicting value's kind, ...). */
  details?: Record<string, unknown>;
}

export function refuse(reason_code: string, message: string, extra: { how_to_enable?: string; details?: Record<string, unknown> } = {}): Refusal {
  return {
    refused: true,
    reason_code,
    message,
    ...(extra.how_to_enable ? { how_to_enable: extra.how_to_enable } : {}),
    ...(extra.details ? { details: extra.details } : {}),
  };
}

export function isRefusal(value: unknown): value is Refusal {
  return typeof value === "object" && value !== null && (value as { refused?: unknown }).refused === true;
}
