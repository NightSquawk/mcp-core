/**
 * redact() with shared patterns (section 7.4). Applied to error messages, audit
 * lines and dry_run output. Servers add patterns with createRedactor().
 */

export type RedactRule = readonly [RegExp, string];

/** Shared patterns. Order matters: specific shapes before the digit-run rule. */
export const SHARED_RULES: readonly RedactRule[] = Object.freeze([
  // HTTP Authorization values
  [/\b(Basic|Bearer)\s+[A-Za-z0-9+/=._~-]{6,}/gi, "$1 [redacted]"],
  // Provider key shapes: Column/Stripe test_ and live_, Stripe sk_/rk_/pk_ (with optional mode)
  [/\b(test|live)_[A-Za-z0-9]{8,}/g, "$1_[redacted]"],
  [/\b(sk|rk)_(?:(?:test|live)_)?[A-Za-z0-9]{8,}/g, "$1_[redacted]"],
  // Credentials in query strings and key=value text
  [/\b((?:api[_-]?key|access[_-]?token|key|token|password|passwd|secret|client[_-]?secret)=)[^&\s"']+/gi, "$1[redacted]"],
  // URL user-info
  [/([a-z][a-z0-9+.-]*:\/\/)[^/@\s"']+@/gi, "$1[redacted]@"],
  // Account and routing numbers: runs of 8-17 digits keep only their last 4
  [/\b\d{4,13}(\d{4})\b/g, "****$1"],
] as RedactRule[]);

export type Redactor = (text: string, secrets?: readonly string[]) => string;

/** Build a redactor with server-specific extra rules (applied before the shared ones). */
export function createRedactor(extra: readonly RedactRule[] = []): Redactor {
  const rules = [...extra, ...SHARED_RULES];
  return (text: string, secrets: readonly string[] = []): string => {
    let out = String(text);
    // Exact secret values first, longest first so a secret containing another is masked whole.
    for (const s of [...secrets].filter(Boolean).sort((a, b) => b.length - a.length)) out = out.split(s).join("[redacted]");
    for (const [pattern, replacement] of rules) {
      pattern.lastIndex = 0;
      out = out.replace(pattern, replacement);
    }
    return out;
  };
}

/** Mask secrets in `text` with the shared patterns. */
export const redact: Redactor = createRedactor();

/** redact() for a JSON value, keeping its shape where it can. */
export function redactValue<T>(value: T, secrets: readonly string[] = [], redactor: Redactor = redact): T | string {
  if (value === undefined) return value;
  const masked = redactor(JSON.stringify(value), secrets);
  try {
    return JSON.parse(masked) as T;
  } catch {
    return masked;
  }
}
