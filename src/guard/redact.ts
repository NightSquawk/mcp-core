/**
 * redact() with shared patterns (section 7.4). Applied to error messages, audit
 * lines and dry_run output. Servers add patterns with createRedactor().
 * redactSensitiveKeys() masks values by key name (passwords, tokens) where the
 * value patterns cannot recognize them.
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
  // URL user-info. The scheme starts at a word boundary and is at most 32 characters,
  // so a long run of letters (base64 data, a padded field) is scanned once, not once
  // per position: the unbounded form took 47 s on a 250 KB string.
  [/\b([a-z][a-z0-9+.-]{0,31}:\/\/)[^/@\s"']+@/gi, "$1[redacted]@"],
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

/** Keys whose values are account, routing or card numbers even when the provider sends them as JSON numbers. */
export const SENSITIVE_NUMBER_KEYS = /(^|_)(account|routing|card|aba)_?(number|num|no)$|^(iban|pan|aba)$/i;

/** Credential key names, compared after normalizeKey(). */
export const SENSITIVE_KEY_NAMES: readonly string[] = Object.freeze(["key", "pass", "pin", "otp", "credential"]);
/** Credential key endings, compared after normalizeKey(): `cipassword`, `root_password`, `client-secret`, `api_key`. */
export const SENSITIVE_KEY_SUFFIXES: readonly string[] = Object.freeze([
  "password",
  "passwd",
  "passphrase",
  "passcode",
  "secret",
  "secretkey",
  "token",
  "apikey",
  "privatekey",
  "signingkey",
]);

/** Lower-case, letters and digits only: `Client-Secret` and `client_secret` are the same key. */
function normalizeKey(key: string): string {
  return String(key).toLowerCase().replace(/[^a-z0-9]/g, "");
}

/**
 * True when a key's value is a credential whatever it looks like (section 7.4):
 * value patterns cannot catch an arbitrary password, so the key name decides.
 * A trailing "s" is ignored (`secrets`, `tokens`). `extra` adds exact names.
 */
export function isSensitiveKey(key: string, extra: readonly string[] = []): boolean {
  const k = normalizeKey(key);
  if (!k) return false;
  const forms = k.length > 1 && k.endsWith("s") ? [k, k.slice(0, -1)] : [k];
  for (const f of forms) {
    if (SENSITIVE_KEY_NAMES.includes(f)) return true;
    for (const s of SENSITIVE_KEY_SUFFIXES) if (f.endsWith(s)) return true;
  }
  return extra.some((e) => normalizeKey(e) === k);
}

/**
 * Replace the value under every credential-named key (isSensitiveKey), at any
 * depth, with "[redacted]"; booleans and null are kept, everything else (strings,
 * numbers, whole objects) is replaced. Other values and the structure are left
 * alone, and `secrets` (exact values such as the API key) are masked wherever they
 * appear. For request bodies in dry-run output and for pre-image files, where the
 * value patterns of redactValue() would miss an arbitrary password.
 */
export function redactSensitiveKeys<T>(value: T, opts: { extraKeys?: readonly string[]; secrets?: readonly string[] } = {}): T {
  const extra = opts.extraKeys ?? [];
  const secrets = [...(opts.secrets ?? [])].filter(Boolean).sort((a, b) => b.length - a.length);
  const mask = (s: string): string => {
    let out = s;
    for (const secret of secrets) out = out.split(secret).join("[redacted]");
    return out;
  };
  const walk = (v: unknown, depth: number): unknown => {
    if (typeof v === "string") return secrets.length ? mask(v) : v;
    if (v === null || typeof v !== "object") return v;
    if (depth > 64) return "[too deep]";
    if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
    if (typeof (v as { toJSON?: unknown }).toJSON === "function") return walk(JSON.parse(JSON.stringify(v) ?? "null"), depth + 1);
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>).map(([k, x]) => [
        secrets.length ? mask(k) : k,
        isSensitiveKey(k, extra) && x !== null && x !== undefined && typeof x !== "boolean" ? "[redacted]" : walk(x, depth + 1),
      ])
    );
  };
  return walk(value, 0) as T;
}

function lastFour(value: string | number): string {
  const digits = String(value).replace(/\D/g, "");
  return digits.length > 4 ? `****${digits.slice(-4)}` : String(value);
}

/**
 * redact() for a JSON value. String leaves and object keys go through the
 * redactor; numbers, booleans and the structure are kept, so an amount such as
 * 12345678 cents is never mistaken for an account number. Values under
 * SENSITIVE_NUMBER_KEYS keep only their last 4 digits whatever their type.
 */
export function redactValue<T>(value: T, secrets: readonly string[] = [], redactor: Redactor = redact): T {
  const walk = (v: unknown, key: string | null, depth: number): unknown => {
    if (key !== null && SENSITIVE_NUMBER_KEYS.test(key) && (typeof v === "number" || typeof v === "string")) {
      return redactor(lastFour(v), secrets);
    }
    if (typeof v === "string") return redactor(v, secrets);
    if (v === null || typeof v !== "object") return v;
    if (depth > 64) return "[too deep]";
    if (Array.isArray(v)) return v.map((x) => walk(x, key, depth + 1));
    if (typeof (v as { toJSON?: unknown }).toJSON === "function") {
      const plain: unknown = JSON.parse(JSON.stringify(v) ?? "null");
      return plain !== null && typeof plain === "object" ? walk(plain, key, depth + 1) : walk(plain, key, depth);
    }
    return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [redactor(k, secrets), walk(x, k, depth + 1)]));
  };
  return walk(value, null, 0) as T;
}
