import { test } from "node:test";
import assert from "node:assert/strict";
import { dist } from "./foundation-helpers.mjs";

const { redact, redactValue, createRedactor, SHARED_RULES, SENSITIVE_NUMBER_KEYS } = await import(dist("guard/redact.js"));

// Synthetic key-shaped values, built at runtime so no key-like literal sits in the repo.
const fake = (prefix, n = 24) => prefix + "Ab9".repeat(Math.ceil(n / 3)).slice(0, n);

test("redact: HTTP Authorization values", () => {
  assert.equal(redact("Authorization: Bearer abc.DEF-123_x~y"), "Authorization: Bearer [redacted]");
  assert.equal(redact("authorization: basic dXNlcjpwYXNzd29yZA=="), "authorization: basic [redacted]");
  assert.equal(redact("Bearer abc"), "Bearer abc", "too short to be a credential");
});

test("redact: provider key shapes", () => {
  for (const p of ["test_", "live_"]) assert.equal(redact(`key ${fake(p)} end`), `key ${p}[redacted] end`);
  for (const p of ["sk_", "rk_", "sk_test_", "sk_live_", "rk_live_"]) {
    const out = redact(`use ${fake(p)} now`);
    assert.ok(!out.includes(fake(p)), `${p} key leaked: ${out}`);
    assert.match(out, /^use (sk|rk)_\[redacted\] now$/);
  }
  assert.equal(redact("latest_transfers"), "latest_transfers", "no word boundary before test_/live_");
  assert.equal(redact("contest_abcdefgh12"), "contest_abcdefgh12");
});

test("redact: credentials in query strings and key=value text", () => {
  assert.equal(redact("https://x.test/a?api_key=s3cr3t&b=1"), "https://x.test/a?api_key=[redacted]&b=1");
  assert.equal(redact("GET /v1?token=abc123def&page=2"), "GET /v1?token=[redacted]&page=2");
  assert.equal(redact("PASSWORD=hunter2!"), "PASSWORD=[redacted]");
  assert.equal(redact("client_secret=zzz access-token=yyy"), "client_secret=[redacted] access-token=[redacted]");
  assert.equal(redact("monkey=banana"), "monkey=banana", "'key' inside a longer word is not a credential name");
});

test("redact: URL user-info", () => {
  assert.equal(redact("postgres://admin:pw@db.internal:5432/app"), "postgres://[redacted]@db.internal:5432/app");
  assert.equal(redact("https://user@host.test/x"), "https://[redacted]@host.test/x");
  assert.equal(redact("mailto:ops@example.com"), "mailto:ops@example.com", "no :// so not user-info");
});

test("redact: account, routing and card numbers keep only their last 4 digits", () => {
  assert.equal(redact("routing 021000021"), "routing ****0021");
  assert.equal(redact("acct 123456789012"), "acct ****9012");
  assert.equal(redact("card 4111111111111111"), "card ****1111");
  assert.equal(redact("did 5551234567"), "did ****4567");
  assert.equal(redact("ref 1234567"), "ref 1234567", "7 digits are left alone");
  assert.equal(redact("n 123456789012345678"), "n 123456789012345678", "18+ digit runs are not account numbers");
});

test("redact: timestamps, hashes and ids are not damaged", () => {
  const safe = [
    "2026-11-04T06:09:43.123Z",
    "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "nst-column-0123456789abcdef",
    "transfer_ach_create_transfer",
  ];
  for (const s of safe) assert.equal(redact(s), s);
});

test("redact: exact secret values are masked first, longest first", () => {
  const short = "Zq7Zq7Zq";
  const long = `${short}LONGERPART`;
  assert.equal(redact(`a ${long} b ${short} c`, [short, long]), "a [redacted] b [redacted] c");
  assert.equal(redact("nothing here", ["", undefined, null].filter(Boolean)), "nothing here");
});

test("redact: repeated calls give the same result (no global-regex state)", () => {
  const s = "Bearer abcdefgh token=xyz 123456789012";
  const first = redact(s);
  for (let i = 0; i < 5; i++) assert.equal(redact(s), first);
});

test("redact: server rules run before the shared ones", () => {
  const r = createRedactor([[/\bcpty_[a-z0-9]{6,}/g, "cpty_[redacted]"]]);
  assert.equal(r("pay cpty_abc123xyz with Bearer abcdefgh"), "pay cpty_[redacted] with Bearer [redacted]");
  assert.equal(redact("pay cpty_abc123xyz"), "pay cpty_abc123xyz", "extra rules do not leak into the shared redactor");
  assert.ok(Object.isFrozen(SHARED_RULES));
});

test("redactValue: keeps the JSON shape and redacts string leaves and keys", () => {
  const input = {
    note: "Bearer abcdefgh123",
    nested: { url: "https://u:p@h.test/", list: ["token=abc", 3, true, null] },
    [fake("test_")]: "key used as a property name",
  };
  const out = redactValue(input);
  assert.equal(out.note, "Bearer [redacted]");
  assert.equal(out.nested.url, "https://[redacted]@h.test/");
  assert.deepEqual(out.nested.list, ["token=[redacted]", 3, true, null]);
  assert.ok(!JSON.stringify(out).includes(fake("test_")), "a secret used as a key must be masked too");
  assert.equal(typeof out, "object");
});

test("redactValue: amounts and other large numbers are never masked", () => {
  const entry = { operation: "transfer_ach_create_transfer", amount_cents: 12345678, duration_ms: 123456789, http_status: 201 };
  const out = redactValue(entry);
  assert.deepEqual(out, entry, "a $123,456.78 transfer must be audited with its amount and operation intact");
});

test("redactValue: values under account/routing/card keys keep only their last 4 digits, whatever their type", () => {
  const out = redactValue({
    account_number: "123456789012",
    routing_number: 21000021,
    bank_account_number: "000123456789",
    cardNumber: "4111 1111 1111 1111",
    iban: "GB82WEST12345698765432",
    account_no: "1234",
    amount: 21000021,
  });
  assert.equal(out.account_number, "****9012");
  assert.equal(out.routing_number, "****0021");
  assert.equal(out.bank_account_number, "****6789");
  assert.equal(out.cardNumber, "****1111");
  assert.equal(out.iban, "****5432");
  assert.equal(out.account_no, "1234", "four digits or fewer stay as they are");
  assert.equal(out.amount, 21000021, "the same digits under a non-sensitive key stay a number");
  for (const k of ["account_number", "routing_number", "card_number", "accountNumber", "aba", "pan", "iban", "account_no"]) {
    assert.ok(SENSITIVE_NUMBER_KEYS.test(k), k);
  }
  for (const k of ["amount", "account_id", "routing", "number", "description"]) assert.ok(!SENSITIVE_NUMBER_KEYS.test(k), k);
});

test("redactValue: secrets, toJSON values, cycles and primitives", () => {
  const secretValue = fake("Zz", 20);
  assert.deepEqual(redactValue({ msg: `got ${secretValue}` }, [secretValue]), { msg: "got [redacted]" });
  const when = new Date("2026-11-04T00:00:00.000Z");
  assert.deepEqual(redactValue({ when }), { when: "2026-11-04T00:00:00.000Z" });
  const cyclic = { a: 1 };
  cyclic.self = cyclic;
  assert.doesNotThrow(() => redactValue(cyclic), "a cycle must not recurse forever");
  assert.equal(redactValue(undefined), undefined);
  assert.equal(redactValue(42), 42);
  assert.equal(redactValue("Bearer abcdefgh"), "Bearer [redacted]");
});
