// Session taint, provenance and client lock (7.9, 7.11); canaries (7.10).
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { CANARY_SALT_ENV, Canaries, canaryHash, normalizeValue, SessionState, tokensOf, trustedLeaves } from "../dist/guard/index.js";

describe("tokens", () => {
  test("tokensOf finds ids, emails and digit runs of 4+", () => {
    const t = tokensOf("Pay cpty_ABC123 at bob@example.com, acct 1234 5678-9012; ok.");
    assert.ok(t.includes("cpty_abc123"));
    assert.ok(t.includes("bob@example.com"));
    assert.ok(t.includes("123456789012"), "spaced digits join");
    assert.ok(!t.includes("ok"), "short tokens are skipped");
  });

  test("normalizeValue matches tokensOf", () => {
    assert.deepEqual(normalizeValue(" CPTY_X1Y2 "), ["cpty_x1y2"]);
    assert.deepEqual(normalizeValue("1234 5678"), ["1234 5678", "12345678"]);
  });

  test("trustedLeaves skips labelled untrusted fields", () => {
    const leaves = trustedLeaves({ id: "obj_1", amount: 500, note: { untrusted: true, text: "evil_payee", source: "x" }, list: ["a_b_c_d"] });
    assert.ok(leaves.includes("obj_1"));
    assert.ok(leaves.includes("500"));
    assert.ok(leaves.includes("a_b_c_d"));
    assert.ok(!leaves.includes("evil_payee"));
  });
});

describe("SessionState", () => {
  test("taint is set once and keeps the first source", () => {
    const s = new SessionState("sess1");
    assert.equal(s.taint, null);
    s.markTainted("toy.a", new Date("2026-11-04T00:00:00Z"));
    s.markTainted("toy.b");
    assert.deepEqual(s.taint, { at: "2026-11-04T00:00:00.000Z", source: "toy.a" });
  });

  test("provenance: untrusted-first values are flagged, trusted values never", () => {
    const s = new SessionState();
    s.recordTrusted(["payee_good"]);
    s.recordUntrusted(["send to payee_good and payee_evil, account 9876 5432"], "toy.thing_get");
    assert.equal(s.untrustedSource("payee_evil"), "toy.thing_get");
    assert.equal(s.untrustedSource("PAYEE_EVIL"), "toy.thing_get", "case-insensitive");
    assert.equal(s.untrustedSource("98765432"), "toy.thing_get");
    assert.equal(s.untrustedSource("payee_good"), null);
    assert.equal(s.untrustedSource("payee_never_seen"), null);
  });

  test("a later trusted sighting does not clear an untrusted-first value, an earlier one wins", () => {
    const s = new SessionState();
    s.recordUntrusted(["payee_x1"], "src1");
    s.recordUntrusted(["payee_x1"], "src2");
    assert.equal(s.untrustedSource("payee_x1"), "src1");
    s.recordTrusted(["payee_x1"]);
    assert.equal(s.untrustedSource("payee_x1"), null, "a trusted record of the same value clears it");
  });

  test("client lock", () => {
    const s = new SessionState();
    assert.equal(s.lockedClient, null);
    assert.equal(s.lockClient("A"), true);
    assert.equal(s.lockClient("A"), true);
    assert.equal(s.lockClient("B"), false);
    assert.equal(s.lockedClient, "A");
  });

  test("ids are random", () => {
    assert.notEqual(new SessionState().id, new SessionState().id);
  });
});

describe("Canaries", () => {
  test("hashes are salted", () => {
    assert.equal(CANARY_SALT_ENV, "NST_MCP_CANARY_SALT");
    assert.notEqual(canaryHash("x", "s1"), canaryHash("x", "s2"));
    assert.match(canaryHash("x", "s"), /^sha256:[0-9a-f]{64}$/);
  });

  test("match, inactive and misconfigured", () => {
    const c = new Canaries([canaryHash("decoy_1", "salt")], "salt");
    assert.equal(c.active, true);
    assert.equal(c.misconfigured, false);
    assert.equal(c.match(["real_1", "decoy_1"]), "decoy_1");
    assert.equal(c.match(["real_1"]), null);
    assert.equal(new Canaries([], "salt").active, false);
    const nosalt = new Canaries([canaryHash("decoy_1", "salt")], "");
    assert.equal(nosalt.misconfigured, true);
    assert.equal(nosalt.match(["decoy_1"]), null);
    assert.equal(new Canaries([canaryHash("decoy_1", "salt")], "other").match(["decoy_1"]), null);
  });
});
