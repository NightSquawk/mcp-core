import { test } from "node:test";
import assert from "node:assert/strict";
import { dist } from "./foundation-helpers.mjs";

const C = await import(dist("guard/canonical.js"));

test("canonicalJson: keys sorted at every depth, independent of insertion order", () => {
  assert.equal(C.canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: 2 } }), '{"a":{"c":2,"d":[3,{"y":2,"z":1}]},"b":1}');
  assert.equal(C.canonicalJson({ x: 1, y: 2 }), C.canonicalJson({ y: 2, x: 1 }));
});

test("canonicalJson: undefined is dropped from objects and becomes null in arrays, like JSON.stringify", () => {
  assert.equal(C.canonicalJson({ a: undefined, b: [undefined, 1] }), '{"b":[null,1]}');
  assert.equal(C.canonicalJson(undefined), "null");
  assert.equal(C.canonicalJson(null), "null");
  assert.equal(C.canonicalJson("x"), '"x"');
  assert.equal(C.canonicalJson(12.5), "12.5");
  assert.equal(C.canonicalJson([]), "[]");
});

test("canonicalJson: values with toJSON serialize as JSON.stringify does (a Date is not {})", () => {
  // Otherwise two different dates canonicalize, hash and derive idempotency keys identically.
  assert.equal(C.canonicalJson({ when: new Date(0) }), '{"when":"1970-01-01T00:00:00.000Z"}');
  assert.notEqual(C.canonicalJson({ when: new Date(0) }), C.canonicalJson({ when: new Date(1) }));
});

test("canonicalJson: an own __proto__ member is kept (covered by the hash), never applied as a prototype", () => {
  const a = JSON.parse('{"a":1,"__proto__":{"amount":1}}');
  const b = JSON.parse('{"a":1,"__proto__":{"amount":2}}');
  assert.notEqual(C.canonicalJson(a), C.canonicalJson(b), "bodies that differ only in __proto__ must not canonicalize the same");
  assert.equal(C.canonicalJson(a), '{"__proto__":{"amount":1},"a":1}');
  assert.equal({}.amount, undefined, "no prototype pollution");
});

test("sha256Hex: standard test vectors, string or Buffer", () => {
  assert.equal(C.sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(C.sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(C.sha256Hex(Buffer.from("abc")), C.sha256Hex("abc"));
});

test("nonce: 24 lowercase hex characters, never repeated", () => {
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const n = C.nonce();
    assert.match(n, /^[0-9a-f]{24}$/);
    seen.add(n);
  }
  assert.equal(seen.size, 200);
});

test("deepFreeze: freezes nested objects and arrays and returns the same value", () => {
  const v = { a: { b: [1, { c: 2 }] } };
  assert.equal(C.deepFreeze(v), v);
  assert.ok(Object.isFrozen(v) && Object.isFrozen(v.a) && Object.isFrozen(v.a.b) && Object.isFrozen(v.a.b[1]));
  assert.throws(() => {
    "use strict";
    v.a.b[1].c = 3;
  }, TypeError);
  assert.equal(C.deepFreeze(5), 5);
  assert.equal(C.deepFreeze(null), null);
});

test("jsonClone: an independent JSON copy", () => {
  const v = { a: [1, { b: 2 }], when: new Date(0), f() {} };
  const c = C.jsonClone(v);
  c.a[1].b = 99;
  assert.equal(v.a[1].b, 2);
  assert.deepEqual(c, { a: [1, { b: 99 }], when: "1970-01-01T00:00:00.000Z" });
  assert.equal(C.jsonClone(undefined), undefined);
});

test("utcDay / utcMonth: UTC calendar, not local time", () => {
  const lateWestCoast = new Date("2026-11-04T23:59:59.999-08:00");
  assert.equal(C.utcDay(lateWestCoast), "2026-11-05");
  assert.equal(C.utcMonth(lateWestCoast), "2026-11");
  const yearEnd = new Date("2026-12-31T23:59:59.999Z");
  assert.equal(C.utcDay(yearEnd), "2026-12-31");
  assert.equal(C.utcMonth(yearEnd), "2026-12");
});
