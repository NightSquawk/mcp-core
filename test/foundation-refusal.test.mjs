import { test } from "node:test";
import assert from "node:assert/strict";
import { dist } from "./foundation-helpers.mjs";

const { refuse, isRefusal } = await import(dist("guard/refusal.js"));

test("refusal: has the section 6 shape", () => {
  const r = refuse("group_off", "The spend group is off.", { how_to_enable: "Set groups.spend.", details: { group: "spend" } });
  assert.deepEqual(r, {
    refused: true,
    reason_code: "group_off",
    message: "The spend group is off.",
    how_to_enable: "Set groups.spend.",
    details: { group: "spend" },
  });
});

test("refusal: optional fields are left out, not set to undefined", () => {
  const r = refuse("blocked", "Never exposed.");
  assert.deepEqual(Object.keys(r).sort(), ["message", "reason_code", "refused"]);
  assert.equal(JSON.stringify(r), '{"refused":true,"reason_code":"blocked","message":"Never exposed."}');
  assert.deepEqual(Object.keys(refuse("x", "y", { how_to_enable: "" })).sort(), ["message", "reason_code", "refused"]);
});

test("refusal: isRefusal only accepts refused === true", () => {
  assert.equal(isRefusal(refuse("a", "b")), true);
  for (const v of [null, undefined, "refused", 1, {}, { refused: "true" }, { refused: 1 }, { refused: false }, [true]]) {
    assert.equal(isRefusal(v), false, JSON.stringify(v));
  }
});
