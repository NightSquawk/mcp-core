import { test } from "node:test";
import assert from "node:assert/strict";
import { dist } from "./foundation-helpers.mjs";

const T = await import(dist("guard/tiers.js"));

test("tiers: exactly the eight plan tiers, in order", () => {
  assert.deepEqual([...T.TIERS], ["read", "reducing", "write", "destructive", "sensitive", "spend", "sandbox", "blocked"]);
  assert.deepEqual([...T.GROUPS], ["read", "change", "critical", "spend"]);
});

test("tiers: tier -> group follows the section 4 table", () => {
  assert.deepEqual({ ...T.TIER_GROUP }, {
    read: "read",
    reducing: "change",
    write: "change",
    sandbox: "change",
    destructive: "critical",
    sensitive: "critical",
    spend: "spend",
    blocked: null,
  });
});

test("tiers: GROUP_TIERS is the exact inverse of TIER_GROUP", () => {
  for (const tier of T.TIERS) {
    const group = T.TIER_GROUP[tier];
    const holders = T.GROUPS.filter((g) => T.GROUP_TIERS[g].includes(tier));
    if (group === null) assert.deepEqual(holders, [], `${tier} must be in no group`);
    else assert.deepEqual(holders, [group], `${tier} must be only in ${group}`);
  }
});

test("tiers: only read is on by default; critical and spend are the high-risk groups", () => {
  assert.deepEqual({ ...T.DEFAULT_GROUPS }, { read: true, change: false, critical: false, spend: false });
  assert.deepEqual([...T.HIGH_RISK_GROUPS].sort(), ["critical", "spend"]);
});

test("tiers: annotations per group match the section 4 table", () => {
  const a = T.GROUP_ANNOTATIONS;
  assert.equal(a.read.readOnlyHint, true);
  assert.equal(a.change.destructiveHint, false);
  assert.equal(a.change.openWorldHint, true);
  assert.equal(a.critical.destructiveHint, true);
  assert.equal(a.critical.openWorldHint, true);
  assert.equal(a.spend.destructiveHint, true);
  assert.equal(a.spend.idempotentHint, false);
  assert.equal(a.spend.openWorldHint, true);
  for (const g of ["change", "critical", "spend"]) assert.notEqual(a[g].readOnlyHint, true, `${g} must not claim read-only`);
});

test("tiers: critical and spend require user interaction unless unattended", () => {
  assert.equal(T.REQUIRES_USER_INTERACTION, "anthropic/requiresUserInteraction");
  for (const g of ["critical", "spend"]) {
    assert.deepEqual(T.groupMeta(g), { "anthropic/requiresUserInteraction": true });
    assert.equal(T.groupMeta(g, { unattended: true }), undefined);
  }
  for (const g of ["read", "change"]) {
    assert.equal(T.groupMeta(g), undefined);
    assert.equal(T.groupMeta(g, { unattended: false }), undefined);
  }
});

test("tiers: group tool names use the fixed suffixes", () => {
  assert.equal(T.groupToolName("column", "spend"), "column_spend");
  assert.equal(T.groupToolName("proxmox", "critical"), "proxmox_critical");
});

test("tiers: isTier / isGroup reject anything outside the lists", () => {
  for (const t of T.TIERS) assert.equal(T.isTier(t), true);
  for (const g of T.GROUPS) assert.equal(T.isGroup(g), true);
  for (const bad of ["Read", "admin", "", null, undefined, 3, {}, ["read"]]) {
    assert.equal(T.isTier(bad), false, `isTier(${JSON.stringify(bad)})`);
    assert.equal(T.isGroup(bad), false, `isGroup(${JSON.stringify(bad)})`);
  }
  assert.equal(T.isGroup("blocked"), false, "blocked is a tier, never a group");
});

test("tiers: the shared tables cannot be changed at runtime", () => {
  assert.throws(() => {
    T.TIER_GROUP.spend = "read";
  }, TypeError);
  assert.throws(() => {
    T.DEFAULT_GROUPS.spend = true;
  }, TypeError);
  assert.throws(() => {
    T.GROUP_TIERS.read.push("spend");
  }, TypeError);
  assert.throws(() => {
    T.GROUP_ANNOTATIONS.critical.destructiveHint = false;
  }, TypeError);
  assert.equal(T.TIER_GROUP.spend, "spend");
});
