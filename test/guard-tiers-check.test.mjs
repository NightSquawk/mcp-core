// The tiers.json checker, the manifest and the version constant.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";
import { assertTiers, buildManifest, checkTiers, flagsOf, GUARD_VERSION, KNOWN_FLAGS, MANIFEST_VERSION } from "../dist/guard/index.js";
import { OPS, TIERS_FILE } from "./guard-helpers.mjs";

const SPEC = OPS.map(({ operationId, method, path }) => ({ operationId, method, path }));

describe("checkTiers", () => {
  test("the toy catalog passes and is counted", () => {
    const r = checkTiers({ operations: SPEC, tiers: TIERS_FILE });
    assert.deepEqual(r.issues, []);
    assert.equal(r.ok, true);
    assert.equal(r.counts.read, 3);
    assert.equal(r.counts.spend, 2);
    assert.equal(r.counts.blocked, 1);
  });

  test("every problem is reported with a code", () => {
    const tiers = {
      $comment: "ignored",
      thing_list: { tier: "read" },
      thing_get: { tier: "reed" },
      thing_search: { tier: "read" },
      thing_create: { tier: "write", flags: { untrusted_output: true, spicy: true } },
      thing_update: { tier: "write", flags: { egress: "yes" } },
      thing_pause: { tier: "reducing", flags: ["egress"] },
      gone_op: { tier: "read" },
    };
    const r = checkTiers({ operations: SPEC.slice(0, 7), tiers });
    const got = r.issues.map((i) => `${i.operationId}:${i.code}`).sort();
    assert.deepEqual(got, ["gone_op:extra", "thing_create:unknown_flag", "thing_get:unknown_tier", "thing_notify:missing", "thing_pause:bad_flag", "thing_search:non_get_read", "thing_update:bad_flag"]);
    assert.equal(r.ok, false);
    assert.equal(checkTiers({ operations: SPEC.slice(0, 7), tiers, allowExtra: true }).issues.some((i) => i.code === "extra"), false);
  });

  test("an egress operation is never read: reads have no approver to ask after taint", () => {
    const ops = [{ operationId: "ping", method: "GET", path: "/nodes/{n}/ping" }, { operationId: "send", method: "POST", path: "/send" }];
    const r = checkTiers({ operations: ops, tiers: { ping: { tier: "read", flags: { egress: true } }, send: { tier: "write", flags: { egress: true } } } });
    assert.deepEqual(r.issues.map((i) => `${i.operationId}:${i.code}`), ["ping:egress_read"]);
    assert.match(r.issues[0].message, /GET \/nodes\/\{n\}\/ping/);
    assert.equal(checkTiers({ operations: ops, tiers: { ping: { tier: "read", flags: { egress: false } }, send: { tier: "write" } } }).ok, true);
  });

  test("a non-GET read needs a real explanation; HEAD counts as GET", () => {
    const ops = [{ operationId: "q", method: "post", path: "/q" }, { operationId: "h", method: "HEAD", path: "/h" }];
    assert.equal(checkTiers({ operations: ops, tiers: { q: { tier: "read", read_reason: "short" }, h: { tier: "read" } } }).issues.length, 1);
    assert.equal(checkTiers({ operations: ops, tiers: { q: { tier: "read", read_reason: "Quote only; creates nothing." }, h: { tier: "read" } } }).ok, true);
    assert.equal(checkTiers({ operations: ops, tiers: { q: { tier: "read", why: "Quote only; creates nothing." }, h: { tier: "read" } }, nonGetReadKey: "why" }).ok, true);
  });

  test("assertTiers throws a readable list", () => {
    assert.throws(() => assertTiers({ operations: SPEC, tiers: {} }), /tiers check failed \(13\):\n  - \[missing\]/);
    assert.equal(assertTiers({ operations: SPEC, tiers: TIERS_FILE }).ok, true);
  });

  test("flagsOf keeps known true flags only", () => {
    assert.deepEqual(KNOWN_FLAGS, ["untrusted_output", "egress"]);
    assert.deepEqual(flagsOf({ flags: { untrusted_output: true, egress: false, other: true } }), { untrusted_output: true });
    assert.equal(flagsOf({ flags: { egress: false } }), undefined);
    assert.equal(flagsOf({}), undefined);
    assert.equal(flagsOf(undefined), undefined);
  });
});

describe("buildManifest", () => {
  test("group tools, operations, blocked ops and flags", () => {
    const m = buildManifest({ server: "toy", version: "1.2.3", prefix: "toy", operations: OPS, extraTools: [{ name: "toy_list_endpoints", group: "read" }] });
    assert.equal(m.manifest_version, MANIFEST_VERSION);
    assert.equal(m.guard_version, GUARD_VERSION);
    assert.deepEqual(m.tools.map((t) => t.name), ["toy_list_endpoints", "toy_read", "toy_change", "toy_critical", "toy_spend"]);
    const spend = m.tools.find((t) => t.name === "toy_spend");
    assert.equal(spend.operations, 2);
    assert.equal(spend._meta["anthropic/requiresUserInteraction"], true);
    assert.deepEqual(m.tools.find((t) => t.name === "toy_change").tiers, ["reducing", "sandbox", "write"]);
    const release = m.operations.find((o) => o.operation === "payment_release");
    assert.deepEqual(release, { operation: "payment_release", tier: "blocked", group: null, tool: null });
    assert.deepEqual(m.operations.find((o) => o.operation === "thing_get").flags, { untrusted_output: true });
    assert.deepEqual(m.operations.map((o) => o.operation), [...m.operations.map((o) => o.operation)].sort());
  });

  test("unattended drops requiresUserInteraction; groupTools:false lists only extra tools", () => {
    const m = buildManifest({ server: "toy", version: "1", prefix: "toy", operations: OPS, unattended: { spend: true } });
    assert.equal(m.tools.find((t) => t.name === "toy_spend")._meta, null);
    const hand = buildManifest({ server: "toy", version: "1", prefix: "toy", operations: OPS, groupTools: false, extraTools: [{ name: "toy_pay", group: "spend", operations: 1 }] });
    assert.deepEqual(hand.tools.map((t) => t.name), ["toy_pay"]);
    assert.ok(hand.operations.every((o) => o.tool === null));
  });
});

test("GUARD_VERSION matches package.json", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(GUARD_VERSION, pkg.version);
});
