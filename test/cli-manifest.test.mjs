// mcp-guard manifest: a manifest built by the guard passes; one edited to mislead clients fails.
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { cli, dist, tempDir, test } from "./cli-helpers.mjs";

const { buildManifest } = await import(dist("guard/manifest.js"));
const { checkManifest } = await import(dist("cli/manifest.js"));

const OPS = [
  { operationId: "list_accounts", tier: "read" },
  { operationId: "get_account", tier: "read" },
  { operationId: "create_note", tier: "write" },
  { operationId: "close_account", tier: "destructive" },
  { operationId: "create_transfer", tier: "spend", flags: { egress: true } },
  { operationId: "delete_everything", tier: "blocked" },
];

const toy = (over = {}) => buildManifest({ server: "toy", version: "1.0.0", prefix: "toy", operations: OPS, ...over });
const clone = (m) => JSON.parse(JSON.stringify(m));
const fails = (r) => r.issues.filter((i) => i.level === "fail").map((i) => `${i.where}: ${i.message}`);
const warns = (r) => r.issues.filter((i) => i.level === "warn").map((i) => `${i.where}: ${i.message}`);

function writePackage(t, manifest, raw) {
  const dir = tempDir(t, "mcp-guard-manifest-");
  mkdirSync(join(dir, "dist"), { recursive: true });
  writeFileSync(join(dir, "dist", "guard-manifest.json"), raw ?? JSON.stringify(manifest, null, 2));
  return dir;
}

test("a manifest the guard builds passes with no issues", () => {
  const r = checkManifest(toy());
  assert.deepEqual(r.issues, []);
  assert.equal(r.ok, true);
  assert.equal(r.server, "toy");
  assert.equal(r.tools, 4);
  assert.equal(r.operations, 6);
  assert.equal(r.counts.read, 2);
  assert.equal(r.counts.blocked, 1);
});

test("hand-written tool servers (groupTools false) pass too", () => {
  const m = buildManifest({
    server: "toy",
    version: "1.0.0",
    prefix: "toy",
    operations: OPS,
    groupTools: false,
    extraTools: [
      { name: "toy_list", group: "read", operations: 2 },
      { name: "toy_note", group: "change", operations: 1 },
    ],
  });
  assert.deepEqual(fails(checkManifest(m)), []);
});

test("an unattended group warns that clients will not ask, but passes", () => {
  const r = checkManifest(toy({ unattended: { critical: true } }));
  assert.equal(r.ok, true);
  assert.equal(warns(r).length, 1);
  assert.match(warns(r)[0], /^tools\[\d\] toy_critical: no _meta\["anthropic\/requiresUserInteraction"\]/);
});

test("edits that mislead a client fail", () => {
  const cases = [
    [
      "readOnlyHint on a change tool",
      (m) => (m.tools.find((t) => t.name === "toy_change").annotations.readOnlyHint = true),
      /toy_change: annotations\.readOnlyHint is true on a change tool/,
    ],
    ["spend without destructiveHint", (m) => delete m.tools.find((t) => t.name === "toy_spend").annotations.destructiveHint, /toy_spend: annotations\.destructiveHint must be true on a spend tool/],
    ["a tier moved into the wrong tool", (m) => m.tools.find((t) => t.name === "toy_read").tiers.push("spend"), /tier spend belongs to spend, not read/],
    ["an operation's group changed", (m) => (m.operations.find((o) => o.operation === "create_transfer").group = "read"), /group is "read", but tier spend belongs to spend/],
    ["an operation moved to the read tool", (m) => (m.operations.find((o) => o.operation === "close_account").tool = "toy_read"), /tool toy_read is in the read group, not critical/],
    ["a blocked operation given a tool", (m) => (m.operations.find((o) => o.operation === "delete_everything").tool = "toy_critical"), /a blocked operation must not have a tool/],
    ["a tool removed", (m) => (m.tools = m.tools.filter((t) => t.name !== "toy_critical")), /tool "toy_critical" is not in tools/],
    ["an operation dropped from its tool's count", (m) => (m.operations = m.operations.filter((o) => o.operation !== "get_account")), /toy_read: says 2 operations, but 1 list it/],
    ["a tool with no tool name for an operation", (m) => (m.operations.find((o) => o.operation === "create_note").tool = null), /no tool, but toy_change runs the change group/],
    ["an unknown tier", (m) => (m.operations.find((o) => o.operation === "create_note").tier = "admin"), /unknown tier "admin"/],
    ["an unknown flag", (m) => (m.operations.find((o) => o.operation === "create_transfer").flags = { trusted: true }), /unknown flag trusted/],
    ["a non-boolean flag", (m) => (m.operations.find((o) => o.operation === "create_transfer").flags = { egress: "yes" }), /flag egress must be true or false/],
    ["a duplicate operation", (m) => m.operations.push({ ...m.operations[0] }), /duplicate operation/],
    ["a duplicate tool", (m) => m.tools.push({ ...m.tools[0] }), /duplicate tool name/],
    ["a group tool renamed into another group", (m) => (m.tools.find((t) => t.name === "toy_read").group = "change"), /named for the read group but in the change group/],
    ["a wrong manifest version", (m) => (m.manifest_version = 2), /expected 1, found 2/],
    ["an invalid server name", (m) => (m.server = "../toy"), /not a valid server name/],
    ["a missing guard_version", (m) => delete m.guard_version, /guard_version: missing or not a string/],
  ];
  for (const [name, edit, expected] of cases) {
    const m = clone(toy());
    edit(m);
    const r = checkManifest(m);
    assert.equal(r.ok, false, `${name}: should fail`);
    assert.ok(
      fails(r).some((f) => expected.test(f)),
      `${name}: expected ${expected}, got ${JSON.stringify(fails(r))}`
    );
  }
});

test("a non-object manifest fails without throwing", () => {
  for (const raw of [null, [], "x", 3]) assert.equal(checkManifest(raw).ok, false);
  assert.equal(checkManifest({ manifest_version: 1, server: "toy", version: "1", guard_version: "1", prefix: "toy", tools: "x", operations: {} }).ok, false);
});

test("manifest --package and the default ./dist location", async (t) => {
  const dir = writePackage(t, toy());
  const r = await cli(["manifest", "--package", dir, "--json"]);
  assert.equal(r.code, 0);
  assert.equal(r.json.ok, true);
  assert.equal(r.json.path, join(dir, "dist", "guard-manifest.json"));

  const here = await cli(["manifest"], { cwd: dir });
  assert.equal(here.code, 0);
  assert.match(here.text, /: ok \(toy\), 4 tools, 6 operations \(read 2, write 1, destructive 1, spend 1, blocked 1\)/);

  const explicit = await cli(["manifest", "--manifest", join(dir, "dist", "guard-manifest.json")]);
  assert.equal(explicit.code, 0);
});

test("manifest exits 1 on a failed check, a missing file or bad JSON", async (t) => {
  const bad = clone(toy());
  bad.tools.find((t) => t.name === "toy_change").annotations.readOnlyHint = true;
  const dir = writePackage(t, bad);
  const r = await cli(["manifest", "--package", dir]);
  assert.equal(r.code, 1);
  assert.match(r.text, /FAILED/);

  const empty = tempDir(t);
  const missing = await cli(["manifest"], { cwd: empty });
  assert.equal(missing.code, 1);
  assert.match(missing.errText, /Cannot read .*guard-manifest\.json/);

  const garbled = writePackage(t, null, "{ nope");
  const g = await cli(["manifest", "--package", garbled]);
  assert.equal(g.code, 1);
  assert.match(g.errText, /is not valid JSON/);

  const both = await cli(["manifest", "--package", dir, "--manifest", "x.json"]);
  assert.equal(both.code, 2);
});

test("a manifest saved with a byte-order mark still loads", async (t) => {
  const dir = writePackage(t, null, `﻿${JSON.stringify(toy())}`);
  const r = await cli(["manifest", "--package", dir]);
  assert.equal(r.code, 0);
});
