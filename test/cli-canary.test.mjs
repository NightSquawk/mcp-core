// mcp-guard canary add: salted hashes into the policy; writes only under the test override.
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { cli, dist, sandbox, tempDir, test } from "./cli-helpers.mjs";

const { canaryHash, Canaries } = await import(dist("guard/canaries.js"));
const { parseIds } = await import(dist("cli/canary.js"));

const SALT = "salt-for-tests-6f1c";
const SERVER = "cli-test-canary-zz";
const base = (server) => ({ version: 1, server, groups: { read: true, change: true, critical: false, spend: false } });
const policyOf = (sb, server) => JSON.parse(readFileSync(sb.policyFile(server), "utf8"));

/** Nothing the command prints may hold the salt or an id. */
function assertQuiet(r, secrets) {
  for (const s of secrets) {
    assert.ok(!r.text.includes(s), `stdout holds ${s}`);
    assert.ok(!r.errText.includes(s), `stderr holds ${s}`);
  }
}

test("parseIds keeps one id per line, trimmed, without blank lines", () => {
  assert.deepEqual(parseIds("vm-decoy-1\r\n\n  9999  \n\t\n"), ["vm-decoy-1", "9999"]);
  assert.deepEqual(parseIds(""), []);
});

test("--print gives the guard's own hashes, one per unique id, and writes nothing", async (t) => {
  const sb = sandbox(t, { NST_MCP_CANARY_SALT: SALT });
  const r = await cli(["canary", "add", "column", "decoy-1", "decoy-2", "decoy-1", "--print"], { env: sb.env });
  assert.equal(r.code, 0);
  assert.deepEqual(r.out, [canaryHash("decoy-1", SALT), canaryHash("decoy-2", SALT)]);
  assert.match(r.out[0], /^sha256:[0-9a-f]{64}$/);
  assert.equal(existsSync(sb.policyDir), false);
  assertQuiet(r, [SALT, "decoy-1", "decoy-2"]);
});

test("with the override it adds the hashes, keeps the rest of the policy, and the guard matches them", async (t) => {
  const sb = sandbox(t, { NST_MCP_CANARY_SALT: SALT });
  const earlier = canaryHash("older-decoy", SALT);
  sb.policy("column", { ...base("column"), allowlists: { counterparty: ["cp_1"] }, surfaces: { sandbox: true }, canaries: { hashes: [earlier] } });

  const r = await cli(["canary", "add", "column", "cp_decoy", "9999", "--json"], { env: sb.env });
  assert.equal(r.code, 0, r.errText);
  assert.equal(r.json.written, true);
  assert.equal(r.json.added, 2);
  const p = policyOf(sb, "column");
  assert.deepEqual(p.canaries.hashes, [earlier, canaryHash("cp_decoy", SALT), canaryHash("9999", SALT)]);
  assert.deepEqual(p.surfaces, { sandbox: true }, "a server's own keys stay");
  assert.deepEqual(p.allowlists, { counterparty: ["cp_1"] });
  assert.deepEqual(p.groups, base("column").groups);

  const hits = new Canaries(p.canaries.hashes, SALT);
  assert.equal(hits.match(["cp_other", "9999"]), "9999");
  assert.equal(hits.match(["cp_1"]), null);

  const status = await cli(["status", "column", "--json"], { env: sb.env });
  assert.equal(status.json.policy.error, undefined);

  const again = await cli(["canary", "add", "column", "9999"], { env: sb.env });
  assert.equal(again.code, 0);
  assert.match(again.text, /already a canary/);
  assert.deepEqual(policyOf(sb, "column").canaries.hashes.length, 3);
});

test("with the override, --file starts from a draft and creates the server's folder", async (t) => {
  const sb = sandbox(t, { NST_MCP_CANARY_SALT: SALT });
  const draft = join(tempDir(t, "mcp-guard-canary-draft-"), "draft.json");
  writeFileSync(draft, JSON.stringify(base("column")));
  const r = await cli(["canary", "add", "column", "decoy-x", "--file", draft], { env: sb.env });
  assert.equal(r.code, 0, r.errText);
  assert.deepEqual(policyOf(sb, "column"), { ...base("column"), canaries: { hashes: [canaryHash("decoy-x", SALT)] } });
  assert.deepEqual(JSON.parse(readFileSync(draft, "utf8")), base("column"), "the draft is left as it was");
  assertQuiet(r, [SALT, "decoy-x"]);
});

test("ids come from stdin when none are given; an empty list is a usage error", async (t) => {
  const sb = sandbox(t, { NST_MCP_CANARY_SALT: SALT });
  sb.policy("column", base("column"));
  const r = await cli(["canary", "add", "column"], { env: sb.env, stdin: "decoy-a\n\ndecoy-b\n" });
  assert.equal(r.code, 0, r.errText);
  assert.deepEqual(policyOf(sb, "column").canaries.hashes, [canaryHash("decoy-a", SALT), canaryHash("decoy-b", SALT)]);
  assertQuiet(r, [SALT, "decoy-a", "decoy-b"]);

  const none = await cli(["canary", "add", "column"], { env: sb.env, stdin: "\n  \n" });
  assert.equal(none.code, 2);
  assert.match(none.errText, /No decoy ids/);
});

test("without the salt, without a policy, or with a broken one, it refuses and writes nothing", async (t) => {
  const sb = sandbox(t);
  sb.policy("column", base("column"));
  const before = readFileSync(sb.policyFile("column"), "utf8");
  const noSalt = await cli(["canary", "add", "column", "decoy"], { env: sb.env });
  assert.equal(noSalt.code, 1);
  assert.match(noSalt.errText, /NST_MCP_CANARY_SALT/);
  assert.equal(readFileSync(sb.policyFile("column"), "utf8"), before);

  const env = { ...sb.env, NST_MCP_CANARY_SALT: SALT };
  const missing = await cli(["canary", "add", "other", "decoy"], { env });
  assert.equal(missing.code, 1);
  assert.match(missing.errText, /No policy at .*mcp-guard init other/);
  assert.equal(existsSync(sb.policyFile("other")), false);

  sb.policy("column", { ...base("column"), groups: { read: "yes" } });
  const broken = await cli(["canary", "add", "column", "decoy"], { env });
  assert.equal(broken.code, 1);
  assert.match(broken.errText, /does not match the policy schema/);
});

test("usage errors: no action, an unknown action, no server", async () => {
  const env = { NST_MCP_CANARY_SALT: SALT };
  for (const [argv, re] of [
    [["canary"], /needs an action/],
    [["canary", "remove", "column", "x"], /only one is add/],
    [["canary", "add"], /needs a server name/],
  ]) {
    const r = await cli(argv, { env });
    assert.equal(r.code, 2, argv.join(" "));
    assert.match(r.errText, re);
  }
});

test("standard paths on Linux: exit 3 with the updated policy in sudo tee commands", async (t) => {
  const target = `/etc/nightsquawk-mcp/${SERVER}/policy.json`;
  if (existsSync(target)) return t.skip(`${target} exists on this machine`);
  const dir = tempDir(t, "mcp-guard-canary-");
  const file = join(dir, "draft.json");
  writeFileSync(file, JSON.stringify({ ...base(SERVER), canaries: { hashes: [] } }));

  const r = await cli(["canary", "add", SERVER, "decoy", "--file", file, "--json"], { env: { NST_MCP_CANARY_SALT: SALT }, platform: "linux" });
  assert.equal(r.code, 3, r.text);
  assert.equal(r.json.written, false);
  assert.equal(r.json.path, target);
  assert.deepEqual(r.json.hashes, [canaryHash("decoy", SALT)]);
  const cmds = r.json.admin.commands;
  const tee = cmds.find((c) => c.startsWith(`sudo tee '${target}'`));
  assert.ok(tee, "writes the standard path through sudo tee");
  const body = tee.split("\n").slice(1, -1).join("\n");
  assert.deepEqual(JSON.parse(body), { ...base(SERVER), canaries: { hashes: [canaryHash("decoy", SALT)] } });
  assert.ok(cmds.includes(`sudo chmod 0644 '${target}'`));
  assert.equal(existsSync(target), false);

  const text = await cli(["canary", "add", SERVER, "decoy", "--file", file], { env: { NST_MCP_CANARY_SALT: SALT }, platform: "linux" });
  assert.equal(text.code, 3);
  assert.match(text.text, /starting from /);
  assert.match(text.text, /canary_salt_missing/);
  assertQuiet(text, [SALT, "decoy"]);
});
