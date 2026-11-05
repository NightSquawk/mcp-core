// Fixes from the foundation review: idempotency window and corrupt-store handling at the
// guard level, key length floor, BOM policies, and the protection probes (user namespaces,
// narrow NOPASSWD rules, Windows owners and reparse points, admin-equivalent groups).
import assert from "node:assert/strict";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import {
  AuditLog,
  canonicalJson,
  checkProtection,
  DOAS_CONFIG_DIR,
  DOAS_CONFIG_FILES,
  createGuard,
  deriveKey,
  hasUnsafePathChar,
  IDENTITY_UID_MAP,
  Ledger,
  loadPolicy,
  MIN_KEY_LENGTH,
  parseDoasConfig,
  parseWindowsOwners,
  posixPart1,
  posixPart2,
  POWERSHELL_SINGLE_QUOTES,
  programDataDir,
  psSingleQuoted,
  realProbes,
  refuse,
  staticProtection,
  TIER_GROUP,
  TRUSTED_OWNER_SIDS,
  windowsOwnersScript,
  windowsPart1,
  windowsPart2,
} from "../dist/guard/index.js";
import { ALL_ON, manualClock, op, sandbox, SECRET, stub, toyExtract } from "./guard-helpers.mjs";

const MIN = 60_000;

function mk(t, clock, guardOpts = {}) {
  const sb = sandbox(t);
  sb.writePolicy(ALL_ON);
  const guard = createGuard({
    server: "toy",
    version: "1.0.0",
    env: sb.env,
    mode: "sandbox",
    clock,
    protection: staticProtection(true, sb.policyPath),
    secrets: () => [SECRET],
    stateDir: sb.stateDir,
    log: () => {},
    ...guardOpts,
  });
  return { guard, sb };
}

const exec = (guard, id, request, handler) => {
  const o = op(id);
  const group = TIER_GROUP[o.tier] ?? "change";
  return guard.execute({ tool: `toy_${group}`, group, operation: o, operationId: id, request, reason: "hardening test", hooks: { extract: toyExtract(refuse) } }, handler);
};
const boom = () => stub(() => ({ ok: false, status: 502, error: { message: "bad gateway" }, sent: true }));
const PAY = { pathParams: { id: "inv_1" }, body: { amount: 500, currency: "USD" } };

// ------------------------------------------------------------------ idempotency through the guard

for (const [id, request] of [
  ["thing_create", { body: { a: 1 } }],
  ["invoice_pay", PAY],
]) {
  test(`guard: an unknown outcome (${id}, no provider key) is never re-run after the window`, async (t) => {
    const clock = manualClock();
    const { guard } = mk(t, clock);
    assert.equal((await exec(guard, id, request, boom())).status, "unknown_outcome");
    for (const after of [5 * MIN, 6 * MIN, 60 * MIN]) {
      clock.advance(after);
      const h = stub();
      const r = await exec(guard, id, request, h);
      assert.equal(h.calls.length, 0, `re-executed after ${after / MIN} more minutes: ${JSON.stringify(r)}`);
      assert.equal(r.status === "refused" && r.refusal.reason_code, "outcome_unknown");
    }
  });
}

test("guard: a done call is answered from the store inside the window and runs again after it", async (t) => {
  const clock = manualClock();
  const { guard } = mk(t, clock);
  const first = stub();
  assert.equal((await exec(guard, "thing_create", { body: { a: 1 } }, first)).status, "done");
  clock.advance(5 * MIN);
  assert.equal((await exec(guard, "thing_create", { body: { a: 1 } }, stub())).status, "deduplicated");
  clock.advance(6 * MIN);
  const later = stub();
  assert.equal((await exec(guard, "thing_create", { body: { a: 1 } }, later)).status, "done");
  assert.equal(later.calls.length, 1);
});

test("guard: an unreadable idempotency store refuses (state_unreadable), runs nothing and keeps the file", async (t) => {
  const clock = manualClock();
  const { guard } = mk(t, clock);
  assert.equal((await exec(guard, "thing_create", { body: { a: 1 } }, stub())).status, "done");
  const file = guard.idempotency.file;
  writeFileSync(file, '{"version":1,"entries":{"x":');
  for (const body of [{ a: 1 }, { a: 2 }]) {
    const h = stub();
    const r = await exec(guard, "thing_create", { body }, h);
    assert.equal(r.status, "refused");
    assert.equal(r.refusal.reason_code, "state_unreadable");
    assert.match(r.refusal.how_to_enable, /idempotency/);
    assert.equal(h.calls.length, 0);
  }
  assert.equal(readFileSync(file, "utf8"), '{"version":1,"entries":{"x":', "the bad file is kept for a human");
  for (const bad of ["null", "[]", '{"version":1,"entries":[]}', '{"version":1,"entries":{"k":null}}', '{"version":1,"entries":{"k":{"key":"k","status":"done","created_at":"never"}}}']) {
    writeFileSync(file, bad);
    const r = await exec(guard, "thing_create", { body: { a: 3 } }, stub());
    assert.equal(r.status === "refused" && r.refusal.reason_code, "state_unreadable", bad);
  }
});

test("guard: a store that breaks after the call was sent still returns the result and audits it", async (t) => {
  const clock = manualClock();
  const { guard } = mk(t, clock);
  const file = guard.idempotency.file;
  const h = stub(() => {
    writeFileSync(file, "garbage");
    return { ok: true, status: 200, data: { id: "obj_1" }, providerIds: ["obj_1"] };
  });
  const r = await exec(guard, "thing_create", { body: { a: 1 } }, h);
  assert.equal(r.status, "done", JSON.stringify(r));
  assert.ok(r.warnings?.some((w) => /could not record this call/.test(w)), JSON.stringify(r.warnings));
  const last = guard.audit.read().at(-1);
  assert.equal(last.decision, "executed");
  assert.match(last.note, /could not record this call/);
});

test("guard: a pending hold is never re-sent after the window", async (t) => {
  const clock = manualClock();
  const { guard } = mk(t, clock);
  const o = op("thing_create");
  const run = (h) =>
    guard.execute(
      { tool: "toy_change", group: "change", operation: o, operationId: o.operationId, request: { body: { a: 9 } }, reason: "hold", hooks: { extract: toyExtract(refuse), external: () => ({ held: true, ref: "apr_1", status: "pre_review" }) } },
      h
    );
  assert.equal((await run(stub())).status, "pending");
  clock.advance(30 * MIN);
  const again = stub();
  const r = await run(again);
  assert.equal(again.calls.length, 0, JSON.stringify(r));
  assert.equal(r.status, "deduplicated");
});

test("createGuard: refuses an idempotency key limit below the floor", (t) => {
  assert.throws(() => mk(t, manualClock(), { idempotencyMaxLength: MIN_KEY_LENGTH - 1 }), /idempotencyMaxLength/);
  assert.throws(() => mk(t, manualClock(), { idempotencyMaxLength: 40.5 }), /idempotencyMaxLength/);
  assert.ok(mk(t, manualClock(), { idempotencyMaxLength: MIN_KEY_LENGTH }).guard);
});

test("deriveKey: the label is cut before the digest, and a tiny limit keeps only digest", () => {
  const base = { server: "column", operation: "x", canonicalBody: "{}", proposalDay: "2026-11-04" };
  const k = deriveKey({ ...base, server: "a".repeat(64), maxLength: 40 });
  assert.equal(k.length, 40);
  assert.match(k, /^nst-a{11}-[0-9a-f]{24}$/);
  const tiny = deriveKey({ ...base, maxLength: 20 });
  assert.match(tiny, /^nst-[0-9a-f]{16}$/);
  assert.notEqual(tiny, deriveKey({ ...base, canonicalBody: "{ }", maxLength: 20 }));
  assert.equal(deriveKey({ ...base, maxLength: 255 }).length, "nst-column-".length + 64);
});

// ------------------------------------------------------------------ canonical, audit, ledger, policy

test("canonicalJson: toJSON returning a primitive, nested __proto__ in arrays, functions dropped", () => {
  assert.equal(canonicalJson([{ toJSON: () => 5 }]), "[5]");
  const v = JSON.parse('[{"__proto__":{"x":1}}]');
  assert.equal(canonicalJson(v), '[{"__proto__":{"x":1}}]');
  assert.equal(canonicalJson({ a: () => 1, b: 2 }), '{"b":2}');
});

test("audit and ledger: lines that parse but are not audit lines are skipped, never thrown on", (t) => {
  const sb = sandbox(t);
  const clock = manualClock();
  const log = new AuditLog(sb.stateDir, "toy", { clock });
  log.append({ server: "toy", version: "1", guard: "x", session: "s", tool: "toy_spend", operation: "invoice_pay", tier: "spend", group: "spend", mode: "sandbox", decision: "executed", dry_run: false, amount_cents: 500, currency: "USD" });
  const file = log.fileFor("2026-11");
  appendFileSync(file, 'null\n[1,2]\n{"ts":"not a date","hash":"sha256:x","group":"spend","operation":"o","decision":"executed"}\n');
  appendFileSync(file, JSON.stringify({ ts: "2026-11-04T12:00:00.000Z", hash: "sha256:" + "0".repeat(64), group: "spend", operation: "o", decision: "executed", amount_cents: "999", currency: "USD" }) + "\n");
  assert.equal(log.read().length, 2);
  const ledger = new Ledger(join(sb.root, "other"), { clock, audit: log });
  assert.equal(ledger.snapshot().spendToday("USD"), 500, "a string amount is not added (or concatenated)");
});

test("loadPolicy: a UTF-8 byte order mark is accepted", (t) => {
  const sb = sandbox(t);
  mkdirSync(join(sb.env.NST_MCP_POLICY_DIR, "toy"), { recursive: true });
  writeFileSync(sb.policyPath, String.fromCharCode(0xfeff) + JSON.stringify({ version: 1, server: "toy", groups: { read: true, change: true } }));
  const loaded = loadPolicy({ server: "toy", env: sb.env });
  assert.equal(loaded.error, undefined, loaded.error);
  assert.equal(loaded.source, "file");
  assert.equal(loaded.policy.groups.change, true);
});

test("loadPolicy: schema messages say what is expected", (t) => {
  const sb = sandbox(t);
  writeFileSync(sb.policyPath, JSON.stringify({ version: 1, server: "Toy!", canaries: { hashes: ["md5:x"] } }));
  const loaded = loadPolicy({ server: "toy", env: sb.env });
  assert.match(loaded.error, /server: the server name/);
  assert.match(loaded.error, /canaries\.hashes\.0: "sha256:" followed by 64/);
});

// ------------------------------------------------------------------ protection probes

function probes({ platform = "linux", files = {}, runs = {}, uid = 1000, env = {}, texts = {}, dirs, owners, creatable = [], writable = [] } = {}) {
  const calls = { run: [], readText: [], windowsOwners: [] };
  return {
    calls,
    platform,
    env,
    lstat: (p) => files[p] ?? null,
    readlink: () => null,
    run(cmd, args) {
      const key = [cmd, ...args].join(" ");
      calls.run.push(key);
      const r = runs[key] ?? runs[cmd];
      return r ? { stdout: "", stderr: "", ...r } : { status: null, stdout: "", stderr: "", error: "ENOENT" };
    },
    getuid: () => uid,
    canOpenForWrite: (p) => writable.includes(p),
    canCreateIn: (d) => creatable.includes(d),
    readText(p) {
      calls.readText.push(p);
      return p in texts ? texts[p] : null;
    },
    // Left out, the probe is missing, as in a hand-made double.
    ...(dirs === undefined ? {} : { listDir: (p) => (p in dirs ? [...dirs[p]] : null) }),
    ...(owners === undefined
      ? {}
      : {
          windowsOwners(paths) {
            calls.windowsOwners.push([...paths]);
            return typeof owners === "function" ? owners(paths) : owners;
          },
        }),
  };
}
const dir = (uid = 0) => ({ isFile: false, isDirectory: true, isSymbolicLink: false, uid, mode: 0o40755 });
const file = (uid = 0) => ({ isFile: true, isDirectory: false, isSymbolicLink: false, uid, mode: 0o100644 });
const POLICY = "/etc/nightsquawk-mcp/toy/policy.json";
const TREE = { "/": dir(), "/etc": dir(), "/etc/nightsquawk-mcp": dir(), "/etc/nightsquawk-mcp/toy": dir(), [POLICY]: file() };

test("posixPart1: the identity uid_map passes; a user namespace or an unreadable map is a reason", () => {
  const ok = probes({ files: TREE, texts: { "/proc/self/uid_map": `         0          0 4294967295\n` } });
  assert.deepEqual(posixPart1(POLICY, ok), { ok: true, reasons: [] });
  const ns = posixPart1(POLICY, probes({ files: TREE, texts: { "/proc/self/uid_map": "         0       1000          1\n         1     100000      65536\n" } }));
  assert.equal(ns.ok, false);
  assert.ok(ns.reasons.some((r) => /user namespace \(uid_map "0 1000 1 1 100000 65536"\)/.test(r)), JSON.stringify(ns.reasons));
  const unreadable = posixPart1(POLICY, probes({ files: TREE }));
  assert.ok(unreadable.reasons.some((r) => /Cannot read \/proc\/self\/uid_map/.test(r)));
  const mac = probes({ platform: "darwin", files: TREE });
  assert.equal(posixPart1(POLICY, mac).ok, true, "no /proc on macOS");
  assert.deepEqual(mac.calls.readText, []);
  assert.equal(IDENTITY_UID_MAP, "0 0 4294967295");
});

const ID_OK = { "id -Gn": { status: 0, stdout: "kim users\n" } };

test("posixPart2: a narrow NOPASSWD rule listed by sudo -n -l is a reason; a listing without one is not", () => {
  const listing = "User kim may run the following commands on host:\n    (root) NOPASSWD: /usr/bin/systemctl restart nginx\n    (ALL : ALL) ALL\n";
  const narrow = probes({ runs: { ...ID_OK, "sudo -n true": { status: 1, stderr: "sudo: a password is required\n" }, "sudo -n -l": { status: 0, stdout: listing } } });
  const part = posixPart2(narrow);
  assert.equal(part.ok, false);
  assert.ok(part.reasons.some((r) => r.includes("NOPASSWD: /usr/bin/systemctl restart nginx")), JSON.stringify(part.reasons));
  assert.deepEqual(narrow.calls.run, ["sudo -n true", "sudo -n -l", "doas -n true", "id -Gn"]);
  const never = probes({ runs: { ...ID_OK, "sudo -n true": { status: 1 }, "sudo -n -l": { status: 0, stdout: "    (ALL : ALL) ALL\n" } } });
  assert.deepEqual(posixPart2(never), { ok: true, reasons: [] }, "listpw=never: a listing with no NOPASSWD rule");
  const asks = probes({ runs: { ...ID_OK, sudo: { status: 1, stderr: "sudo: a password is required\n" } } });
  assert.deepEqual(posixPart2(asks), { ok: true, reasons: [] });
  const many = probes({ runs: { ...ID_OK, "sudo -n true": { status: 1 }, "sudo -n -l": { status: 0, stdout: "(root) NOPASSWD: /a\n(root) NOPASSWD: /b\n(root) NOPASSWD: /c\n(root) NOPASSWD:SETENV: /d\n" } } });
  assert.ok(posixPart2(many).reasons.some((r) => /\(\+1 more\)/.test(r)));
  const killed = probes({ runs: { ...ID_OK, "sudo -n true": { status: 1 }, "sudo -n -l": { status: null, signal: "SIGTERM", error: "ETIMEDOUT" } } });
  assert.ok(posixPart2(killed).reasons.some((r) => /Could not list this user's sudo rules/.test(r)));
  const doasKilled = probes({ runs: { ...ID_OK, doas: { status: null, signal: "SIGKILL" } } });
  assert.ok(posixPart2(doasKilled).reasons.some((r) => /doas needs a password: "doas -n true" was killed \(SIGKILL\)/.test(r)));
});

// doas refuses "true" (no rule for it, or one that asks for a password); its rules are read instead.
const DOAS_REFUSES = { status: 1, stderr: "doas: Operation not permitted\n" };
const CONF = { isFile: true, isDirectory: false, isSymbolicLink: false, uid: 0, mode: 0o100644 };
const FOLDER = { isFile: false, isDirectory: true, isSymbolicLink: false, uid: 0, mode: 0o40755 };
const KIM = { ...ID_OK, doas: DOAS_REFUSES, "id -un": { status: 0, stdout: "kim\n" }, "id -G": { status: 0, stdout: "1000 100\n" } };
const doasWith = (conf, extra = {}) => probes({ runs: KIM, files: { "/etc/doas.conf": CONF }, texts: { "/etc/doas.conf": conf }, ...extra });

test("parseDoasConfig: reads rules the way doas does", () => {
  const conf = parseDoasConfig(
    [
      "# admins type their password",
      "permit persist :wheel",
      "permit nopass kim as root cmd /usr/bin/tee args /etc/hosts # one command",
      'permit nopass keepenv setenv { PATH=/bin FOO } :ops cmd "/usr/bin/my tool"',
      "permit \\",
      "    nopass bob",
      "permit no\\pass carol",
      "deny kim",
      "",
    ].join("\n"),
  );
  assert.equal(conf.error, undefined);
  assert.deepEqual(
    conf.rules.map((r) => [r.line, r.action, r.options.join(","), r.identity, r.target ?? "", r.cmd ?? "", (r.args ?? []).join(" ")]),
    [
      [2, "permit", "persist", ":wheel", "", "", ""],
      [3, "permit", "nopass", "kim", "root", "/usr/bin/tee", "/etc/hosts"],
      [4, "permit", "nopass,keepenv,setenv", ":ops", "", "/usr/bin/my tool", ""],
      [5, "permit", "nopass", "bob", "", "", ""],
      [7, "permit", "nopass", "carol", "", "", ""],
      [8, "deny", "", "kim", "", "", ""],
    ],
  );
  assert.equal(conf.rules[2].text, 'permit nopass keepenv setenv :ops cmd "/usr/bin/my tool"');
  // A quoted word is never a keyword, so this names a user called nopass and then has an extra word.
  assert.deepEqual(parseDoasConfig('permit "nopass" kim\n').error, { line: 1, message: '"kim" is not expected here' });
  for (const bad of ["permit nopass kim cmd\n", "deny nopass kim\n", "allow kim\n", 'permit nopass "kim\n', "permit setenv { A kim\n"]) {
    assert.ok(parseDoasConfig(bad).error, `${JSON.stringify(bad)} parsed without an error`);
  }
});

test("posixPart2: a doas rule without a password for one command, for the user or a group, is a reason", () => {
  const one = doasWith("permit persist :wheel\npermit nopass kim as root cmd /usr/bin/tee\n");
  const part = posixPart2(one);
  assert.equal(part.ok, false);
  assert.deepEqual(part.reasons, ['doas lets this user run commands without a password: /etc/doas.conf:2 "permit nopass kim as root cmd /usr/bin/tee".']);
  assert.deepEqual(one.calls.run, ["sudo -n true", "doas -n true", "id -Gn", "id -un", "id -G"]);
  for (const identity of [":users", ":100", "1000", "+1000"]) {
    assert.equal(posixPart2(doasWith(`permit nopass ${identity} cmd /usr/bin/systemctl\n`)).ok, false, identity);
  }
  // Rules for others, rules with a password, and deny rules are no path.
  assert.deepEqual(posixPart2(doasWith("permit nopass bob\npermit nopass :ops\npermit nopass 2000\npermit nopass :2000\n")), { ok: true, reasons: [] });
  const passwords = doasWith("permit persist :wheel\npermit kim\ndeny kim\n");
  assert.deepEqual(posixPart2(passwords), { ok: true, reasons: [] });
  assert.deepEqual(passwords.calls.run, ["sudo -n true", "doas -n true", "id -Gn"], "no rule without a password: nothing more to look up");
  // A later deny rule does not clear a rule without a password: remove the rule itself.
  assert.equal(posixPart2(doasWith("permit nopass kim\ndeny kim\n")).ok, false);
});

test("posixPart2: doas rules that cannot be read or followed fail closed", () => {
  const notEnabled = probes({ runs: { ...KIM, doas: { status: 1, stderr: "doas: doas is not enabled, /etc/doas.conf: No such file or directory\n" } } });
  assert.deepEqual(posixPart2(notEnabled), { ok: true, reasons: [] }, "no configuration: doas permits nothing");
  assert.deepEqual(notEnabled.calls.readText, []);
  const unreadable = posixPart2(probes({ runs: KIM, files: { "/etc/doas.conf": { ...CONF, mode: 0o100400 } } }));
  assert.ok(unreadable.reasons.some((r) => r.startsWith("Cannot read /etc/doas.conf, so this user's doas rules cannot be checked")), JSON.stringify(unreadable.reasons));
  const nowhere = posixPart2(probes({ runs: KIM }));
  assert.ok(nowhere.reasons.some((r) => r.includes(`its configuration is in none of ${DOAS_CONFIG_FILES.join(", ")}, ${DOAS_CONFIG_DIR}/*.conf`)), JSON.stringify(nowhere.reasons));
  const broken = posixPart2(doasWith("permit nopass kim cmd\n"));
  assert.deepEqual(broken.reasons, ["Cannot read the doas rules in /etc/doas.conf: line 1, cmd is followed by a command."]);
  const noName = posixPart2(doasWith("permit nopass kim\n", { runs: { ...KIM, "id -un": { status: 1 } } }));
  assert.ok(noName.reasons.some((r) => r.startsWith('Could not tell whether these doas rules without a password apply to this user ("id -un" or "id -G" failed): /etc/doas.conf:1')), JSON.stringify(noName.reasons));
  // A numeric rule is still decided by the uid alone.
  assert.equal(posixPart2(doasWith("permit nopass 2000\n", { runs: { ...KIM, "id -un": { status: 1 } } })).ok, true);
});

test("posixPart2: Alpine's /etc/doas.d/*.conf files are read too", () => {
  const files = { [DOAS_CONFIG_DIR]: FOLDER, "/etc/doas.d/20-wheel.conf": CONF, "/etc/doas.d/30-ops.conf": CONF, "/etc/doas.d/old": FOLDER };
  const texts = { "/etc/doas.d/20-wheel.conf": "permit persist :wheel\n", "/etc/doas.d/30-ops.conf": "permit nopass :users cmd /sbin/reboot\n" };
  const dirs = { [DOAS_CONFIG_DIR]: ["30-ops.conf", "README", "20-wheel.conf", "old"] };
  const p = probes({ runs: KIM, files, texts, dirs });
  assert.deepEqual(posixPart2(p).reasons, ['doas lets this user run commands without a password: /etc/doas.d/30-ops.conf:1 "permit nopass :users cmd /sbin/reboot".']);
  assert.deepEqual(p.calls.readText, ["/etc/doas.d/20-wheel.conf", "/etc/doas.d/30-ops.conf"]);
  const unlisted = posixPart2(probes({ runs: KIM, files, texts, dirs: {} }));
  assert.ok(unlisted.reasons.includes(`Cannot list ${DOAS_CONFIG_DIR}, so the doas rules in it cannot be checked.`), JSON.stringify(unlisted.reasons));
  const noProbe = posixPart2(probes({ runs: KIM, files, texts }));
  assert.ok(noProbe.reasons.includes(`Cannot list ${DOAS_CONFIG_DIR}, so the doas rules in it cannot be checked.`), "a double without listDir fails closed");
});

const WIN = "C:\\ProgramData\\NightSquawk\\mcp\\toy\\policy.json";
const CHAIN = [WIN, "C:\\ProgramData\\NightSquawk\\mcp\\toy", "C:\\ProgramData\\NightSquawk\\mcp", "C:\\ProgramData\\NightSquawk", "C:\\ProgramData", "C:\\"];
const USER_SID = "S-1-5-21-1111-2222-3333-1001";
const owned = (owner, over = {}) => (paths) =>
  paths.map((p) => ({ path: p, owner: over[p]?.owner ?? owner, reparse: over[p]?.reparse ?? false, rights: over[p]?.rights === undefined ? 0 : over[p].rights }));

test("windowsPart1: every link must be owned by SYSTEM, Administrators or TrustedInstaller, with no reparse points", () => {
  const env = { ProgramData: "C:\\ProgramData" };
  const files = { [WIN]: file() };
  for (const sid of TRUSTED_OWNER_SIDS) {
    const p = probes({ platform: "win32", env, files, owners: owned(sid) });
    assert.deepEqual(windowsPart1(WIN, p), { ok: true, reasons: [] }, sid);
    assert.deepEqual(p.calls.windowsOwners, [CHAIN], "one call covering the file and each folder up to the drive root");
  }
  const userFile = windowsPart1(WIN, probes({ platform: "win32", env, files, owners: owned("S-1-5-18", { [WIN]: { owner: USER_SID } }) }));
  assert.equal(userFile.ok, false, "read-only now, but its owner can change the ACL back");
  assert.ok(userFile.reasons.includes(`${WIN} is owned by ${USER_SID}, not SYSTEM, Administrators or TrustedInstaller.`), JSON.stringify(userFile.reasons));
  const userTop = windowsPart1(WIN, probes({ platform: "win32", env, files, owners: owned("S-1-5-18", { "C:\\ProgramData\\NightSquawk": { owner: USER_SID } }) }));
  assert.ok(userTop.reasons.some((r) => r.startsWith("C:\\ProgramData\\NightSquawk is owned by")), "a user-created NightSquawk folder");
  const junction = windowsPart1(WIN, probes({ platform: "win32", env, files, owners: owned("S-1-5-32-544", { "C:\\ProgramData\\NightSquawk\\mcp": { reparse: true } }) }));
  assert.ok(junction.reasons.includes("C:\\ProgramData\\NightSquawk\\mcp is a junction or symbolic link."));
  // Above NightSquawk only owners and links count: whoever owns ProgramData or the drive root can replace everything below.
  const userPd = windowsPart1(WIN, probes({ platform: "win32", env, files, owners: owned("S-1-5-18", { "C:\\ProgramData": { owner: USER_SID } }) }));
  assert.ok(userPd.reasons.includes(`C:\\ProgramData is owned by ${USER_SID}, not SYSTEM, Administrators or TrustedInstaller.`), JSON.stringify(userPd.reasons));
  const movedPd = windowsPart1(WIN, probes({ platform: "win32", env, files, owners: owned("S-1-5-18", { "C:\\ProgramData": { reparse: true } }) }));
  assert.deepEqual(movedPd.reasons, ["C:\\ProgramData is a junction or symbolic link."], "a ProgramData moved with a junction");
  const userRoot = windowsPart1(WIN, probes({ platform: "win32", env, files, owners: owned("S-1-5-18", { "C:\\": { owner: USER_SID } }) }));
  assert.ok(userRoot.reasons.includes(`C:\\ is owned by ${USER_SID}, not SYSTEM, Administrators or TrustedInstaller.`), JSON.stringify(userRoot.reasons));
  const unreadable = windowsPart1(WIN, probes({ platform: "win32", env, files, owners: null }));
  assert.ok(unreadable.reasons.includes("Could not read the owners of the policy file and its folders."));
  const partial = windowsPart1(WIN, probes({ platform: "win32", env, files, owners: (paths) => owned("S-1-5-18")(paths.slice(1)) }));
  assert.ok(partial.reasons.includes(`Could not read the owner of ${WIN}.`));
  const nullOwner = windowsPart1(WIN, probes({ platform: "win32", env, files, owners: owned(null) }));
  assert.equal(nullOwner.ok, false);
  const caseless = windowsPart1(WIN, probes({ platform: "win32", env, files, owners: (paths) => paths.map((p) => ({ path: p.toUpperCase(), owner: "S-1-5-18", reparse: false, rights: 0 })) }));
  assert.equal(caseless.ok, true, "paths compare case-insensitively");
});

test("windowsPart1: a ProgramData redirect to a user folder is caught by the owner check", () => {
  const env = { ProgramData: "D:\\Users\\kim\\pd" };
  const policy = "D:\\Users\\kim\\pd\\NightSquawk\\mcp\\toy\\policy.json";
  const p = probes({ platform: "win32", env, files: { [policy]: file() }, owners: owned(USER_SID) });
  const part = windowsPart1(policy, p);
  assert.equal(part.ok, false);
  assert.deepEqual(p.calls.windowsOwners[0].slice(-5), ["D:\\Users\\kim\\pd\\NightSquawk", "D:\\Users\\kim\\pd", "D:\\Users\\kim", "D:\\Users", "D:\\"]);
  const blank = probes({ platform: "win32", env: { ProgramData: "  " }, files: { [WIN]: file() }, owners: owned("S-1-5-18") });
  assert.equal(windowsPart1(WIN, blank).ok, true, "a blank ProgramData falls back to C:\\ProgramData");
});

const csv = (...rows) => rows.map((r) => r.map((c) => `"${c}"`).join(",")).join("\r\n");
const MEDIUM = ["Mandatory Label\\Medium Mandatory Level", "Label", "S-1-16-8192", ""];
const UAC_OK = "\r\n    EnableLUA    REG_DWORD    0x1\r\n    ConsentPromptBehaviorUser    REG_DWORD    0x3\r\n";

test("windowsPart2: Backup, Server, Account and Print Operators are admin-equivalent", () => {
  for (const [sid, name] of [
    ["S-1-5-32-551", "Backup Operators"],
    ["S-1-5-32-549", "Server Operators"],
    ["S-1-5-32-548", "Account Operators"],
    ["S-1-5-32-550", "Print Operators"],
  ]) {
    const who = csv([`BUILTIN\\${name}`, "Alias", sid, "Group used for deny only"], MEDIUM);
    const part = windowsPart2(probes({ platform: "win32", runs: { whoami: { status: 0, stdout: who }, reg: { status: 0, stdout: UAC_OK } } }), []);
    assert.equal(part.ok, false, name);
    assert.ok(part.reasons.includes(`Member of admin-equivalent group(s): ${name}.`), JSON.stringify(part.reasons));
  }
  const plain = windowsPart2(probes({ platform: "win32", runs: { whoami: { status: 0, stdout: csv(MEDIUM) }, reg: { status: 0, stdout: UAC_OK } } }), []);
  assert.equal(plain.ok, true, JSON.stringify(plain.reasons));
});

test("checkProtection: a redirected ProgramData is noted", () => {
  const p = probes({ platform: "win32", env: { ProgramData: "D:\\pd" }, files: { "D:\\pd\\NightSquawk\\mcp\\toy\\policy.json": file() }, owners: owned("S-1-5-18"), runs: { whoami: { status: 0, stdout: csv(MEDIUM) }, reg: { status: 0, stdout: UAC_OK } } });
  const report = checkProtection("D:\\pd\\NightSquawk\\mcp\\toy\\policy.json", { override: false, probes: p });
  assert.ok(report.notes.some((n) => /ProgramData is D:\\pd, not C:\\ProgramData/.test(n)), JSON.stringify(report.notes));
});

test("parseWindowsOwners and windowsOwnersScript", () => {
  assert.deepEqual(parseWindowsOwners('[{"path":"C:\\\\a","owner":"S-1-5-18","reparse":false,"rights":0},{"path":"C:\\\\b","owner":null,"reparse":true,"rights":null}]'), [
    { path: "C:\\a", owner: "S-1-5-18", reparse: false, rights: 0 },
    { path: "C:\\b", owner: null, reparse: true, rights: null },
  ]);
  assert.deepEqual(parseWindowsOwners('{"path":"C:\\\\a","owner":"S-1-5-32-544","reparse":false,"rights":262144}'), [{ path: "C:\\a", owner: "S-1-5-32-544", reparse: false, rights: 262144 }], "PowerShell may unwrap a one-item array");
  assert.deepEqual(parseWindowsOwners('[{"path":"C:\\\\a","owner":"BUILTIN\\\\Administrators"}]'), [{ path: "C:\\a", owner: null, reparse: false, rights: null }], "only SIDs count");
  for (const bad of ["", "not json", "42", '[{"owner":"S-1-5-18"}]', "[null]"]) assert.equal(parseWindowsOwners(bad), null, bad);
  const script = windowsOwnersScript(["C:\\ProgramData\\Nightsquawk", "C:\\it's here"]);
  assert.ok(!/[\r\n]/.test(script), "one line, so -Command - runs it without a trailing blank line");
  assert.ok(script.includes("'C:\\it''s here'"), "single quotes are doubled inside a PowerShell literal");
  assert.ok(script.includes("GetOwner([System.Security.Principal.SecurityIdentifier])"));
  assert.ok(script.includes("GetAccessRules($true, $true, $sid)"), "explicit and inherited entries, by SID");
  assert.ok(script.includes("((([int]$e.PropagationFlags) -band 2) -eq 0)"), "inherit-only entries do not apply to the path itself");
});

test("realProbes: has the user-namespace and owner probes, and readText fails soft", () => {
  const p = realProbes();
  assert.equal(typeof p.readText, "function");
  assert.equal(typeof p.windowsOwners, "function");
  assert.equal(p.readText(join("/nonexistent-dir-for-test", "x")), null);
  if (process.platform === "linux") assert.notEqual(p.readText("/proc/self/uid_map"), null);
});

test("psSingleQuoted doubles every PowerShell quote character, so a path cannot leave the literal", () => {
  assert.deepEqual([...POWERSHELL_SINGLE_QUOTES], [0x27, 0x2018, 0x2019, 0x201a, 0x201b]);
  for (const cp of POWERSHELL_SINGLE_QUOTES) {
    const q = String.fromCharCode(cp);
    assert.equal(psSingleQuoted(`C:\\a${q}b`), `'C:\\a${q}${q}b'`, `U+${cp.toString(16)}`);
  }
  // A breakout attempt: close the literal with U+2019, run a command, reopen with U+2018.
  const open = String.fromCharCode(0x2018);
  const close = String.fromCharCode(0x2019);
  const evil = `C:\\x${close}; Write-Output pwned; ${open}`;
  const script = windowsOwnersScript([evil]);
  assert.ok(script.includes(`'C:\\x${close}${close}; Write-Output pwned; ${open}${open}'`), script);
  // Every quote character in the literal is paired, so the literal ends only at the final ASCII quote.
  const lit = psSingleQuoted(evil).slice(1, -1);
  let i = 0;
  while (i < lit.length) {
    const c = lit.charCodeAt(i);
    if (POWERSHELL_SINGLE_QUOTES.includes(c)) {
      assert.equal(lit.charCodeAt(i + 1), c, `unpaired quote at ${i}`);
      i += 2;
    } else i += 1;
  }
});

test("hasUnsafePathChar: controls and line separators are refused; psSingleQuoted throws; the owner probe fails closed", () => {
  for (const cp of [0x00, 0x09, 0x0a, 0x0d, 0x1f, 0x7f, 0x85, 0x9f, 0x2028, 0x2029]) {
    const p = `C:\\a${String.fromCharCode(cp)}b`;
    assert.equal(hasUnsafePathChar(p), true, `U+${cp.toString(16)}`);
    assert.throws(() => psSingleQuoted(p), RangeError);
    assert.throws(() => windowsOwnersScript([p]), RangeError);
  }
  for (const ok of ["C:\\ProgramData\\NightSquawk", "C:\\it's here", `C:\\caf${String.fromCharCode(0xe9)}`, "D:/x y/z"]) assert.equal(hasUnsafePathChar(ok), false, ok);
  const cr = `C:\\ProgramData${String.fromCharCode(13)}Write-Output S-1-5-18`;
  assert.equal(realProbes().windowsOwners([cr]), null);
});

test("programDataDir: a value holding a control character or line separator falls back to the default", () => {
  for (const cp of [0x0a, 0x0d, 0x00, 0x85, 0x2028]) {
    assert.equal(programDataDir({ ProgramData: `C:\\Users\\me${String.fromCharCode(cp)}x` }), "C:\\ProgramData", `U+${cp.toString(16)}`);
  }
  const q = String.fromCharCode(0x2019);
  assert.equal(programDataDir({ ProgramData: `C:\\Users\\o${q}brien` }), `C:\\Users\\o${q}brien`, "a quote character is quoted later, not refused here");
});

test("redact and tokensOf stay linear on long adversarial strings", async () => {
  const { redact, redactValue } = await import("../dist/guard/index.js");
  const { tokensOf } = await import("../dist/guard/session.js");
  const N = 400_000;
  const inputs = {
    letters: "x".repeat(N),
    alnum: "a1".repeat(N / 2),
    dotted: "a.".repeat(N / 2),
    schemes: "a://".repeat(N / 4),
    dots: `a${".".repeat(N)}a`,
    dashes: `1${"-".repeat(N)}x`,
  };
  for (const [name, s] of Object.entries(inputs)) {
    const t0 = performance.now();
    redact(s);
    redactValue({ v: s });
    tokensOf(s);
    const ms = performance.now() - t0;
    // Quadratic forms take minutes here; linear ones a few milliseconds.
    assert.ok(ms < 2_000, `${name}: ${ms.toFixed(0)} ms`);
  }
  // The rules still do their job.
  assert.equal(redact("see https://user:pa55@example.com/x"), "see https://[redacted]@example.com/x");
  assert.equal(redact('{"u":"sftp://bob:pw@h"}'), '{"u":"sftp://[redacted]@h"}');
  assert.deepEqual(tokensOf("...abc-def..."), ["abc-def"]);
  assert.deepEqual(tokensOf(`a${".".repeat(10)}b`), [`a${".".repeat(10)}b`]);
  assert.deepEqual(tokensOf("+.-x1y2-.+"), ["x1y2"]);
});

test("credential keys are masked by name, whatever their value looks like", async () => {
  const { isSensitiveKey, redactSensitiveKeys } = await import("../dist/guard/index.js");
  for (const k of ["password", "cipassword", "root_password", "Client-Secret", "api_key", "apiKey", "access_token", "privateKey", "secret_key", "key", "keys", "pin", "otp", "credentials", "tokens", "passphrase", "card-passcode"]) {
    assert.equal(isSensitiveKey(k), true, k);
  }
  for (const k of ["idempotency_key", "ssh_keys", "tokenid", "description", "account_number", "keyboard", "", "secret_name", "pinned", "address", "bypass"]) {
    assert.equal(isSensitiveKey(k), false, k);
  }
  assert.equal(isSensitiveKey("vault_phrase"), false);
  assert.equal(isSensitiveKey("vault-phrase", ["vault_phrase"]), true, "extra names match after the same normalization");

  const input = { user: "bob", password: "p4ss", nested: [{ token: 123 }, { mfa: { otp: "000111" } }], flags: { secret: true, key: null }, note: "has XSECRETX inside", creds: { credentials: { a: 1 } } };
  const out = redactSensitiveKeys(input, { secrets: ["XSECRETX"] });
  assert.deepEqual(out, {
    user: "bob",
    password: "[redacted]",
    nested: [{ token: "[redacted]" }, { mfa: { otp: "[redacted]" } }],
    flags: { secret: true, key: null },
    note: "has [redacted] inside",
    creds: { credentials: "[redacted]" },
  });
  assert.equal(input.password, "p4ss", "the input is not changed");
  assert.deepEqual(redactSensitiveKeys({ at: new Date(0), token: "t0k3n" }), { at: "1970-01-01T00:00:00.000Z", token: "[redacted]" }, "toJSON values are walked as JSON");
  let deep = { password: "x" };
  for (let i = 0; i < 80; i++) deep = { d: deep };
  assert.ok(JSON.stringify(redactSensitiveKeys(deep)).includes("[too deep]"));
  const t0 = performance.now();
  assert.equal(isSensitiveKey("x".repeat(400_000)), false);
  assert.equal(isSensitiveKey(`${"x".repeat(400_000)}_password`), true);
  assert.ok(performance.now() - t0 < 2_000, "linear in the key length");
});

test("notSecretKeys takes exact names out of the built-in rule; an added name stays masked", async () => {
  const { isBuiltInCredentialName, isSensitiveKey, redactSensitiveKeys } = await import("../dist/guard/index.js");
  assert.equal(isSensitiveKey("tokens"), true);
  assert.equal(isSensitiveKey("tokens", [], ["tokens"]), false);
  assert.equal(isSensitiveKey("lock-token", [], ["lock_token"]), false, "names match after normalizing");
  assert.equal(isSensitiveKey("access_token", [], ["lock-token"]), true, "only the exact name is exempt");
  assert.equal(isSensitiveKey("tokens", ["tokens"], ["tokens"]), true, "an added name wins");
  for (const n of ["token", "API_KEY", "password", "key", "Secret", "private-key"]) assert.equal(isBuiltInCredentialName(n), true, n);
  for (const n of ["tokens", "lock-token", "keys", "data", ""]) assert.equal(isBuiltInCredentialName(n), false, n);
  const out = redactSensitiveKeys({ tokens: ["root@pam!ci"], "lock-token": "abc", nested: { tokens: "x", token: "y" } }, { notSecretKeys: ["tokens", "lock-token"] });
  assert.deepEqual(out, { tokens: ["root@pam!ci"], "lock-token": "abc", nested: { tokens: "x", token: "[redacted]" } });
});

test("createGuard: notSecretKeys refuses a built-in credential name", (t) => {
  assert.throws(() => mk(t, manualClock(), { notSecretKeys: ["tokens", "api-key", "TOKEN"] }), /notSecretKeys cannot hold a built-in credential name \("api-key", "TOKEN"\)/);
  assert.ok(mk(t, manualClock(), { notSecretKeys: ["tokens", "lock-token"] }).guard);
});
