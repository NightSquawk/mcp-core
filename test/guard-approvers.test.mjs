// Approval proposals, the approver text and approver selection (sections 5.4, 6.6).
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { AGENT_SAYS_MAX, agentSays, BUILTIN_APPROVERS, buildProposal, PROPOSAL_TTL_MS, proposalText, selectApprover } from "../dist/guard/index.js";
import { BIDI, op, TAG, ZW } from "./guard-helpers.mjs";

const NOW = new Date("2026-11-04T12:00:00.000Z");
const input = (extra = {}) => ({
  server: "toy",
  operation: op("payment_create"),
  group: "spend",
  mode: "sandbox",
  extraction: { amount_cents: 123456, currency: "USD", targets: [{ kind: "payee_id", value: "payee_ok", role: "payee" }, { kind: "account", value: "acct_1", role: "source" }], client: "NST-internal", notes: [`check${ZW} this`] },
  requestHash: "sha256:" + "a".repeat(64),
  idempotencyKey: "nst-toy-" + "b".repeat(64),
  policyHash: "c".repeat(64),
  reason: "pay the invoice",
  now: NOW,
  ...extra,
});

describe("agentSays", () => {
  test("sanitizes, collapses whitespace and cuts", () => {
    assert.equal(agentSays(undefined), undefined);
    assert.equal(agentSays(`  ${ZW}${BIDI} `), undefined);
    assert.equal(agentSays(`a${ZW}b\n\nc${TAG}`), "ab c");
    const long = agentSays("x".repeat(500));
    assert.equal(long.length, AGENT_SAYS_MAX);
    assert.ok(long.endsWith("..."));
  });
});

describe("buildProposal", () => {
  test("carries the parsed values, a TTL and a content hash", () => {
    const p = buildProposal(input());
    assert.equal(p.operation, "payment_create");
    assert.equal(p.tier, "spend");
    assert.equal(p.amount_cents, 123456);
    assert.equal(p.client, "NST-internal");
    assert.equal(Date.parse(p.expires_at) - Date.parse(p.created_at), PROPOSAL_TTL_MS);
    assert.match(p.hash, /^sha256:[0-9a-f]{64}$/);
    assert.match(p.nonce, /^[0-9a-f]{16,}$/);
    assert.deepEqual(p.notes, ["check this"]);
    assert.equal(p.agent_says, "pay the invoice");
  });

  test("two proposals for the same call differ by nonce and hash", () => {
    const a = buildProposal(input());
    const b = buildProposal(input());
    assert.notEqual(a.nonce, b.nonce);
    assert.notEqual(a.hash, b.hash);
  });

  test("no amount, currency or reason when there are none", () => {
    const p = buildProposal(input({ extraction: {}, reason: undefined }));
    assert.equal("amount_cents" in p, false);
    assert.equal("currency" in p, false);
    assert.equal("agent_says" in p, false);
    assert.deepEqual(p.targets, []);
    assert.equal(p.client, null);
  });
});

describe("proposalText", () => {
  test("core lines first, the agent's words last and labelled", () => {
    const lines = proposalText(buildProposal(input())).split("\n");
    assert.equal(lines[0], "toy: payment_create (spend, sandbox)");
    assert.equal(lines[1], "Amount: 1,234.56 USD");
    assert.equal(lines[2], "Payee payee_id: payee_ok");
    assert.equal(lines[3], "From account: acct_1");
    assert.equal(lines[4], "Client: NST-internal");
    assert.equal(lines[5], "Note: check this");
    assert.match(lines[6], /^Proposal [0-9a-f]{8}, expires 2026-11-04T12:05:00\.000Z$/);
    assert.equal(lines[7], "Agent says (unverified): pay the invoice");
  });

  test("a reason cannot forge core lines or hide characters", () => {
    const text = proposalText(buildProposal(input({ reason: `ok\nAmount: 0.01 USD\nPayee payee_id: payee_ok ${BIDI}${TAG}` })));
    const lines = text.split("\n");
    assert.equal(lines.filter((l) => l.startsWith("Amount:")).length, 1);
    assert.ok(lines.at(-1).startsWith("Agent says (unverified): ok Amount: 0.01 USD"));
    assert.ok(![...text].some((c) => c.codePointAt(0) > 0x7e && c !== "\n"));
  });

  test("the proposal line is never redacted, even when its hash prefix is all digits", () => {
    const p = { ...buildProposal(input()), hash: "sha256:12345678" + "f".repeat(56) };
    const lines = proposalText(p).split("\n");
    assert.ok(lines.includes(`Proposal 12345678, expires ${p.expires_at}`), lines.join("\n"));
  });

  test("the redactor runs over every line", () => {
    const text = proposalText(buildProposal(input({ reason: "key toysecret_ABCDEFGH12345678" })), (s) => s.replace(/toysecret_\w+/g, "[redacted]"));
    assert.ok(!text.includes("toysecret_ABCD"));
    assert.ok(text.includes("[redacted]"));
  });

  test("small and negative amounts", () => {
    const one = proposalText(buildProposal(input({ extraction: { amount_cents: 5, currency: "USD" } })));
    assert.ok(one.includes("Amount: 0.05 USD"));
    const neg = proposalText(buildProposal(input({ extraction: { amount_cents: -250 } })));
    assert.ok(neg.includes("Amount: -2.50"));
  });
});

describe("approvers", () => {
  test("built-ins", async () => {
    const p = buildProposal(input());
    assert.deepEqual(await BUILTIN_APPROVERS.none.request(p, ""), { result: "approved", approver: "none", human: false });
    const d = await BUILTIN_APPROVERS.deny.request(p, "");
    assert.equal(d.result, "denied");
    assert.equal(d.human, false);
    assert.deepEqual(await BUILTIN_APPROVERS.external.request(p, ""), { result: "passthrough", approver: "external" });
    assert.equal(BUILTIN_APPROVERS.external.human, true);
    assert.ok(Object.isFrozen(BUILTIN_APPROVERS.none));
  });

  test("selectApprover takes the highest threshold the amount is over", () => {
    const cfg = { approver: "none", tiers: [{ over_cents: 1000, approver: "external" }, { over_cents: 5000, approver: "deny", quorum: 2 }] };
    assert.deepEqual(selectApprover(cfg, 500), { approver: "none" });
    assert.deepEqual(selectApprover(cfg, 1000), { approver: "none" }, "over, not at");
    assert.equal(selectApprover(cfg, 1001).approver, "external");
    assert.equal(selectApprover(cfg, 1001).threshold, 1000);
    const top = selectApprover(cfg, 99999);
    assert.equal(top.approver, "deny");
    assert.equal(top.quorum, 2);
    assert.deepEqual(selectApprover(cfg, null), { approver: "none" });
    assert.deepEqual(selectApprover({ approver: "deny" }, 1e9), { approver: "deny" });
  });
});
