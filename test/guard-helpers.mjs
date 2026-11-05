// Shared helpers for the guard-*.test.mjs files (not a test file: the runner only picks *.test.mjs).
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Hidden characters, built from code points so the test sources stay ASCII. */
export const ZW = String.fromCodePoint(0x200b);
export const BIDI = String.fromCodePoint(0x202e);
export const TAG = String.fromCodePoint(0xe0041);

/** A temp root with policy/ and state/ folders, removed when the test ends. */
export function sandbox(t, server = "toy") {
  const root = mkdtempSync(join(tmpdir(), "mcp-guard-unit-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const policyDir = join(root, "policy");
  mkdirSync(join(policyDir, server), { recursive: true });
  const env = { NST_MCP_POLICY_DIR: policyDir, NST_MCP_STATE_DIR: join(root, "state") };
  return {
    root,
    env,
    policyPath: join(policyDir, server, "policy.json"),
    stateDir: join(root, "state", server),
    writePolicy(policy) {
      writeFileSync(join(policyDir, server, "policy.json"), JSON.stringify({ version: 1, server, ...policy }, null, 2));
    },
  };
}

/** A clock the test moves by hand. */
export function manualClock(iso = "2026-11-04T12:00:00.000Z") {
  let now = Date.parse(iso);
  const clock = () => new Date(now);
  clock.advance = (ms) => {
    now += ms;
  };
  clock.set = (v) => {
    now = typeof v === "number" ? v : Date.parse(v);
  };
  return clock;
}

/** The toy catalog: one operation per tier and flag. */
export const OPS = Object.freeze([
  { operationId: "thing_list", tier: "read", method: "GET", path: "/things" },
  { operationId: "thing_get", tier: "read", method: "GET", path: "/things/{id}", flags: { untrusted_output: true } },
  { operationId: "thing_search", tier: "read", method: "POST", path: "/things/search" },
  { operationId: "thing_create", tier: "write", method: "POST", path: "/things" },
  { operationId: "thing_update", tier: "write", method: "PATCH", path: "/things/{id}" },
  { operationId: "thing_pause", tier: "reducing", method: "POST", path: "/things/{id}/pause" },
  { operationId: "thing_notify", tier: "write", method: "POST", path: "/things/{id}/notify", flags: { egress: true } },
  { operationId: "thing_delete", tier: "destructive", method: "DELETE", path: "/things/{id}" },
  { operationId: "payee_create", tier: "sensitive", method: "POST", path: "/payees" },
  { operationId: "payment_create", tier: "spend", method: "POST", path: "/payments", idempotencyKey: true },
  { operationId: "invoice_pay", tier: "spend", method: "POST", path: "/invoices/{id}/pay" },
  { operationId: "sim_settle", tier: "sandbox", method: "POST", path: "/simulate/settle" },
  { operationId: "payment_release", tier: "blocked", method: "POST", path: "/payments/{id}/release" },
]);

export const TIERS_FILE = Object.fromEntries(
  OPS.map((o) => [
    o.operationId,
    {
      tier: o.tier,
      ...(o.flags ? { flags: o.flags } : {}),
      ...(o.operationId === "thing_search" ? { read_reason: "Search takes its filters in a POST body and changes nothing." } : {}),
    },
  ])
);

export const SECRET = "toysecret_ABCDEFGH12345678";

export const SPEND_POLICY = {
  allowlists: { payee_id: ["payee_ok"] },
  limits: { spend: { unit: "cents", currency: "USD", per_call: 10000, per_day: 50000 } },
};

/** The toy extractor: payments name a payee; anything with an id path param names a subject. */
export function toyExtract(refuse) {
  return (op, req) => {
    const b = req.body ?? {};
    if (op.operationId === "payment_create") {
      if (b.payee_details) return refuse("inline_payee", "Inline payee details are refused; use an allowlisted payee_id.");
      return {
        amount_cents: b.amount,
        currency: b.currency,
        targets: b.payee_id === undefined ? [] : [{ kind: "payee_id", value: String(b.payee_id), role: "payee" }],
        ...(b.client ? { client: b.client } : {}),
      };
    }
    if (op.operationId === "invoice_pay") return { amount_cents: b.amount, currency: b.currency, targets: [], notes: ["no payee: pays the provider's own invoice"] };
    if (op.operationId === "payee_create") return { targets: b.payee_id ? [{ kind: "payee_id", value: String(b.payee_id), role: "payee" }] : [] };
    if (req.pathParams?.id !== undefined) return { targets: [{ kind: "thing_id", value: String(req.pathParams.id), role: "subject" }] };
    return {};
  };
}

export const ALL_ON = Object.freeze({
  groups: { read: true, change: true, critical: true, spend: true },
  environment: { allow_live: true },
  approval: { change: "none", critical: "none", spend: "none" },
  ...SPEND_POLICY,
});

export const op = (id) => OPS.find((o) => o.operationId === id) ?? null;

/** A provider stub that records calls. `respond(req, ctx, n)` may return a HandlerResult (default: 200 ok). */
export function stub(respond) {
  const calls = [];
  const h = async (req, ctx) => {
    calls.push({ req, ctx });
    const r = typeof respond === "function" ? await respond(req, ctx, calls.length) : respond;
    return r ?? { ok: true, status: 200, data: { id: `obj_${calls.length}` }, providerIds: [`obj_${calls.length}`] };
  };
  h.calls = calls;
  return h;
}
