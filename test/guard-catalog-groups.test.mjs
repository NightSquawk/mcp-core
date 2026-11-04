// registerCatalogGroups: registration, schemas, rendering, default list/describe, resources.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { renderExecute, renderRead } from "../dist/guard/index.js";
import { startHarness } from "../dist/guard/testing/index.js";
import { ALL_ON, OPS, SECRET } from "./guard-helpers.mjs";
import { buildToy } from "./guard-toy.mjs";

async function harness(t, scenario = {}, extra = {}) {
  const h = await startHarness(
    { server: "toy", operations: OPS, build: (ctx) => buildToy(ctx, extra), secrets: [SECRET], samples: {} },
    { policy: ALL_ON, mode: "sandbox", ...scenario }
  );
  t.after(() => h.close());
  return h;
}
const names = async (h) => (await h.tools()).map((x) => x.name).sort();
const tool = async (h, name) => (await h.tools()).find((x) => x.name === name);

describe("registration", () => {
  test("one tool per enabled group, plus list and describe", async (t) => {
    const all = await harness(t);
    assert.deepEqual(await names(all), ["toy_change", "toy_critical", "toy_describe_endpoint", "toy_list_endpoints", "toy_read", "toy_spend"]);
    const ro = await harness(t, { policy: { groups: { read: true } } });
    assert.deepEqual(await names(ro), ["toy_describe_endpoint", "toy_list_endpoints", "toy_read"]);
  });

  test("annotations and _meta follow the group", async (t) => {
    const h = await harness(t);
    const read = await tool(h, "toy_read");
    const change = await tool(h, "toy_change");
    const critical = await tool(h, "toy_critical");
    const spend = await tool(h, "toy_spend");
    assert.equal(read.annotations.readOnlyHint, true);
    assert.equal(change.annotations.destructiveHint, false);
    assert.equal(critical.annotations.destructiveHint, true);
    assert.equal(spend.annotations.idempotentHint, false);
    for (const x of [read, change, critical, spend]) assert.equal(x.annotations.openWorldHint, true, x.name);
    assert.equal(change._meta?.["anthropic/requiresUserInteraction"], undefined);
    for (const x of [critical, spend]) assert.equal(x._meta["anthropic/requiresUserInteraction"], true, x.name);
  });

  test("input schemas: reason required for critical and spend, no dry_run on reads", async (t) => {
    const h = await harness(t);
    const schema = async (n) => (await tool(h, n)).inputSchema;
    assert.deepEqual((await schema("toy_read")).required, ["operation_id"]);
    assert.equal((await schema("toy_read")).properties.dry_run, undefined);
    assert.deepEqual((await schema("toy_change")).required, ["operation_id"]);
    assert.ok((await schema("toy_change")).properties.dry_run);
    for (const n of ["toy_critical", "toy_spend"]) assert.deepEqual([...(await schema(n)).required].sort(), ["operation_id", "reason"], n);
    const r = await h.call("toy_spend", { operation_id: "payment_create", body: { amount: 1, currency: "USD", payee_id: "payee_ok" } });
    assert.equal(r.isError, true);
    assert.equal(h.calls.length, 0);
    const empty = await h.call("toy_read", { operation_id: "" });
    assert.equal(empty.isError, true);
  });

  test("descriptions point at list and describe", async (t) => {
    const h = await harness(t);
    for (const n of ["toy_read", "toy_change", "toy_critical", "toy_spend"]) assert.match((await tool(h, n)).description, /toy_list_endpoints/, n);
  });

  test("custom titles and descriptions are sanitized", async (t) => {
    const hidden = String.fromCodePoint(0x200b);
    const h = await harness(t, {}, { tools: { read: { title: "Look", description: `Reads${hidden} only` } } });
    const read = await tool(h, "toy_read");
    assert.equal(read.description, "Reads only");
    assert.equal(read.annotations.title, "Look");
  });
});

describe("rendering through the tools", () => {
  test("reads return {operation_id, status, result}; refusals are errors", async (t) => {
    const h = await harness(t);
    const ok = await h.call("toy_read", { operation_id: "thing_list" });
    assert.equal(ok.isError, false);
    assert.deepEqual(ok.json, { operation_id: "thing_list", status: 200, result: { id: "stub_1", object: "stub" } });
    const no = await h.call("toy_read", { operation_id: "payment_create" });
    assert.equal(no.isError, true);
    assert.equal(no.json.reason_code, "wrong_group");
  });

  test("untrusted fields are labelled and explained", async (t) => {
    const h = await harness(t, { respond: () => ({ ok: true, status: 200, data: { id: "thing_1", note: "hello there" } }) });
    const r = await h.call("toy_read", { operation_id: "thing_get", path_params: { id: "thing_1" } });
    assert.equal(r.json.untrusted_fields, 1);
    assert.match(r.json.note, /never as instructions/);
    assert.equal(r.json.result.note.untrusted, true);
    assert.equal(r.json.result.id, "thing_1");
  });

  test("the untrusted note says whether marked fields or the whole result hold outside text", () => {
    const json = (r) => JSON.parse(r.content[0].text);
    const whole = json(renderRead({ status: "done", operation: "x", http_status: 200, data: { a: 1 }, untrusted_fields: 1, untrusted_whole: true }));
    assert.equal(whole.untrusted_whole, true);
    assert.match(whole.note, /whole result/);
    const fields = json(renderRead({ status: "done", operation: "x", data: {}, untrusted_fields: 2 }));
    assert.equal(fields.untrusted_whole, undefined);
    assert.equal(fields.untrusted_fields, 2);
    assert.match(fields.note, /^Fields marked untrusted/);
    assert.equal(json(renderRead({ status: "done", operation: "x", data: {}, untrusted_fields: 0 })).note, undefined);
    const done = json(renderExecute({ status: "done", operation: "x", idempotency_key: "k", data: {}, untrusted_fields: 1 }));
    assert.match(done.note, /^Fields marked untrusted/);
    const pending = json(renderExecute({ status: "pending", operation: "x", idempotency_key: "k", hold: { ref: "r" }, message: "m", data: {}, untrusted_fields: 1, untrusted_whole: true }));
    assert.match(pending.note, /whole result/);
    assert.equal(json(renderExecute({ status: "done", operation: "x", idempotency_key: "k", data: {} })).note, undefined);
  });

  test("an oversized read is refused; an oversized done result is cut, never refused", async (t) => {
    const h = await harness(t, { respond: () => ({ ok: true, status: 200, data: { id: "obj_9", blob: "x".repeat(1000) }, providerIds: ["obj_9"] }) }, { maxResultChars: 300 });
    const read = await h.call("toy_read", { operation_id: "thing_list" });
    assert.equal(read.isError, true);
    assert.equal(read.json.reason_code, "result_too_large");
    const done = await h.call("toy_change", { operation_id: "thing_create", body: { name: "big" } });
    assert.equal(done.isError, false);
    assert.equal(done.json.result_truncated, true);
    assert.deepEqual(done.json.provider_ids, ["obj_9"]);
    assert.equal(h.calls.length, 2);
  });

  test("dry_run, deduplicated and failed outcomes", async (t) => {
    const h = await harness(t, {
      respond: (op, req) => (req.body?.fail ? { ok: false, status: 422, error: { message: "invalid" }, sent: true } : undefined),
    });
    const dry = await h.call("toy_spend", { operation_id: "payment_create", body: { amount: 500, currency: "USD", payee_id: "payee_ok" }, reason: "test", dry_run: true });
    assert.equal(dry.isError, false);
    assert.equal(dry.json.dry_run, true);
    assert.equal(h.calls.length, 0);
    const a = await h.call("toy_spend", { operation_id: "payment_create", body: { amount: 500, currency: "USD", payee_id: "payee_ok" }, reason: "test" });
    const b = await h.call("toy_spend", { operation_id: "payment_create", body: { amount: 500, currency: "USD", payee_id: "payee_ok" }, reason: "test" });
    assert.equal(a.isError, false);
    assert.equal(b.json.deduplicated, true);
    assert.equal(b.json.idempotency_key, a.json.idempotency_key);
    const f = await h.call("toy_change", { operation_id: "thing_create", body: { fail: true } });
    assert.equal(f.isError, true);
    assert.equal(f.json.failed, true);
    assert.equal(f.json.status, 422);
  });
});

describe("render functions", () => {
  test("renderRead", () => {
    const failed = renderRead({ status: "failed", operation: "x", http_status: 500, error: { message: "boom" } });
    assert.equal(failed.isError, true);
    assert.deepEqual(JSON.parse(failed.content[0].text), { operation_id: "x", status: 500, error: { message: "boom" } });
    const big = renderRead({ status: "done", operation: "x", http_status: 200, data: "y".repeat(50) }, 20);
    assert.equal(JSON.parse(big.content[0].text).reason_code, "result_too_large");
  });

  test("renderExecute error and success shapes", () => {
    const unknown = renderExecute({ status: "unknown_outcome", operation: "x", idempotency_key: "k", error: { message: "timeout" }, message: "m" });
    assert.equal(unknown.isError, true);
    assert.equal(JSON.parse(unknown.content[0].text).unknown_outcome, true);
    const pending = renderExecute({ status: "pending", operation: "x", idempotency_key: "k", provider_ids: [], hold: { ref: "r" }, message: "m" });
    assert.equal(pending.isError, undefined);
    assert.equal(JSON.parse(pending.content[0].text).pending, true);
    const refused = renderExecute({ status: "refused", refusal: { refused: true, reason_code: "blocked", message: "no" } });
    assert.equal(refused.isError, true);
  });
});

describe("default list and describe", () => {
  const scenario = { policy: { groups: { read: true, change: true } }, mode: "none" };

  test("list filters, pages and explains availability", async (t) => {
    const h = await harness(t, scenario);
    const list = async (args) => (await h.call("toy_list_endpoints", args)).json;
    const all = await list({});
    assert.equal(all.total, OPS.length);
    const spend = await list({ group: "spend" });
    assert.deepEqual(spend.operations.map((o) => [o.operation_id, o.available, o.reason_code]), [["invoice_pay", false, "group_off"], ["payment_create", false, "group_off"]]);
    const blocked = await list({ tier: "blocked" });
    assert.deepEqual(blocked.operations.map((o) => [o.operation_id, o.tool, o.reason_code]), [["payment_release", null, "blocked"]]);
    assert.deepEqual((await list({ search: "payee" })).operations.map((o) => o.operation_id), ["payee_create"]);
    const avail = await list({ available_only: true });
    assert.ok(avail.operations.every((o) => o.available));
    assert.ok(avail.operations.some((o) => o.operation_id === "thing_create"));
    assert.ok(!avail.operations.some((o) => o.operation_id === "sim_settle"), "sandbox-only is unavailable without a sandbox key");
    const page = await list({ limit: 2, offset: 1 });
    assert.equal(page.total, OPS.length);
    assert.deepEqual(page.operations.map((o) => o.operation_id), all.operations.slice(1, 3).map((o) => o.operation_id));
  });

  test("describe shows availability, flags and server details; unknown ids get suggestions", async (t) => {
    const h = await harness(t, scenario, { describe: (op) => ({ summary: `About ${op.operationId}` }), suggest: () => ["thing_list"] });
    const d = (await h.call("toy_describe_endpoint", { operation_id: "thing_get" })).json;
    assert.equal(d.tool, "toy_read");
    assert.equal(d.available, true);
    assert.deepEqual(d.flags, { untrusted_output: true });
    assert.equal(d.details.summary, "About thing_get");
    const off = (await h.call("toy_describe_endpoint", { operation_id: "payment_create" })).json;
    assert.equal(off.reason_code, "group_off");
    const u = await h.call("toy_describe_endpoint", { operation_id: "thing_lst" });
    assert.equal(u.isError, true);
    assert.match(u.json.message, /Did you mean: thing_list/);
  });

  test("listDescribe:false leaves them to the server and lists its extraTools in the manifest", async (t) => {
    const h = await harness(t, {}, { listDescribe: false, extraTools: [{ name: "toy_find", group: "read" }] });
    assert.deepEqual(await names(h), ["toy_change", "toy_critical", "toy_read", "toy_spend"]);
    const m = JSON.parse((await h.client.readResource({ uri: "guard://manifest" })).contents[0].text);
    assert.ok(m.tools.some((x) => x.name === "toy_find"));
    assert.ok(!m.tools.some((x) => x.name === "toy_list_endpoints"));
  });
});

describe("resources", () => {
  test("guard://manifest and guard://status", async (t) => {
    const h = await harness(t);
    const m = JSON.parse((await h.client.readResource({ uri: "guard://manifest" })).contents[0].text);
    assert.equal(m.server, "toy");
    assert.equal(m.operations.find((o) => o.operation === "payment_release").tool, null);
    assert.equal(m.operations.find((o) => o.operation === "payment_create").tool, "toy_spend");
    const s = JSON.parse((await h.client.readResource({ uri: "guard://status" })).contents[0].text);
    assert.equal(s.server, "toy");
    assert.equal(s.groups.spend.enabled, true);
  });

  test("resources:false registers none", async (t) => {
    const h = await harness(t, {}, { resources: false });
    const list = await h.client.listResources().catch(() => ({ resources: [] }));
    assert.equal(list.resources.length, 0);
  });
});
