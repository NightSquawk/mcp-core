// The conformance suite (section 7.6) run against a toy catalog server built on registerCatalogGroups.
import { runConformance } from "../dist/guard/testing/index.js";
import { OPS, SECRET, SPEND_POLICY, TIERS_FILE } from "./guard-helpers.mjs";
import { buildToy } from "./guard-toy.mjs";

runConformance({
  server: "toy",
  operations: OPS,
  tiers: TIERS_FILE,
  build: (ctx) => buildToy(ctx),
  policyPatch: SPEND_POLICY,
  samples: {
    change: { operation_id: "thing_create", body: { name: "x" } },
    critical: { operation_id: "thing_delete", path_params: { id: "thing_1" } },
    spend: { operation_id: "payment_create", body: { amount: 500, currency: "USD", payee_id: "payee_ok", description: "conformance" } },
  },
  secrets: [SECRET],
  untrusted: { read: { operation_id: "thing_get", path_params: { id: "thing_1" } }, field: "note" },
  egress: { group: "change", sample: { operation_id: "thing_notify", path_params: { id: "thing_1" }, body: { message: "hi" } } },
  canary: { group: "critical", sample: { operation_id: "thing_delete", path_params: { id: "thing_canary" } }, value: "thing_canary" },
});
