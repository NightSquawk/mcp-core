// The toy catalog server used by the conformance and catalog-groups tests.
import { createMcpServer } from "../dist/index.js";
import { createGuard, refuse, registerCatalogGroups } from "../dist/guard/index.js";
import { OPS, SECRET, toyExtract } from "./guard-helpers.mjs";

const byId = new Map(OPS.map((o) => [o.operationId, o]));

export function buildToy(ctx, extra = {}) {
  const server = createMcpServer({ name: "toy", version: "1.0.0" });
  const guard = createGuard({
    server: "toy",
    version: "1.0.0",
    secrets: () => [SECRET],
    redactRules: [[/toysecret_[A-Za-z0-9]{8,}/g, "toysecret_[redacted]"]],
    ...ctx.guardOptions,
  });
  const result = registerCatalogGroups(server, {
    guard,
    operations: OPS,
    resolve: (id) => byId.get(id) ?? null,
    handler: ctx.handler,
    listDescribe: "default",
    untrustedFields: (op) => (op.operationId === "thing_get" ? ["note"] : undefined),
    extract: toyExtract(refuse),
    ...extra,
  });
  return { server, guard, result };
}
