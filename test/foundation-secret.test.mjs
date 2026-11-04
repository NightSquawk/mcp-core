import { test } from "node:test";
import assert from "node:assert/strict";
import { inspect } from "node:util";
import { dist } from "./foundation-helpers.mjs";

const S = await import(dist("guard/secret.js"));

const VALUE = "Qx9-Qx9-Qx9-Qx9-Qx9"; // synthetic, never a real credential

test("secret: reads from env and reveals only on request", () => {
  const s = S.secret("COLUMN_API_KEY", { COLUMN_API_KEY: `  ${VALUE}  ` });
  assert.equal(s.name, "COLUMN_API_KEY");
  assert.equal(s.reveal(), VALUE, "surrounding whitespace is trimmed");
});

test("secret: never prints its value", () => {
  const s = S.secret("K", { K: VALUE });
  const renderings = [String(s), `${s}`, JSON.stringify({ s }), inspect(s), inspect({ nested: { s } }), s + ""];
  for (const r of renderings) assert.ok(!r.includes(VALUE), `leaked in: ${r}`);
  assert.equal(JSON.stringify({ s }), '{"s":"[redacted]"}');
  assert.match(inspect(s), /Secret\(K: \[redacted\]\)/);
});

test("secret: a missing or blank value names the variable, never a value", () => {
  for (const env of [{}, { K: "" }, { K: "   " }]) {
    assert.throws(
      () => S.secret("K", env),
      (e) => e instanceof S.MissingSecretError && e.variables.length === 1 && e.variables[0] === "K" && /Missing required environment variable: K\./.test(e.message)
    );
  }
});

test("secrets: reports every missing name at once", () => {
  assert.throws(
    () => S.secrets(["A", "B", "C"], { B: VALUE }),
    (e) => e instanceof S.MissingSecretError && e.variables.join(",") === "A,C" && e.message.includes("A, C") && !e.message.includes(VALUE)
  );
  const got = S.secrets(["A", "B"], { A: VALUE, B: `${VALUE}2` });
  assert.equal(got.A.reveal(), VALUE);
  assert.equal(got.B.reveal(), `${VALUE}2`);
});

test("optionalSecret: undefined when unset", () => {
  assert.equal(S.optionalSecret("NOPE", {}), undefined);
  assert.equal(S.optionalSecret("NOPE", { NOPE: " " }), undefined);
  assert.equal(S.optionalSecret("YES", { YES: VALUE }).reveal(), VALUE);
});

test("assertNoSecretsInArgv: refuses a secret passed on the command line", () => {
  const s = S.secret("COLUMN_API_KEY", { COLUMN_API_KEY: VALUE });
  for (const argv of [["node", "server.js", VALUE], ["node", "server.js", `--key=${VALUE}`], ["node", `x${VALUE}y`]]) {
    assert.throws(
      () => S.assertNoSecretsInArgv([s], argv),
      (e) => e instanceof S.SecretInArgvError && e.variable === "COLUMN_API_KEY" && !e.message.includes(VALUE)
    );
  }
  assert.doesNotThrow(() => S.assertNoSecretsInArgv([s, undefined], ["node", "server.js", "--stdio"]));
});

test("assertNoSecretsInArgv: short values are skipped so ordinary words cannot trip it", () => {
  const short = S.secret("PIN", { PIN: "node" });
  assert.doesNotThrow(() => S.assertNoSecretsInArgv([short], ["node", "server.js"]));
});
