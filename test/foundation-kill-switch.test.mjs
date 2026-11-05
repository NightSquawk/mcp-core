import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { dist, manualClock, runWorkers, tempDir } from "./foundation-helpers.mjs";

const { KillSwitch } = await import(dist("guard/kill-switch.js"));
const { killMarkers } = await import(dist("guard/paths.js"));

function setup(t, clock = manualClock("2026-11-04T12:00:00.000Z")) {
  const root = tempDir(t);
  mkdirSync(join(root, "policy", "column"), { recursive: true });
  const markers = killMarkers("column", { env: { NST_MCP_POLICY_DIR: join(root, "policy") } });
  const ks = new KillSwitch({ markers, stateDir: join(root, "state"), clock });
  return { ks, markers, clock, root };
}
const CHANGING = ["change", "critical", "spend"];

test("kill switch: nothing set, nothing stopped", (t) => {
  const { ks, markers } = setup(t);
  for (const g of ["read", ...CHANGING]) assert.equal(ks.stopped(g), null, g);
  assert.deepEqual(ks.state(), { manual: { server: false, all: false, markers }, trips: [] });
});

test("kill switch: the server marker stops every non-read call, with its note", (t) => {
  const { ks, markers } = setup(t);
  writeFileSync(markers.server, `  Paused for the bank migration. ${"x".repeat(400)}\n`);
  for (const g of CHANGING) {
    const why = ks.stopped(g);
    assert.match(why, /^The kill switch for this server is set/);
    assert.ok(why.includes(markers.server));
    assert.match(why, /Note: Paused for the bank migration\./);
  }
  assert.equal(ks.stopped("read"), null, "reads are never stopped");
  assert.equal(ks.state().manual.note.length, 300, "the note is trimmed and capped");
  writeFileSync(markers.server, "");
  assert.equal(ks.state().manual.note, undefined, "an empty marker has no note");
  assert.match(ks.stopped("spend"), /^The kill switch for this server is set \(.*\)\.$/);
});

test("kill switch: the all-servers marker wins", (t) => {
  const { ks, markers } = setup(t);
  writeFileSync(markers.all, "fleet-wide stop");
  assert.match(ks.stopped("change"), /^The kill switch for every server is set .*Note: fleet-wide stop$/);
  writeFileSync(markers.server, "server note");
  const s = ks.state();
  assert.equal(s.manual.server && s.manual.all, true);
  assert.match(ks.stopped("critical"), /every server/);
});

test("kill switch: automatic trips stop their scope", (t) => {
  const { ks } = setup(t);
  const trip = ks.trip("spend", "canary hit: cpty_canary");
  assert.deepEqual(trip, { scope: "spend", reason: "canary hit: cpty_canary", at: "2026-11-04T12:00:00.000Z" });
  assert.equal(ks.stopped("spend"), "Automatic trip (spend) at 2026-11-04T12:00:00.000Z: canary hit: cpty_canary");
  assert.equal(ks.stopped("change"), null);
  ks.trip("all", "audit chain broken");
  for (const g of CHANGING) assert.notEqual(ks.stopped(g), null, g);
  assert.equal(ks.stopped("read"), null);
});

test("kill switch: the same trip twice is recorded once, with the later time", (t) => {
  const { ks, clock } = setup(t);
  ks.trip("critical", "denial breaker");
  clock.advance(60_000);
  ks.trip("critical", "denial breaker");
  ks.trip("critical", "another reason");
  const trips = ks.state().trips;
  assert.equal(trips.length, 2);
  assert.deepEqual(
    trips.find((x) => x.reason === "denial breaker"),
    { scope: "critical", reason: "denial breaker", at: "2026-11-04T12:01:00.000Z" }
  );
});

test("kill switch: reset clears automatic trips only", (t) => {
  const { ks, markers } = setup(t);
  ks.trip("spend", "a");
  ks.trip("all", "b");
  assert.equal(ks.reset(), 2);
  assert.equal(ks.stopped("spend"), null);
  assert.equal(ks.reset(), 0);
  writeFileSync(markers.server, "");
  ks.reset();
  assert.notEqual(ks.stopped("spend"), null, "a manual marker needs unkill (admin rights), not reset");
});

test("kill switch: an unreadable trip file stops everything until reset", (t) => {
  const { ks } = setup(t);
  ks.trip("spend", "x");
  writeFileSync(ks.file, "{corrupt");
  for (const g of CHANGING) assert.match(ks.stopped(g), /Automatic trip \(all\).*Unreadable/, g);
  ks.trip("change", "new trip on a corrupt file");
  assert.match(ks.stopped("spend"), /Unreadable/, "tripping again keeps the fail-closed trip");
  assert.equal(JSON.parse(readFileSync(ks.file, "utf8")).trips.length, 2);
  ks.reset();
  assert.equal(ks.stopped("spend"), null);
});

test("kill switch: JSON that is not a list of trips stops everything until reset", (t) => {
  const { ks, root } = setup(t);
  assert.equal(ks.fileProblem(), null, "no file is no trips");
  mkdirSync(join(root, "state"), { recursive: true });
  const shapes = [
    "{}",
    '{"trips":"corrupt"}',
    "[]",
    "null",
    "7",
    '{"trips":[null]}',
    '{"trips":[{"scope":"spend"}]}',
    '{"trips":[{"scope":"everything","reason":"x","at":"y"}]}',
  ];
  for (const text of shapes) {
    writeFileSync(ks.file, text);
    assert.equal(ks.fileProblem(), "malformed", text);
    for (const g of CHANGING) assert.match(ks.stopped(g), /Automatic trip \(all\).*is not a list of trips/, `${text} ${g}`);
    assert.equal(ks.stopped("read"), null, "reads are never stopped");
  }
  ks.trip("change", "new trip on a malformed file");
  assert.equal(ks.fileProblem(), null);
  assert.match(ks.stopped("spend"), /is not a list of trips/, "tripping again keeps the fail-closed trip");
  writeFileSync(ks.file, "{corrupt");
  assert.equal(ks.fileProblem(), "unreadable");
  ks.reset();
  assert.equal(ks.fileProblem(), null);
  assert.equal(ks.stopped("spend"), null);
});

test("kill switch: trips from 5 processes at once are all kept", async (t) => {
  const { root, markers } = setup(t);
  const code = `
    import { KillSwitch } from ${JSON.stringify(dist("guard/kill-switch.js"))};
    const ks = new KillSwitch({ markers: JSON.parse(process.env.MARKERS), stateDir: process.env.STATE_DIR });
    for (let i = 0; i < 4; i++) ks.trip("spend", "worker " + process.env.WORKER + " trip " + i);
  `;
  await runWorkers(5, code, { MARKERS: JSON.stringify(markers), STATE_DIR: join(root, "state") });
  const ks = new KillSwitch({ markers, stateDir: join(root, "state") });
  assert.equal(ks.state().trips.length, 20);
});
