/**
 * Kill switch and circuit breakers (section 7.8).
 *
 * - Manual: a marker file next to the policy (`<root>/<server>/KILL`, or
 *   `<root>/KILL` for every server). Admin rights, like the policy.
 * - Automatic: trips written to the agent's own state folder (canary hit, audit
 *   chain break, an unheld spend in live mode, the denial breaker). Without the
 *   broker they stop a confused agent, not a deliberate one.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { readJsonFile, withFileLock, writeJsonFile } from "./lock.js";
import { GROUPS, type Group } from "./tiers.js";

export type KillScope = "all" | Group;

/** Why kill.json cannot be used: it is not JSON (unreadable), or JSON but not a list of trips (malformed). */
export type KillFileProblem = "unreadable" | "malformed";

const SCOPES: readonly string[] = ["all", ...GROUPS];

/** A trip as trip() writes it. */
function isKillTrip(v: unknown): v is KillTrip {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const t = v as Record<string, unknown>;
  return typeof t.scope === "string" && SCOPES.includes(t.scope) && typeof t.reason === "string" && typeof t.at === "string";
}

export interface KillTrip {
  scope: KillScope;
  reason: string;
  at: string;
}

export interface KillState {
  manual: { server: boolean; all: boolean; markers: { server: string; all: string }; note?: string };
  trips: KillTrip[];
}

export class KillSwitch {
  readonly markers: { server: string; all: string };
  readonly file: string;
  readonly #lock: string;
  readonly #clock: () => Date;

  constructor(opts: { markers: { server: string; all: string }; stateDir: string; clock?: () => Date }) {
    this.markers = opts.markers;
    this.file = join(opts.stateDir, "kill.json");
    this.#lock = join(opts.stateDir, "kill.lock");
    this.#clock = opts.clock ?? (() => new Date());
  }

  #read(): { trips: KillTrip[] } | { problem: KillFileProblem } {
    let f: unknown;
    try {
      f = readJsonFile<unknown>(this.file, { trips: [] });
    } catch {
      return { problem: "unreadable" };
    }
    const trips = f !== null && typeof f === "object" && !Array.isArray(f) ? (f as { trips?: unknown }).trips : undefined;
    return Array.isArray(trips) && trips.every(isKillTrip) ? { trips } : { problem: "malformed" };
  }

  /** Why kill.json cannot be used, or null; a missing file is fine. Either problem stops every group until mcp-guard reset. */
  fileProblem(): KillFileProblem | null {
    const r = this.#read();
    return "problem" in r ? r.problem : null;
  }

  #trips(): KillTrip[] {
    const r = this.#read();
    if ("trips" in r) return r.trips;
    // A trip file that is not JSON, or JSON but not a list of trips ({}, {"trips": "x"}), fails
    // closed: it counts as a trip of everything, never as no trips.
    const what = r.problem === "unreadable" ? `Unreadable ${this.file}` : `${this.file} is not a list of trips`;
    return [{ scope: "all", reason: `${what}; delete it with mcp-guard reset after checking why.`, at: new Date(0).toISOString() }];
  }

  state(): KillState {
    const note = (p: string) => {
      try {
        return readFileSync(p, "utf8").trim().slice(0, 300);
      } catch {
        return undefined;
      }
    };
    const server = existsSync(this.markers.server);
    const all = existsSync(this.markers.all);
    const text = (server ? note(this.markers.server) : undefined) ?? (all ? note(this.markers.all) : undefined);
    return { manual: { server, all, markers: this.markers, ...(text ? { note: text } : {}) }, trips: this.#trips() };
  }

  /** Why calls in `group` are stopped, or null. Reads are never stopped. */
  stopped(group: Group): string | null {
    if (group === "read") return null;
    const s = this.state();
    if (s.manual.all) return `The kill switch for every server is set (${this.markers.all}).${s.manual.note ? ` Note: ${s.manual.note}` : ""}`;
    if (s.manual.server) return `The kill switch for this server is set (${this.markers.server}).${s.manual.note ? ` Note: ${s.manual.note}` : ""}`;
    const trip = s.trips.find((t) => t.scope === "all" || t.scope === group);
    if (trip) return `Automatic trip (${trip.scope}) at ${trip.at}: ${trip.reason}`;
    return null;
  }

  trip(scope: KillScope, reason: string): KillTrip {
    return withFileLock(this.#lock, () => {
      const trips = this.#trips().filter((t) => !(t.scope === scope && t.reason === reason));
      const t = { scope, reason, at: this.#clock().toISOString() };
      trips.push(t);
      writeJsonFile(this.file, { trips });
      return t;
    });
  }

  /** Clear automatic trips (mcp-guard reset). Manual markers need `unkill` with admin rights. */
  reset(): number {
    return withFileLock(this.#lock, () => {
      const n = this.#trips().length;
      writeJsonFile(this.file, { trips: [] });
      return n;
    });
  }
}
