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
import type { Group } from "./tiers.js";

export type KillScope = "all" | Group;

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

  #trips(): KillTrip[] {
    try {
      const f = readJsonFile<{ trips?: KillTrip[] }>(this.file, { trips: [] });
      return Array.isArray(f.trips) ? f.trips : [];
    } catch {
      // A corrupt trip file fails closed: treat it as a trip of everything.
      return [{ scope: "all", reason: `Unreadable ${this.file}; delete it with mcp-guard reset after checking why.`, at: new Date(0).toISOString() }];
    }
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
