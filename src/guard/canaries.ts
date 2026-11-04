/**
 * Canary records (section 7.10). The policy lists only salted hashes of decoy ids;
 * the salt comes from a secret (`NST_MCP_CANARY_SALT`), so the policy alone does
 * not reveal which records are decoys.
 */
import { sha256Hex } from "./canonical.js";

export const CANARY_SALT_ENV = "NST_MCP_CANARY_SALT";

export function canaryHash(id: string, salt: string): string {
  return `sha256:${sha256Hex(`${salt}:${id}`)}`;
}

export class Canaries {
  readonly #hashes: ReadonlySet<string>;
  readonly #salt: string | undefined;

  constructor(hashes: readonly string[], salt: string | undefined) {
    this.#hashes = new Set(hashes);
    this.#salt = salt && salt.length ? salt : undefined;
  }

  /** Canaries are configured. */
  get active(): boolean {
    return this.#hashes.size > 0;
  }

  /** Configured but unusable: the salt is missing, so no call can be checked. */
  get misconfigured(): boolean {
    return this.active && this.#salt === undefined;
  }

  /** The first value that is a canary, or null. */
  match(values: readonly string[]): string | null {
    if (!this.active || !this.#salt) return null;
    for (const v of values) if (this.#hashes.has(canaryHash(v, this.#salt))) return v;
    return null;
  }
}
