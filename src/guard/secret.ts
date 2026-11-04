/**
 * secret(name) and the argv check (section 7.4).
 *
 * A secret is read only from the environment, never logged, and a missing one is
 * reported by its variable *name* only.
 */
import { inspect } from "node:util";

/** A value that never prints itself: logging or serializing it shows "[redacted]". */
export class Secret {
  readonly #value: string;
  readonly name: string;
  constructor(name: string, value: string) {
    this.name = name;
    this.#value = value;
  }
  reveal(): string {
    return this.#value;
  }
  toString(): string {
    return "[redacted]";
  }
  toJSON(): string {
    return "[redacted]";
  }
  [inspect.custom](): string {
    return `Secret(${this.name}: [redacted])`;
  }
}

export class MissingSecretError extends Error {
  override name = "MissingSecretError";
  constructor(readonly variables: readonly string[]) {
    super(`Missing required environment variable${variables.length > 1 ? "s" : ""}: ${variables.join(", ")}.`);
  }
}

export class SecretInArgvError extends Error {
  override name = "SecretInArgvError";
  constructor(readonly variable: string) {
    super(`The value of ${variable} also appears in the process arguments. Pass it only through the environment.`);
  }
}

/** Read one secret from `env`. Throws MissingSecretError naming the variable, never the value. */
export function secret(name: string, env: NodeJS.ProcessEnv = process.env): Secret {
  const value = (env[name] ?? "").trim();
  if (!value) throw new MissingSecretError([name]);
  return new Secret(name, value);
}

/** Read several secrets; reports every missing name at once (voipms `missing[]` pattern). */
export function secrets(names: readonly string[], env: NodeJS.ProcessEnv = process.env): Record<string, Secret> {
  const missing = names.filter((n) => !(env[n] ?? "").trim());
  if (missing.length) throw new MissingSecretError(missing);
  return Object.fromEntries(names.map((n) => [n, new Secret(n, (env[n] ?? "").trim())]));
}

/** An optional secret: undefined when unset. */
export function optionalSecret(name: string, env: NodeJS.ProcessEnv = process.env): Secret | undefined {
  const value = (env[name] ?? "").trim();
  return value ? new Secret(name, value) : undefined;
}

/**
 * Refuse to run if any secret value appears in argv (section 7.4). Short values
 * (under 8 characters) are skipped: they would match by accident and are not keys.
 */
export function assertNoSecretsInArgv(values: ReadonlyArray<Secret | undefined>, argv: readonly string[] = process.argv): void {
  for (const s of values) {
    if (!s) continue;
    const v = s.reveal();
    if (v.length >= 8 && argv.some((arg) => arg.includes(v))) throw new SecretInArgvError(s.name);
  }
}
