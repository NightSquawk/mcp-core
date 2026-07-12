import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

/**
 * Generic on-disk catalog loader for the catalog-backed servers. Each server
 * generates a catalog (one aggregate `index.json` plus one JSON file per entry
 * under subdirectories) and reads it back at runtime for discovery + request
 * validation.
 *
 * IMPORTANT — inverted path resolution: the *server* resolves its own catalog
 * directory (from the server module's own location) and passes it in. This
 * loader NEVER derives the path from its own module location, because once it
 * lives in node_modules/@nightsquawk/mcp-core it would otherwise look for the
 * catalog next to the library instead of next to the server's data.
 *
 * Entry ids are validated against a flat-identifier pattern to prevent path
 * traversal; results are cached per (catalogDir, subdir, id).
 */

const SAFE_ID = /^[a-z0-9_]+$/;

export interface CatalogStore<I> {
  /** The aggregate index (parsed + cached). */
  index(): I;
  /** A single entry file (`<subdir>/<id>.json`), or null if unknown/invalid. */
  entry<E>(id: string, subdir?: string): E | null;
  /** Whether the entry file exists on disk (no parse). */
  has(id: string, subdir?: string): boolean;
}

export interface CatalogStoreOptions {
  /** Index filename relative to catalogDir (default "index.json"). */
  indexFile?: string;
  /** Default subdirectory for entries (default "endpoints"). */
  entriesSubdir?: string;
}

/**
 * Create a cached catalog store rooted at `catalogDir`.
 *
 * @param catalogDir Absolute path to the catalog directory (server-resolved).
 */
export function createCatalogStore<I>(
  catalogDir: string,
  options: CatalogStoreOptions = {}
): CatalogStore<I> {
  const indexFile = options.indexFile ?? "index.json";
  const defaultSubdir = options.entriesSubdir ?? "endpoints";

  let indexCache: I | null = null;
  const entryCache = new Map<string, unknown>();

  function entryPath(id: string, subdir: string): string {
    return join(catalogDir, subdir, `${id}.json`);
  }

  return {
    index(): I {
      if (indexCache === null) {
        indexCache = JSON.parse(readFileSync(join(catalogDir, indexFile), "utf8")) as I;
      }
      return indexCache;
    },

    entry<E>(id: string, subdir: string = defaultSubdir): E | null {
      if (!SAFE_ID.test(id)) return null;
      const key = `${subdir}/${id}`;
      if (entryCache.has(key)) return entryCache.get(key) as E | null;
      let value: E | null = null;
      try {
        value = JSON.parse(readFileSync(entryPath(id, subdir), "utf8")) as E;
      } catch {
        value = null;
      }
      entryCache.set(key, value);
      return value;
    },

    has(id: string, subdir: string = defaultSubdir): boolean {
      if (!SAFE_ID.test(id)) return false;
      return existsSync(entryPath(id, subdir));
    },
  };
}
