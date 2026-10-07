import { createRequire } from "node:module";
import { isAbsolute } from "node:path";

/** Resolve only the installed SDK binary, before creating the storage worker.
 * Database contents and caller configuration cannot select executable code. */
export function sqliteExtensionPath(): string {
  try {
    const binding = createRequire(import.meta.url)("@floegence/flowersec-node-native") as { sqliteExtensionPath?: () => unknown };
    const path = binding.sqliteExtensionPath?.();
    if (typeof path !== "string" || !isAbsolute(path)) throw new Error("storage_unavailable");
    return path;
  } catch { throw new Error("storage_unavailable"); }
}
