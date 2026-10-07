import { expect, test } from "@playwright/test";
import { startBrowserModuleSite } from "./browser-module-site.js";

test("Chromium runs strict IndexedDB format refusals before selecting a record reader", async ({ page }) => {
  const site = await startBrowserModuleSite();
  try {
    await page.goto(site.origin);
    const results = await page.evaluate(async () => {
      const sdk = await import("/dist/browser/index.js");
      const bytes = (value: number, size = 32) => new Uint8Array(size).fill(value);
      const limit = new sdk.ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 2000n, 2000n, 2000n, 2000n, 2000n, 2000n]);
      const root = new sdk.ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 16, reservations: 256, references: 512,
        rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
      const environment = sdk.createTransportEnvironment({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32),
        runtimeBytes: 1024n, namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, dependencies: 8, acquireMS: 10000n, cleanupMS: 100,
        clock: { profile: { rate: new sdk.ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
          tick: () => ({ milliseconds: BigInt(Math.floor(performance.now())), incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: 1000n, upperMS: 1050n }) },
        random: (destination: Uint8Array) => { crypto.getRandomValues(destination); } });
      const result: unknown[] = [];
      try {
        for (const variant of ["future", "conflict", "identity", "schema"] as const) {
          const name = `flowersec-format-${variant}`;
          const backing = sdk.createIndexedDBPoolBacking(environment, name, { maxRecords: 4, maxRecordBytes: 16384, transactionMS: 10000n,
            runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, storageBytes: 1048576n });
          const options = { create: true, identity: { authority: "spend", storeID: bytes(9), generation: 1n },
            continuity: { check: () => undefined }, bindings: [{ tenant: "tenant", issuer: bytes(5, 16) }] };
          const store = await sdk.openIndexedDBPoolStore(backing, options); store.close();
          try {
            await new Promise<void>((resolve, reject) => {
              const open = indexedDB.open(name, variant === "future" ? 2 : 1);
              open.onupgradeneeded = () => {
                // Future rows have a different layout. Only their fixed
                // manifest header may be inspected by the current SDK.
                const db = open.result, manifest = open.transaction!.objectStore("manifest"), get = manifest.get(1);
                get.onsuccess = () => manifest.put({ ...get.result, revision: 2 });
                db.deleteObjectStore("spend"); db.deleteObjectStore("material_pool"); db.createObjectStore("future_records");
              };
              open.onerror = () => reject(open.error);
              open.onsuccess = () => {
                const db = open.result;
                if (variant === "future") { db.close(); resolve(); return; }
                const tx = db.transaction("manifest", "readwrite"), manifest = tx.objectStore("manifest"), get = manifest.get(1);
                get.onsuccess = () => manifest.put({ ...get.result, ...(variant === "conflict" ? { revision: 2 } : variant === "identity" ? { authority: "different" } : { maxRecords: 5 }) });
                tx.oncomplete = () => { db.close(); resolve(); }; tx.onabort = () => { db.close(); reject(tx.error); };
              };
            });
            const failure = await sdk.openIndexedDBPoolStore(backing, { ...options, create: false }).catch((error: unknown) => error);
            if (!(failure instanceof sdk.IndexedDBPoolError)) throw new Error("expected fixed format refusal");
            const epoch = await new Promise<string>((resolve, reject) => {
              const open = indexedDB.open(name); open.onerror = () => reject(open.error);
              open.onsuccess = () => {
                const db = open.result, tx = db.transaction("manifest"), read = tx.objectStore("manifest").get(1);
                let value = ""; read.onsuccess = () => { value = String(read.result.epoch); };
                tx.oncomplete = () => { db.close(); resolve(value); }; tx.onabort = () => { db.close(); reject(tx.error); };
              };
            });
            result.push({ variant, code: failure.code, message: failure.message, format: failure.format, epoch, frozen: Object.isFrozen(failure.format) });
          } finally {
            await new Promise<void>((resolve, reject) => { const remove = indexedDB.deleteDatabase(name); remove.onsuccess = () => resolve(); remove.onerror = () => reject(remove.error); });
            await backing.releaseRemoved();
          }
        }
      } finally { await environment.close(); root.close(); }
      return result;
    });
    expect(results).toHaveLength(4);
    for (const [index, reason, known, value] of [[0, "newer_revision", true, 2], [1, "revision_conflict", false, 0], [2, "identity_mismatch", false, 0], [3, "schema_or_state_invalid", true, 1]] as const) {
      expect(results[index]).toMatchObject({ code: "storage_format", message: "storage_format_incompatible", epoch: "1", frozen: true, format: {
        code: "storage_format_incompatible", transactionGroup: "flowersec-v4-indexeddb-pool", wireProfile: "flowersec-v4-transport-security",
        requiredRevision: 1, observedRevision: { known, value }, reason, exactConversionAvailable: false,
      } });
    }
  } finally { await site.close(); }
});
