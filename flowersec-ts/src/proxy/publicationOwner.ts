import type { ProxyPublicationOwner } from "./types.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";

const owners = new WeakSet<ProxyPublicationOwner>();
let ownerEpochSequence = 0;

/**
 * This value is only an association label. Freshness is established by the
 * worker-issued claim, so a new document may safely restart at one.
 */
export function nextServiceWorkerPublicationOwnerEpoch(): number {
  if (ownerEpochSequence >= Number.MAX_SAFE_INTEGER) throw new Error("publication_owner_unavailable");
  return ++ownerEpochSequence;
}
export function isProxyPublicationOwner(owner: ProxyPublicationOwner): boolean { return owners.has(owner); }
/** The private control port retains cleanup observations from the exact original
 * worker. A replacement controller cannot inherit this publication identity. */
export function serviceWorkerPublicationOwner(container: ServiceWorkerContainer,
  registrationToken: string, ownerID: string, ownerEpoch: number, ownerClaim: string): ProxyPublicationOwner {
  const selectedWorker = container.controller;
  if (selectedWorker === null || registrationToken === "") throw new Error("publication_owner_unavailable");
  const worker: ServiceWorker = selectedWorker;
  if (!Number.isSafeInteger(ownerEpoch) || ownerEpoch < 1 || ownerClaim === "" || ownerClaim !== ownerClaim.trim() || ownerClaim.length > 256) {
    throw new Error("publication_owner_unavailable");
  }
  let sequence = 0, closed = false, context: string | undefined, pending = 0n;
  let watched: MessagePort | undefined;
  let remote: V4CleanupStatus = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
  const next = (): number => {
    if (sequence >= Number.MAX_SAFE_INTEGER) throw new Error("publication_owner_unavailable");
    return ++sequence;
  };
  const observe = (value: unknown): boolean => {
    if (!Number.isSafeInteger(value) || Number(value) < 0) return false;
    const count = BigInt(Number(value));
    remote = Object.freeze({ status: count === 0n ? "complete" : "pending", core_cleanup: count === 0n ? "complete" : "pending", pending_callbacks: count });
    if (closed && count === 0n) { watched?.close(); watched = undefined; }
    return true;
  };
  function send(action: "fence" | "install", value: string, signal: AbortSignal): Promise<void> {
    if (closed || container.controller !== worker) return Promise.reject(new Error("publication_owner_unavailable"));
    signal.throwIfAborted(); const command = next(); pending++;
    return new Promise<void>((resolve, reject) => {
      const channel = new MessageChannel(); let settled = false;
      const finish = (error?: Error): void => {
        if (settled) return; settled = true; pending--; signal.removeEventListener("abort", canceled);
        if (error === undefined) { watched?.close(); watched = channel.port1; resolve(); }
        else { channel.port1.close(); remote = Object.freeze({ status: "pending", core_cleanup: "pending", pending_callbacks: remote.pending_callbacks }); reject(error); }
      };
      const canceled = (): void => {
        // Retain the later FENCE's observer and physical cleanup facts.
        finish(new Error("publication_owner_canceled"));
        if (!closed && action === "install") void send("fence", value, AbortSignal.timeout(5000)).catch(() => undefined);
      };
      channel.port1.onmessage = event => {
        const ack = event.data as Record<string, unknown>;
        if (ack?.sequence !== command || ack.context !== value) return;
        if (settled) {
          if (watched === channel.port1 && ack.type === "flowersec-proxy:publication-cleanup") observe(ack.pending_callbacks);
          return;
        }
        if (ack.type !== "flowersec-proxy:publication-ack" || ack.action !== action || ack.ok !== true || !observe(ack.pending_callbacks)) {
          finish(new Error("publication_owner_invalid_ack")); return;
        }
        context = value; finish();
      };
      channel.port1.onmessageerror = () => finish(new Error("publication_owner_invalid_ack"));
      signal.addEventListener("abort", canceled, { once: true }); channel.port1.start();
      try { worker.postMessage({ type: "flowersec-proxy:publication-control", action, context: value,
        token: registrationToken, owner_id: ownerID, owner_epoch: ownerEpoch, owner_claim: ownerClaim, sequence: command }, [channel.port2]); }
      catch { finish(new Error("publication_owner_unavailable")); }
      if (signal.aborted) canceled();
    });
  }
  const owner: ProxyPublicationOwner = Object.freeze<ProxyPublicationOwner>({ ownerID,
    fence: (value, signal) => send("fence", value, signal), install: (value, signal) => send("install", value, signal),
    cleanupStatus: () => Object.freeze({ status: pending === 0n ? remote.status : "pending", core_cleanup: remote.core_cleanup,
      pending_callbacks: remote.pending_callbacks + pending }),
    close() {
      if (closed) return;
      if (context !== undefined && container.controller === worker) {
        const sealing = send("fence", context, AbortSignal.timeout(5000));
        closed = true;
        void sealing.then(() => { if (remote.pending_callbacks === 0n) { watched?.close(); watched = undefined; } }, () => undefined);
      } else { closed = true; if (remote.pending_callbacks === 0n) { watched?.close(); watched = undefined; } }
    },
  }); owners.add(owner); return owner;
}
