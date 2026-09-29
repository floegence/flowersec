import { sha256 } from "@noble/hashes/sha2.js";
import { ResourceVector, resourceDimensions, type ResourceRoot, type ResourceOwner, type ResourceAccount, type ResourceReference, type ProtectedResourceAccounts } from "./resources.js";

/** Local aggregate queue cap; independent of the peer's receive-credit mirror. */
export function captureSendQueueBytes(value: number | undefined): number {
  const bytes = value ?? 12 * 1024 * 1024;
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > 0x7fffffff) throw new Error("configuration_capacity");
  return bytes;
}
/** Reject an unusable queue before consuming connection authorization. The
 * ordinary maximum write and one actual native output must fit together. */
export function checkSendQueueCapacity(bytes: number, maxWriteBytes: number, runtimeBytes: bigint, nativeOutputBytes = 0): void {
  captureSendQueueBytes(bytes);
  if (!Number.isSafeInteger(maxWriteBytes) || maxWriteBytes < 1 || maxWriteBytes > 1048576 || runtimeBytes <= 0n ||
      !Number.isSafeInteger(nativeOutputBytes) || nativeOutputBytes < 0 ||
      BigInt(bytes) < BigInt(maxWriteBytes) + runtimeBytes + BigInt(nativeOutputBytes) + (nativeOutputBytes === 0 ? 0n : 128n)) {
    throw new Error("configuration_capacity");
  }
}
export function captureStreamSendQueueBytes(value: number | undefined, role: "client" | "server"): number {
  return captureSendQueueBytes(value ?? (role === "client" ? 4 : 8) * 1024 * 1024);
}
export function createSendAccount(root: ResourceRoot, owner: ResourceOwner, bytes: number): ResourceAccount {
  captureSendQueueBytes(bytes);
  // Original Environment/backing identities distinguish simultaneous and
  // replacement Sessions sharing this root; the account is not a new pool.
  const identity = new TextEncoder().encode(JSON.stringify([owner.tenant, owner.environment, owner.backing, "send", "session"]));
  const digest = sha256(identity), id = Array.from(digest.subarray(0, 16), n => n.toString(16).padStart(2, "0")).join("");
  identity.fill(0); digest.fill(0);
  const limits = resourceDimensions.map(() => (1n << 64n) - 1n);
  limits[0] = BigInt(bytes);
  return root.account("pool", id, new ResourceVector(limits));
}

export function sendAccountPoolCapacity(maxDirections: number, ingress: number): number {
  if (!Number.isSafeInteger(maxDirections) || maxDirections < 0 || !Number.isSafeInteger(ingress) || ingress < 0 || maxDirections + ingress + 1 > 4096) {
    throw new Error("configuration_capacity");
  }
  return maxDirections + ingress + 1;
}
export function createStreamSendAccounts(root: ResourceRoot, count: number, bytes: number, runtimeBytes: bigint,
  reference: ResourceReference): ProtectedResourceAccounts {
  captureSendQueueBytes(bytes);
  const limits = resourceDimensions.map(() => (1n << 64n) - 1n); limits[0] = BigInt(bytes);
  return root.reserveAccountPool(count, "direction", new ResourceVector(limits), runtimeBytes, reference);
}
