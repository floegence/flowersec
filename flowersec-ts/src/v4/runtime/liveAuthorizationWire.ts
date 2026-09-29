import type { V4LiveAuthorizationRequest } from "./liveAuthorization.js";
import { FixedCBORWriter } from "./cborWriter.js";

const profiles = ["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"];
const identity = /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u;

/** Reference control application's bounded envelope. The authority resolves
 * its original Artifact and authenticates the caller independently. Encoding
 * these lookup fields confers no spend or activation authority. */
export function encodeLiveAuthorizationRequest(request: V4LiveAuthorizationRequest, output: Uint8Array): Uint8Array {
  if (!identity.test(request.tenant) || !identity.test(request.audience) || !identity.test(request.authority) ||
      !profiles.includes(request.cryptoProfile) || !Number.isSafeInteger(request.candidateIndex) || request.candidateIndex < 0 || request.candidateIndex > 15 ||
      typeof request.activationNotAfterMS !== "bigint" || request.activationNotAfterMS <= 0n || request.activationNotAfterMS > 0xffffffffffffffffn || request.attemptNo !== 1) throw new Error("control_request_invalid");
  for (const [bytes, size] of [[request.issuer, 16], [request.lease, 16], [request.attempt, 16], [request.artifact, 32],
    [request.clientIdentity, 32], [request.serverIdentity, 32], [request.candidateID, 16], [request.routeDigest, 32]] as const) {
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== size) throw new Error("control_request_invalid");
  }
  const writer = new FixedCBORWriter(output.subarray(0, Math.min(output.length, 1024))).array(13), encoder = new TextEncoder();
  for (const value of ["live-authorization-1", request.tenant, request.audience, request.cryptoProfile]) writer.data(encoder.encode(value), true);
  for (const bytes of [request.issuer, request.lease, request.attempt, request.artifact, request.clientIdentity, request.serverIdentity]) writer.data(bytes);
  writer.array(3).uint(request.candidateIndex).data(request.candidateID).data(request.routeDigest).uint(request.activationNotAfterMS).uint(1);
  return writer.result();
}
