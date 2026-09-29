import type { V4TransportEnvironment } from "./public.js";
import { importOperationReference, encodeOperationReference, type V4OperationReference } from "./operationReference.js";
import { originalEnvironment, type EnvironmentDependency, type V4EnvironmentRuntime } from "./runtime/environment.js";
import { CBORDecoder, cborDecoderCharge, byteLength, byteSlice } from "./runtime/cbor.js";
import { readExecutionTarget } from "./runtime/executionManagementCodec.js";
import { ResourceVector, type ProtectedResourceReservation } from "./runtime/resources.js";

const capability = Symbol("environment reference codec"), copy = Uint8Array.prototype.set;
const settings = (runtimeBytes: bigint) => ({ bytes: 2048, nodes: 64, textBytes: 640, arrayItems: 16, runtimeBytes });
/** One reusable, Environment-admitted canonical persistence workspace. The
 * returned immutable reference is a query locator, never a stored credential. */
export class V4OperationReferenceCodec {
  #dependency: EnvironmentDependency | undefined;
  #decoder: CBORDecoder | undefined;
  #position: ProtectedResourceReservation | undefined;
  #wire = new Uint8Array(2048);
  #working = false;
  #closed = false;
  constructor(token: symbol, dependency: EnvironmentDependency, position: ProtectedResourceReservation, runtimeBytes: bigint) {
    if (token !== capability) throw new Error("operation_reference_owner");
    this.#dependency = dependency; this.#position = position;
    try {
      const reference = position.checkout();
      try { this.#decoder = new CBORDecoder(settings(runtimeBytes), reference); } finally { reference.release(); }
      dependency.onClose(() => this.close());
    } catch (error) { this.close(); throw error; }
    Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  #enter(): void {
    if (this.#closed) throw new Error("closed");
    if (this.#working) throw new Error("busy");
    this.#dependency!.check(); this.#working = true;
  }
  /** Copies into caller-owned storage; no persistence I/O or hidden store. */
  export(reference: V4OperationReference, destination: Uint8Array): number {
    this.#enter();
    try {
      const encoded = encodeOperationReference(reference, this.#wire), doc = this.#decoder!.decodeMap(encoded, "OperationReference"); doc.release();
      const length = byteLength(encoded);
      if (byteLength(destination) < length) throw new Error("operation_reference_capacity");
      this.#dependency!.check(); copy.call(destination, encoded); return length;
    } finally { this.#leave(); }
  }
  /** expectedDomain is supplied by trusted local configuration. Saved bytes
   * provide no peer mapping; each Session resolves and authorizes it anew. */
  import(encoded: Uint8Array, expectedDomain: string): V4OperationReference {
    this.#enter();
    try {
      if (typeof expectedDomain !== "string" || !/^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(expectedDomain)) throw new Error("operation_reference_domain");
      const length = byteLength(encoded);
      if (length < 1 || length > 2048) throw new Error("operation_reference_capacity");
      copy.call(this.#wire, encoded);
      const doc = this.#decoder!.decodeMap(byteSlice(this.#wire, 0, length), "OperationReference");
      try {
        const domain = doc.text(doc.field(0, 1));
        if (domain !== expectedDomain) throw new Error("operation_reference_domain");
        const reference = importOperationReference({ domain, target: readExecutionTarget(doc, doc.field(0, 2)),
          shape: Number(doc.uint(doc.field(0, 3))) as 0 | 1 | 2, mode: Number(doc.uint(doc.field(0, 4))) as 0 | 1,
          deadlineAtMS: doc.uint(doc.field(0, 5)), cancel: Number(doc.uint(doc.field(0, 6))) as 0 | 1 });
        this.#dependency!.check(); return reference;
      } finally { doc.release(); }
    } finally { this.#leave(); }
  }
  #leave(): void { this.#wire.fill(0); this.#working = false; this.#collect(); }
  close(): void { this.#closed = true; this.#collect(); }
  #collect(): void {
    if (!this.#closed || this.#working || this.#dependency === undefined) return;
    this.#decoder?.close(); this.#decoder = undefined; this.#position?.close(); this.#position = undefined; this.#wire.fill(0); this.#wire = new Uint8Array();
    const dependency = this.#dependency; this.#dependency = undefined; dependency.release();
  }
  toJSON(): object { return {}; }
}
export function createV4OperationReferenceCodec(environment: V4TransportEnvironment): V4OperationReferenceCodec {
  return createOperationReferenceCodec(originalEnvironment(environment));
}
/** Original assembler entry; public callers use their TransportEnvironment. */
export function createOperationReferenceCodec(environment: V4EnvironmentRuntime): V4OperationReferenceCodec {
  const runtimeBytes = environment.resources.runtimeBytes;
  const charge = new ResourceVector([8192n + 4n * runtimeBytes, 0n, 0n, 4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
  const { dependency, positions } = environment.admitDependencyPositions("operation_reference_codec", charge, cborDecoderCharge(settings(runtimeBytes)), 1);
  try { return new V4OperationReferenceCodec(capability, dependency, positions[0]!, runtimeBytes); }
  catch (error) { positions[0]!.close(); dependency.release(); throw error; }
}
Object.freeze(V4OperationReferenceCodec.prototype); Object.freeze(V4OperationReferenceCodec);
