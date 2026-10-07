import type { V4TopUpControlTransport, V4TopUpExchangeResult } from "./poolSource.js";
import { V4ServiceClient } from "./serviceClient.js";
import { rpcUnaryResultCleanup } from "./runtime/rpcUnaryExchange.js";
import { rpcUnaryCallCleanup } from "./runtime/rpcUnaryCall.js";
import { methodDefinition, type V4MethodDefinition, type V4ServiceMethods } from "./serviceDefinition.js";

export interface V4PoolControlReplyDecoder {
  /** Decode only authenticated application completion. Local I/O failure must
   * never be projected into an authoritative terminal operation result. */
  decode(method: 41006 | 41007, applicationErrorCode: number | undefined, payload: Uint8Array): V4TopUpExchangeResult;
}
/** Uses the already bound real Session service client and its original method
 * slots. Calls are transient, explicit, bounded, and never automatically retried. */
export function createV4SessionPoolControl<Methods extends V4ServiceMethods>(client: V4ServiceClient<Methods>,
  topUp: V4MethodDefinition<Uint8Array, Uint8Array, "unary", "transient"> & Methods[keyof Methods],
  ack: V4MethodDefinition<Uint8Array, Uint8Array, "unary", "transient"> & Methods[keyof Methods],
  decoder: V4PoolControlReplyDecoder, timeoutMS: bigint): V4TopUpControlTransport {
  if (!(client instanceof V4ServiceClient) || typeof timeoutMS !== "bigint" || timeoutMS < 1n || timeoutMS > 120000n || typeof decoder.decode !== "function") throw new Error("source_contract_invalid");
  const decode = decoder.decode.bind(decoder);
  for (const [method, id] of [[topUp, 41006], [ack, 41007]] as const) {
    const facts = methodDefinition(method);
    if (facts.typeID !== id || facts.shape !== "unary" || facts.semantics !== "transient" || facts.request.implementation !== "bytes" ||
        facts.response?.implementation !== "bytes" || facts.requestMaxBytes > 524288 || facts.maxResponseBytes > 524288) throw new Error("source_contract_invalid");
  }
  return Object.freeze({ async exchange(method: 41006 | 41007, request: Uint8Array, signal: AbortSignal): Promise<V4TopUpExchangeResult> {
    signal.throwIfAborted();
    const definition = method === 41006 ? topUp : method === 41007 ? ack : undefined;
    if (definition === undefined || request.length < 1 || request.length > methodDefinition(definition).requestMaxBytes) throw new Error("source_contract_invalid");
    const call = client.call(definition, request, { timeoutMS, signal, responseLimitBytes: methodDefinition(definition).maxResponseBytes });
    try {
      const result = await call;
      let release: (() => void) | undefined;
      try {
        if (result.kind !== "value" && result.kind !== "application_error") throw new Error("source_unavailable");
        if (!("release" in result) || typeof (result as { release?: unknown }).release !== "function") throw new Error("source_unavailable");
        release = (result as { release: () => void }).release;
        const payload = result.encoding === "encoded" ? result.bytes : result.kind === "value" ? result.value : result.error;
        if (!(payload instanceof Uint8Array)) throw new Error("source_contract_invalid");
        const decoded = decode(method, result.kind === "application_error" ? Number(result.header.uint(10)) : undefined, payload);
        return decoded.kind === "success" || decoded.kind === "replay" ? Object.freeze({ kind: decoded.kind, response: new Uint8Array(decoded.response) }) : Object.freeze({ ...decoded });
      } finally {
        const cleanup = rpcUnaryResultCleanup(result);
        release?.();
        await cleanup;
      }
    } finally {
      // Rejected/metadata/sdk-error calls have no result shell, but the
      // original convenience call still owns a physical exchange tail.
      await rpcUnaryCallCleanup(call);
    }
  } });
}
