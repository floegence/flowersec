import { adaptWebTransportCarrierSessionV2, type WebTransportSessionLikeV2 } from "../transport/webTransportAdapter.js";
import type { NativeCarrierSessionV2 } from "../v2/carrier.js";
import type { PathKind } from "../v2/contract.js";
import { RuntimeError } from "../runtime/errors.js";

export type NodeWebTransportClientOptionsV2 = Readonly<{
  path: PathKind;
  inboundBidirectionalStreamCapacity: number;
  signal?: AbortSignal;
  serverCertificateHash?: Uint8Array;
}>;

export async function createNodeWebTransportClientV2(
  url: string,
  options: NodeWebTransportClientOptionsV2,
): Promise<NativeCarrierSessionV2> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (error) {
    throw new RuntimeError("runtime_start_failed", "Node WebTransport URL is invalid", error);
  }
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "") {
    throw new RuntimeError("runtime_start_failed", "Node WebTransport requires an HTTPS URL without credentials");
  }
  if (options.signal?.aborted === true) throw options.signal.reason;
  let transport: (WebTransportSessionLikeV2 & Readonly<{ ready: Promise<void> }>) | undefined;
  try {
    const runtime = await loadNodeWebTransportRuntime();
    await raceAbort(runtime.quicheLoaded, options.signal);
    transport = new runtime.WebTransport(parsed.href, {
      requireUnreliable: true,
      ...(options.serverCertificateHash === undefined
        ? {}
        : { serverCertificateHashes: [{ algorithm: "sha-256", value: options.serverCertificateHash.slice() }] }),
    });
    await raceAbort(transport.ready, options.signal);
    return adaptWebTransportCarrierSessionV2(transport, {
      path: options.path,
      inboundBidirectionalStreamCapacity: options.inboundBidirectionalStreamCapacity,
      datagramMaxSize: 1_200,
    });
  } catch (error) {
    transport?.close({ closeCode: 6, reason: "Node WebTransport start failed" });
    if (error instanceof RuntimeError) throw error;
    throw new RuntimeError("runtime_start_failed", "Node WebTransport failed to start", error);
  }
}

const NODE_WEBTRANSPORT_MODULE = "@fails-components/webtransport";
type NodeWebTransportRuntime = Readonly<{
  quicheLoaded: Promise<unknown>;
  WebTransport: new (url: string, options: Readonly<{
    requireUnreliable: boolean;
    serverCertificateHashes?: readonly Readonly<{ algorithm: string; value: Uint8Array }>[];
  }>) => WebTransportSessionLikeV2 & Readonly<{ ready: Promise<void> }>;
}>;
let runtimePromise: Promise<NodeWebTransportRuntime> | undefined;

function loadNodeWebTransportRuntime(): Promise<NodeWebTransportRuntime> {
  runtimePromise ??= import(NODE_WEBTRANSPORT_MODULE).then((value) => value as unknown as NodeWebTransportRuntime);
  return runtimePromise;
}

async function raceAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return await promise;
  if (signal.aborted) throw signal.reason;
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
