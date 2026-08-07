import { randomBytes } from "node:crypto";

import { adaptWebTransportCarrierSessionV2, type WebTransportSessionLikeV2 } from "../transport/webTransportAdapter.js";
import type { NativeCarrierSessionV2 } from "../v2/carrier.js";
import type { PathKind } from "../v2/contract.js";
import { RuntimeError } from "../runtime/errors.js";

export type NodeWebTransportServerOptionsV2 = Readonly<{
  host: string;
  port: number;
  path: string;
  certificate: string;
  privateKey: string;
  carrierPath: PathKind;
  inboundBidirectionalStreamCapacity: number;
}>;

export type NodeWebTransportServerV2 = Readonly<{
  address(): Readonly<{ host: string; port: number }>;
  accept(options?: Readonly<{ signal?: AbortSignal }>): Promise<NativeCarrierSessionV2>;
  close(): Promise<void>;
}>;

export async function startNodeWebTransportServerV2(
  options: NodeWebTransportServerOptionsV2,
): Promise<NodeWebTransportServerV2> {
  if (!options.path.startsWith("/") || options.path.includes("?") || options.path.includes("#")) {
    throw new TypeError("Node WebTransport server path must be an absolute path");
  }
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65_535) {
    throw new RangeError("Node WebTransport server port is invalid");
  }
  let runtime: NodeWebTransportRuntime;
  try {
    runtime = await loadNodeWebTransportRuntime();
    await runtime.quicheLoaded;
  } catch (error) {
    throw new RuntimeError("runtime_start_failed", "Node WebTransport runtime failed to load", error);
  }
  let server: NodeWebTransportServerRuntime;
  try {
    server = new runtime.Http3Server({
      host: options.host,
      port: options.port,
      secret: randomBytes(32).toString("hex"),
      cert: options.certificate,
      privKey: options.privateKey,
    });
  } catch (error) {
    throw new RuntimeError("runtime_start_failed", "Node WebTransport server could not be created", error);
  }
  const sessions = server.sessionStream(options.path).getReader();
  server.startServer();
  try {
    await server.ready;
  } catch (error) {
    server.stopServer();
    throw new RuntimeError("runtime_start_failed", "Node WebTransport server failed to start", error);
  }
  let closed = false;
  return {
    address() {
      const address = server.address();
      if (address === null) throw new Error("Node WebTransport server is not listening");
      return Object.freeze({ host: address.host, port: address.port });
    },
    async accept(acceptOptions = {}) {
      if (closed) throw new Error("Node WebTransport server is closed");
      try {
        const result = await raceAbort(sessions.read(), acceptOptions.signal);
        if (result.done || result.value === undefined) {
          throw new RuntimeError("runtime_crashed", "Node WebTransport server session stream closed");
        }
        await raceAbort(result.value.ready, acceptOptions.signal);
        return adaptWebTransportCarrierSessionV2(result.value, {
          path: options.carrierPath,
          inboundBidirectionalStreamCapacity: options.inboundBidirectionalStreamCapacity,
          datagramMaxSize: 1_200,
        });
      } catch (error) {
        if (error instanceof RuntimeError) throw error;
        throw new RuntimeError("runtime_crashed", "Node WebTransport server failed while accepting a session", error);
      }
    },
    async close() {
      if (closed) return;
      closed = true;
      server.stopServer();
      try {
        await server.closed;
      } catch (error) {
        throw new RuntimeError("runtime_crashed", "Node WebTransport server failed while closing", error);
      }
    },
  };
}

const NODE_WEBTRANSPORT_MODULE = "@fails-components/webtransport";
type NodeWebTransportRuntime = Readonly<{
  quicheLoaded: Promise<unknown>;
  Http3Server: new (options: Readonly<{
    host: string;
    port: number;
    secret: string;
    cert: string;
    privKey: string;
  }>) => NodeWebTransportServerRuntime;
}>;
type NodeWebTransportServerRuntime = Readonly<{
  ready: Promise<unknown>;
  closed: Promise<unknown>;
  startServer(): void;
  stopServer(): void;
  address(): Readonly<{ host: string; port: number }> | null;
  sessionStream(path: string): ReadableStream<NodeWebTransportSessionRuntime>;
}>;
type NodeWebTransportSessionRuntime = WebTransportSessionLikeV2 & Readonly<{ ready: Promise<void> }>;
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
