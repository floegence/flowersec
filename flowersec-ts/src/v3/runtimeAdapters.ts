import { WebSocketBinaryTransport, type WebSocketLike } from "../ws-client/binaryTransport.js";
import type { ArtifactV3, CanonicalArtifactCandidateV3 } from "./artifact.js";
import {
  adaptNativeCarrierSessionV3,
  type NativeCarrierSessionV3,
} from "./carrier.js";
import type { ReadyAdmissionTransportV3 } from "./sessionConnector.js";
import { TransportFailureV3 } from "./security.js";
import { createWebSocketCarrierSessionV3 } from "./webSocketCarrier.js";
import { websocketSubprotocolForPathV3 } from "./transportConstants.js";

export type WebSocketLikeV3 = WebSocketLike & Readonly<{ protocol?: string }>;

export async function readyWebSocketAdmissionV3(
  candidate: CanonicalArtifactCandidateV3,
  artifact: ArtifactV3,
  socket: WebSocketLikeV3,
  signal: AbortSignal,
): Promise<ReadyAdmissionTransportV3> {
  const subprotocol = websocketSubprotocolForPathV3(artifact.path.kind);
  await waitForWebSocketOpen(socket, subprotocol, signal);
  const transport = new WebSocketBinaryTransport(socket);
  let finalized = false;
  return {
    candidate,
    openAdmissionChannel: async () => ({
      framing: "message",
      write: async (data, operationSignal) => await transport.writeBinary(
        data,
        operationSignal === undefined ? {} : { signal: operationSignal },
      ),
      read: async (operationSignal) => await transport.readBinary(
        operationSignal === undefined ? {} : { signal: operationSignal },
      ),
      abort: () => transport.close(),
    }),
    finalize: () => {
      if (finalized) throw new TransportFailureV3("connection_failed");
      finalized = true;
      return createWebSocketCarrierSessionV3(transport, {
        path: artifact.path.kind,
        client: artifact.path.kind !== "tunnel" || artifact.path.role !== 2,
        inboundBidirectionalStreamCapacity: artifact.session.max_inbound_streams + 2,
      });
    },
    close: async () => transport.close(),
    abort: () => transport.close(),
  };
}

export function readyNativeAdmissionV3(
  candidate: CanonicalArtifactCandidateV3,
  carrier: NativeCarrierSessionV3,
): ReadyAdmissionTransportV3 {
  let finalized = false;
  return {
    candidate,
    openAdmissionChannel: async (signal) => {
      const options = signal === undefined ? {} : { signal };
      const stream = carrier.kind === "webtransport"
        ? await carrier.acceptStream(options)
        : await carrier.openStream(options);
      return {
        framing: "stream",
        stream,
        abort: (error) => stream.abort(error),
      };
    },
    finalize: () => {
      if (finalized) throw new TransportFailureV3("connection_failed");
      finalized = true;
      return adaptNativeCarrierSessionV3(carrier);
    },
    close: async () => await carrier.close(),
    abort: () => carrier.abort({ code: 6, reason: "candidate aborted" }),
  };
}

function waitForWebSocketOpen(
  socket: WebSocketLikeV3,
  expectedProtocol: string,
  signal: AbortSignal,
): Promise<void> {
  if (signal.aborted) return Promise.reject(signal.reason);
  if (socket.readyState === 1) {
    if (socket.protocol === undefined || socket.protocol === expectedProtocol) return Promise.resolve();
    closeWebSocketAfterProtocolMismatch(socket);
    return Promise.reject(new TransportFailureV3("connection_failed"));
  }
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      socket.removeEventListener("open", open);
      socket.removeEventListener("error", error);
      socket.removeEventListener("close", close);
      signal.removeEventListener("abort", abort);
    };
    const finish = (failure?: unknown) => {
      if (settled) return;
      settled = true;
      cleanup();
      failure === undefined ? resolve() : reject(failure);
    };
    const open = () => {
      if (socket.protocol === undefined || socket.protocol === expectedProtocol) {
        finish();
        return;
      }
      closeWebSocketAfterProtocolMismatch(socket);
      finish(new TransportFailureV3("connection_failed"));
    };
    const error = (event: unknown) => finish(new TransportFailureV3("connection_failed", undefined, event));
    const close = () => finish(new TransportFailureV3("connection_failed"));
    const abort = () => {
      socket.close();
      finish(signal.reason);
    };
    socket.addEventListener("open", open);
    socket.addEventListener("error", error);
    socket.addEventListener("close", close);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
}

function closeWebSocketAfterProtocolMismatch(socket: WebSocketLikeV3): void {
  try { socket.close(); } catch { /* best effort cleanup after a failed handshake */ }
}
