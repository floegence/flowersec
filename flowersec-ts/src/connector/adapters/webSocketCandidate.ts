import type { ArtifactV2, CanonicalArtifactCandidateV2 } from "../../v2/artifact.js";
import type { ReadyAdmissionTransportV2 } from "../admissionCommit.js";
import type {
  CandidateAttemptFactoryV2,
  CandidateAttemptV2,
} from "../sessionConnector.js";
import { createWebSocketCarrierSessionV2 } from "../../transport/webSocketAdapter.js";
import { WebSocketBinaryTransport, type WebSocketLike } from "../../ws-client/binaryTransport.js";

type WebSocketLikeWithProtocol = WebSocketLike & Readonly<{ protocol?: string }>;

export function createWebSocketCandidateFactoryV2(
  factory: (url: string, subprotocol: string) => WebSocketLikeWithProtocol,
): CandidateAttemptFactoryV2 {
  return {
    create(candidate, artifact) {
      if (candidate.carrier !== "websocket") throw new Error(`unsupported WebSocket carrier ${candidate.carrier}`);
      return new WebSocketCandidateAttempt(candidate, artifact, factory);
    },
  };
}

class WebSocketCandidateAttempt implements CandidateAttemptV2 {
  private socket: WebSocketLikeWithProtocol | undefined;
  private transport: WebSocketBinaryTransport | undefined;
  private aborted = false;
  private finalized = false;

  constructor(
    readonly candidate: CanonicalArtifactCandidateV2,
    private readonly artifact: ArtifactV2,
    private readonly factory: (url: string, subprotocol: string) => WebSocketLikeWithProtocol,
  ) {}

  async ready(signal?: AbortSignal): Promise<ReadyAdmissionTransportV2> {
    if (this.aborted) throw new Error("WebSocket candidate aborted");
    const path = this.artifact.path.kind;
    const subprotocol = path === "direct" ? "flowersec.direct.v2" : "flowersec.tunnel.v2";
    const socket = this.factory(this.candidate.normalized_url, subprotocol);
    this.socket = socket;
    await waitForOpen(socket, subprotocol, signal);
    if (this.aborted) throw new Error("WebSocket candidate aborted");
    const transport = new WebSocketBinaryTransport(socket);
    this.transport = transport;
    const inboundBidirectionalStreamCapacity = this.artifact.session.max_inbound_streams + 2;
    return {
      candidate: this.candidate,
      kind: "websocket",
      path,
      inboundBidirectionalStreamCapacity,
      openAdmissionChannel: async () => ({
        framing: "message",
        write: async (data, options = {}) => await transport.writeBinary(data, options),
        read: async (options = {}) => await transport.readBinary(options),
        abort: () => transport.close(),
      }),
      finalize: () => {
        if (this.finalized) throw new Error("WebSocket candidate already finalized");
        this.finalized = true;
        return createWebSocketCarrierSessionV2(transport, {
          path,
          client: this.artifact.path.kind !== "tunnel" || this.artifact.path.role !== 2,
          inboundBidirectionalStreamCapacity,
        });
      },
      close: async () => transport.close(),
      abort: () => transport.close(),
    };
  }

  abort(): void {
    this.aborted = true;
    this.transport?.close();
    this.socket?.close();
  }
}

function waitForOpen(socket: WebSocketLikeWithProtocol, expectedProtocol: string, signal?: AbortSignal): Promise<void> {
  if (socket.readyState === 1) {
    validateSubprotocol(socket, expectedProtocol);
    return Promise.resolve();
  }
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      socket.removeEventListener("open", open);
      socket.removeEventListener("error", error);
      socket.removeEventListener("close", close);
      signal?.removeEventListener("abort", abort);
    };
    const finish = (failure?: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      failure === undefined ? resolve() : reject(failure);
    };
    const open = () => {
      try { validateSubprotocol(socket, expectedProtocol); finish(); } catch (cause) { finish(asError(cause)); }
    };
    const error = () => finish(new Error("WebSocket candidate failed before ready"));
    const close = () => finish(new Error("WebSocket candidate closed before ready"));
    const abort = () => { socket.close(); finish(new Error("WebSocket candidate aborted")); };
    socket.addEventListener("open", open);
    socket.addEventListener("error", error);
    socket.addEventListener("close", close);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted === true) abort();
  });
}

function validateSubprotocol(socket: WebSocketLikeWithProtocol, expected: string): void {
  if (socket.protocol !== undefined && socket.protocol !== expected) {
    throw new Error(`unexpected WebSocket subprotocol ${socket.protocol}`);
  }
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
