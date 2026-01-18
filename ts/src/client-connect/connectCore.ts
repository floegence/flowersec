import { clientHandshake } from "../e2ee/handshake.js";
import { ByteReader } from "../yamux/byteReader.js";
import { YamuxSession } from "../yamux/session.js";
import { RpcClient } from "../rpc/client.js";
import { writeStreamHello } from "../rpc/streamHello.js";
import { normalizeObserver, nowSeconds, type ClientObserverLike } from "../observability/observer.js";
import { base64urlDecode } from "../utils/base64url.js";
import { FlowersecError, throwIfAborted } from "../utils/errors.js";
import { WebSocketBinaryTransport, type WebSocketLike } from "../ws-client/binaryTransport.js";
import type { Client } from "../client.js";
import {
  OriginMismatchError,
  WsFactoryRequiredError,
  classifyConnectError,
  classifyHandshakeError,
  createWebSocket,
  waitOpen,
  withAbortAndTimeout,
} from "./common.js";

export type ConnectOptionsBase = Readonly<{
  /** Explicit Origin value (required). In browsers this must match window.location.origin. */
  origin: string;
  /** Optional AbortSignal to cancel connect/handshake. */
  signal?: AbortSignal;
  /** Optional websocket connect timeout in milliseconds (0 disables). */
  connectTimeoutMs?: number;
  /** Optional total E2EE handshake timeout in milliseconds (0 disables). */
  handshakeTimeoutMs?: number;
  /** Feature bitset advertised during the E2EE handshake. */
  clientFeatures?: number;
  /** Maximum allowed bytes for handshake payloads. */
  maxHandshakePayload?: number;
  /** Maximum encrypted record size on the wire. */
  maxRecordBytes?: number;
  /** Maximum buffered plaintext bytes in the secure channel. */
  maxBufferedBytes?: number;
  /** Maximum queued websocket bytes before backpressure. */
  maxWsQueuedBytes?: number;
  /** Optional factory for creating the WebSocket instance. */
  wsFactory?: (url: string, origin: string) => WebSocketLike;
  /** Optional observer for client metrics. */
  observer?: ClientObserverLike;
}>;

export type ConnectCoreArgs = Readonly<{
  path: "tunnel" | "direct";
  wsUrl: string;
  channelId: string;
  e2eePskB64u: string;
  defaultSuite: number;
  opts: ConnectOptionsBase;
  attach?: Readonly<{ attachJson: string; endpointInstanceId: string }>;
}>;

export async function connectCore(args: ConnectCoreArgs): Promise<Client> {
  const observer = normalizeObserver(args.opts.observer);
  const signal = args.opts.signal;
  const connectTimeoutMs = args.opts.connectTimeoutMs ?? 10_000;
  const handshakeTimeoutMs = args.opts.handshakeTimeoutMs ?? 10_000;
  const connectStart = nowSeconds();

  const origin = args.opts.origin;
  if (origin == null || origin === "") {
    throw new FlowersecError({ path: args.path, stage: "validate", code: "missing_origin", message: "missing origin" });
  }

  let ws: WebSocketLike;
  try {
    ws = createWebSocket(args.wsUrl, origin, args.opts.wsFactory);
  } catch (e) {
    if (e instanceof OriginMismatchError) {
      throw new FlowersecError({ path: args.path, stage: "validate", code: "origin_mismatch", message: e.message, cause: e });
    }
    if (e instanceof WsFactoryRequiredError) {
      throw new FlowersecError({ path: args.path, stage: "validate", code: "ws_factory_required", message: e.message, cause: e });
    }
    throw new FlowersecError({ path: args.path, stage: "validate", code: "websocket_init_failed", message: "websocket init failed", cause: e });
  }

  try {
    try {
      await waitOpen(ws, {
        timeoutMs: connectTimeoutMs,
        ...(signal !== undefined ? { signal } : {}),
      });
      observer.onConnect(args.path, "ok", undefined, nowSeconds() - connectStart);
    } catch (err) {
      const reason = classifyConnectError(err);
      observer.onConnect(args.path, "fail", reason, nowSeconds() - connectStart);
      throw new FlowersecError({
        path: args.path,
        stage: "connect",
        code: reason,
        message: `connect failed: ${reason}`,
        cause: err,
      });
    }

    throwIfAborted(signal, "connect aborted");

    if (args.path === "tunnel") {
      if (args.attach == null) {
        throw new FlowersecError({
          path: args.path,
          stage: "validate",
          code: "missing_attach",
          message: "missing attach payload",
        });
      }
      try {
        ws.send(args.attach.attachJson);
        observer.onAttach("ok", undefined);
      } catch (err) {
        observer.onAttach("fail", "send_failed");
        try {
          ws.close();
        } catch {
          // ignore
        }
        throw new FlowersecError({ path: args.path, stage: "attach", code: "send_failed", message: "attach send failed", cause: err });
      }
    }

    const transport = new WebSocketBinaryTransport(ws, {
      ...(args.opts.maxWsQueuedBytes !== undefined ? { maxQueuedBytes: args.opts.maxWsQueuedBytes } : {}),
      observer,
    });

    let psk: Uint8Array;
    try {
      psk = base64urlDecode(args.e2eePskB64u);
    } catch (e) {
      transport.close();
      throw new FlowersecError({ path: args.path, stage: "validate", code: "invalid_psk", message: "invalid e2ee_psk_b64u", cause: e });
    }
    if (psk.length !== 32) {
      transport.close();
      throw new FlowersecError({ path: args.path, stage: "validate", code: "invalid_psk", message: "psk must be 32 bytes" });
    }
    if (args.channelId == null || args.channelId === "") {
      transport.close();
      throw new FlowersecError({ path: args.path, stage: "validate", code: "missing_channel_id", message: "missing channel_id" });
    }
    const suite = args.defaultSuite as unknown as 1 | 2;
    if (suite !== 1 && suite !== 2) {
      transport.close();
      throw new FlowersecError({ path: args.path, stage: "validate", code: "invalid_suite", message: "invalid suite" });
    }

    const handshakeStart = nowSeconds();
    let secure: Awaited<ReturnType<typeof clientHandshake>>;
    try {
      secure = await withAbortAndTimeout(
        clientHandshake(transport, {
          channelId: args.channelId,
          suite,
          psk,
          clientFeatures: args.opts.clientFeatures ?? 0,
          maxHandshakePayload: args.opts.maxHandshakePayload ?? 8 * 1024,
          maxRecordBytes: args.opts.maxRecordBytes ?? (1 << 20),
          ...(args.opts.maxBufferedBytes !== undefined ? { maxBufferedBytes: args.opts.maxBufferedBytes } : {}),
          timeoutMs: handshakeTimeoutMs,
          ...(signal !== undefined ? { signal } : {}),
        }),
        {
          timeoutMs: handshakeTimeoutMs,
          ...(signal !== undefined ? { signal } : {}),
          onCancel: () => transport.close(),
        }
      );
      observer.onHandshake(args.path, "ok", undefined, nowSeconds() - handshakeStart);
    } catch (err) {
      observer.onHandshake(args.path, "fail", classifyHandshakeError(err), nowSeconds() - handshakeStart);
      transport.close();
      throw new FlowersecError({
        path: args.path,
        stage: "handshake",
        code: classifyHandshakeError(err),
        message: "handshake failed",
        cause: err,
      });
    }

    const conn = {
      read: () => secure.read(),
      write: (b: Uint8Array) => secure.write(b),
      close: () => secure.close(),
    };
    const mux = new YamuxSession(conn, { client: true });

    let rpcStream: Awaited<ReturnType<YamuxSession["openStream"]>>;
    try {
      rpcStream = await mux.openStream();
    } catch (e) {
      mux.close();
      secure.close();
      throw new FlowersecError({ path: args.path, stage: "yamux", code: "open_stream_failed", message: "open rpc stream failed", cause: e });
    }

    const reader = new ByteReader(async () => {
      try {
        return await rpcStream.read();
      } catch {
        return null;
      }
    });
    const readExactly = (n: number) => reader.readExactly(n);
    const write = (b: Uint8Array) => rpcStream.write(b);

    try {
      await writeStreamHello(write, "rpc");
    } catch (e) {
      try {
        await rpcStream.close();
      } catch {
        // ignore
      }
      mux.close();
      secure.close();
      throw new FlowersecError({
        path: args.path,
        stage: "rpc",
        code: "stream_hello_failed",
        message: "rpc stream hello failed",
        cause: e,
      });
    }

    const rpc = new RpcClient(readExactly, write, { observer });

    return {
      path: args.path,
      ...(args.attach != null ? { endpointInstanceId: args.attach.endpointInstanceId } : {}),
      secure,
      mux,
      rpc,
      openStream: async (kind: string) => {
        if (kind == null || kind === "") throw new FlowersecError({ path: args.path, stage: "yamux", code: "missing_stream_kind", message: "missing stream kind" });
        let s: Awaited<ReturnType<YamuxSession["openStream"]>>;
        try {
          s = await mux.openStream();
        } catch (e) {
          throw new FlowersecError({ path: args.path, stage: "yamux", code: "open_stream_failed", message: "open stream failed", cause: e });
        }
        try {
          await writeStreamHello((b) => s.write(b), kind);
        } catch (err) {
          try {
            await s.close();
          } catch {
            // ignore
          }
          throw new FlowersecError({
            path: args.path,
            stage: "rpc",
            code: "stream_hello_failed",
            message: "stream hello failed",
            cause: err,
          });
        }
        return s;
      },
      close: () => {
        rpc.close();
        mux.close();
        secure.close();
      },
    };
  } catch (e) {
    try {
      ws.close();
    } catch {
      // ignore
    }
    throw e;
  }
}
