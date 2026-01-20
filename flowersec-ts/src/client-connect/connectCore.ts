import { clientHandshake } from "../e2ee/handshake.js";
import { ByteReader } from "../yamux/byteReader.js";
import { YamuxSession } from "../yamux/session.js";
import { RpcClient } from "../rpc/client.js";
import { writeStreamHello } from "../streamhello/streamHello.js";
import { normalizeObserver, nowSeconds, type ClientObserverLike } from "../observability/observer.js";
import { base64urlDecode } from "../utils/base64url.js";
import { FlowersecError, throwIfAborted } from "../utils/errors.js";
import { WebSocketBinaryTransport, WsCloseError, type WebSocketLike } from "../ws-client/binaryTransport.js";
import type { ClientInternal } from "../client.js";
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
  /** Maximum allowed bytes for handshake payloads (0 uses default). */
  maxHandshakePayload?: number;
  /** Maximum encrypted record size on the wire (0 uses default). */
  maxRecordBytes?: number;
  /** Maximum buffered plaintext bytes in the secure channel (0 uses default). */
  maxBufferedBytes?: number;
  /** Maximum queued websocket bytes before backpressure (0 uses default). */
  maxWsQueuedBytes?: number;
  /** Optional factory for creating the WebSocket instance. */
  wsFactory?: (url: string, origin: string) => WebSocketLike;
  /** Optional observer for client metrics. */
  observer?: ClientObserverLike;
  /** Encrypted keepalive ping interval in milliseconds (0 disables). */
  keepaliveIntervalMs?: number;
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

export async function connectCore(args: ConnectCoreArgs): Promise<ClientInternal> {
  const observer = normalizeObserver(args.opts.observer);
  const signal = args.opts.signal;
  const connectTimeoutMs = args.opts.connectTimeoutMs ?? 10_000;
  const handshakeTimeoutMs = args.opts.handshakeTimeoutMs ?? 10_000;
  const connectStart = nowSeconds();

  const origin = args.opts.origin;
  if (origin == null || origin === "") {
    throw new FlowersecError({ path: args.path, stage: "validate", code: "missing_origin", message: "missing origin" });
  }
  if (args.wsUrl == null || args.wsUrl === "") {
    const code = args.path === "tunnel" ? "missing_tunnel_url" : "missing_ws_url";
    throw new FlowersecError({ path: args.path, stage: "validate", code, message: "missing websocket url" });
  }

  let ws: WebSocketLike;
  try {
    ws = createWebSocket(args.wsUrl, origin, args.opts.wsFactory);
  } catch (e) {
    if (e instanceof OriginMismatchError) {
      throw new FlowersecError({ path: args.path, stage: "validate", code: "invalid_option", message: e.message, cause: e });
    }
    if (e instanceof WsFactoryRequiredError) {
      throw new FlowersecError({ path: args.path, stage: "validate", code: "invalid_option", message: e.message, cause: e });
    }
    throw new FlowersecError({ path: args.path, stage: "connect", code: "dial_failed", message: "dial failed", cause: e });
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
      const code = reason === "timeout" ? "timeout" : reason === "canceled" ? "canceled" : "dial_failed";
      throw new FlowersecError({
        path: args.path,
        stage: "connect",
        code,
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
          code: "invalid_option",
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
        throw new FlowersecError({ path: args.path, stage: "attach", code: "attach_failed", message: "attach failed", cause: err });
      }
    }

    const transport = new WebSocketBinaryTransport(ws, {
      ...(args.opts.maxWsQueuedBytes != null && args.opts.maxWsQueuedBytes > 0 ? { maxQueuedBytes: args.opts.maxWsQueuedBytes } : {}),
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
      const maxHandshakePayload = args.opts.maxHandshakePayload ?? 0;
      const maxRecordBytes = args.opts.maxRecordBytes ?? 0;
      const maxBufferedBytes = args.opts.maxBufferedBytes ?? 0;
      secure = await withAbortAndTimeout(
        clientHandshake(transport, {
          channelId: args.channelId,
          suite,
          psk,
          clientFeatures: args.opts.clientFeatures ?? 0,
          maxHandshakePayload: maxHandshakePayload > 0 ? maxHandshakePayload : 8 * 1024,
          maxRecordBytes: maxRecordBytes > 0 ? maxRecordBytes : (1 << 20),
          ...(maxBufferedBytes > 0 ? { maxBufferedBytes } : {}),
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

      if (args.path === "tunnel" && err instanceof WsCloseError) {
        const reason = err.reason;
        if (reason === "too_many_connections") {
          throw new FlowersecError({ path: args.path, stage: "attach", code: "too_many_connections", message: "tunnel rejected attach", cause: err });
        }
        if (reason === "expected_attach") {
          throw new FlowersecError({ path: args.path, stage: "attach", code: "expected_attach", message: "tunnel rejected attach", cause: err });
        }
        if (reason === "invalid_attach") {
          throw new FlowersecError({ path: args.path, stage: "attach", code: "invalid_attach", message: "tunnel rejected attach", cause: err });
        }
        if (reason === "invalid_token") {
          throw new FlowersecError({ path: args.path, stage: "attach", code: "invalid_token", message: "tunnel rejected attach", cause: err });
        }
        if (reason === "channel_mismatch") {
          throw new FlowersecError({ path: args.path, stage: "attach", code: "channel_mismatch", message: "tunnel rejected attach", cause: err });
        }
        if (reason === "role_mismatch") {
          throw new FlowersecError({ path: args.path, stage: "attach", code: "role_mismatch", message: "tunnel rejected attach", cause: err });
        }
        if (reason === "token_replay") {
          throw new FlowersecError({ path: args.path, stage: "attach", code: "token_replay", message: "tunnel rejected attach", cause: err });
        }
        if (reason === "replace_rate_limited") {
          throw new FlowersecError({ path: args.path, stage: "attach", code: "replace_rate_limited", message: "tunnel rejected attach", cause: err });
        }
        if (reason === "attach_failed") {
          throw new FlowersecError({ path: args.path, stage: "attach", code: "attach_failed", message: "tunnel rejected attach", cause: err });
        }
      }

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

    const ping = async (): Promise<void> => {
      try {
        await secure.sendPing();
      } catch (e) {
        throw new FlowersecError({ path: args.path, stage: "secure", code: "ping_failed", message: "ping failed", cause: e });
      }
    };

    const keepaliveIntervalMs = Math.max(0, args.opts.keepaliveIntervalMs ?? 0);
    let keepaliveTimer: ReturnType<typeof setInterval> | undefined;
    let keepaliveInFlight = false;
    const stopKeepalive = () => {
      if (keepaliveTimer === undefined) return;
      clearInterval(keepaliveTimer);
      keepaliveTimer = undefined;
    };
    if (keepaliveIntervalMs > 0) {
      keepaliveTimer = setInterval(() => {
        if (keepaliveInFlight) return;
        keepaliveInFlight = true;
        ping()
          .catch(() => {
            try {
              ws.close();
            } catch {
              // ignore
            }
          })
          .finally(() => {
            keepaliveInFlight = false;
          });
      }, keepaliveIntervalMs);
      (keepaliveTimer as any)?.unref?.();
    }

    return {
      path: args.path,
      ...(args.attach != null ? { endpointInstanceId: args.attach.endpointInstanceId } : {}),
      secure,
      mux,
      rpc,
      ping,
      openStream: async (kind: string) => {
        if (kind == null || kind === "") throw new FlowersecError({ path: args.path, stage: "validate", code: "missing_stream_kind", message: "missing stream kind" });
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
        stopKeepalive();
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
