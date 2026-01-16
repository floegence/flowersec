import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import { Role as TunnelRole, type Attach } from "../gen/flowersec/tunnel/v1.gen.js";
import { normalizeObserver, nowSeconds, type ClientObserverLike } from "../observability/observer.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { WebSocketBinaryTransport, type WebSocketLike } from "../ws-client/binaryTransport.js";
import { clientHandshake } from "../e2ee/handshake.js";
import { YamuxSession } from "../yamux/session.js";
import { ByteReader } from "../yamux/byteReader.js";
import { RpcClient } from "../rpc/client.js";
import { writeStreamHello } from "../rpc/streamHello.js";
import { RpcProxy } from "../rpc-proxy/rpcProxy.js";

// TunnelConnectOptions controls transport and handshake limits.
export type TunnelConnectOptions = Readonly<{
  /** Optional caller-provided endpoint instance ID (base64url). */
  endpointInstanceId?: string;
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
  wsFactory?: (url: string) => WebSocketLike;
  /** Optional observer for client metrics. */
  observer?: ClientObserverLike;
}>;

// connectTunnelClientRpc attaches to a tunnel and returns an RPC-ready client.
export async function connectTunnelClientRpc(grant: ChannelInitGrant, opts: TunnelConnectOptions = {}) {
  const observer = normalizeObserver(opts.observer);
  const connectStart = nowSeconds();
  const ws = (opts.wsFactory ?? defaultWebSocketFactory)(grant.tunnel_url);
  try {
    await waitOpen(ws);
    observer.onTunnelConnect("ok", undefined, nowSeconds() - connectStart);
  } catch (err) {
    const reason = err instanceof Error && err.message === "websocket closed" ? "websocket_closed" : "websocket_error";
    observer.onTunnelConnect("fail", reason, nowSeconds() - connectStart);
    throw err;
  }

  const endpointInstanceId = opts.endpointInstanceId ?? base64urlEncode(randomBytes(24));
  const attach: Attach = {
    v: 1,
    channel_id: grant.channel_id,
    role: TunnelRole.Role_client,
    token: grant.token,
    endpoint_instance_id: endpointInstanceId
  };
  try {
    ws.send(JSON.stringify(attach));
    observer.onTunnelAttach("ok", undefined);
  } catch (err) {
    observer.onTunnelAttach("fail", "send_failed");
    throw err;
  }

  const transport = new WebSocketBinaryTransport(ws, {
    ...(opts.maxWsQueuedBytes !== undefined ? { maxQueuedBytes: opts.maxWsQueuedBytes } : {}),
    observer
  });
  const psk = base64urlDecode(grant.e2ee_psk_b64u);
  const suite = grant.default_suite as unknown as 1 | 2;
  // Complete the E2EE handshake over the websocket transport.
  const handshakeStart = nowSeconds();
  let secure: Awaited<ReturnType<typeof clientHandshake>>;
  try {
    secure = await clientHandshake(transport, {
      channelId: grant.channel_id,
      suite,
      psk,
      clientFeatures: opts.clientFeatures ?? 0,
      maxHandshakePayload: opts.maxHandshakePayload ?? 8 * 1024,
      maxRecordBytes: opts.maxRecordBytes ?? (1 << 20),
      ...(opts.maxBufferedBytes !== undefined ? { maxBufferedBytes: opts.maxBufferedBytes } : {})
    });
    observer.onTunnelHandshake("ok", undefined, nowSeconds() - handshakeStart);
  } catch (err) {
    observer.onTunnelHandshake("fail", "handshake_error", nowSeconds() - handshakeStart);
    throw err;
  }

  const conn = {
    read: () => secure.read(),
    write: (b: Uint8Array) => secure.write(b),
    close: () => secure.close()
  };
  const mux = new YamuxSession(conn, { client: true });
  const rpcStream = await mux.openStream();

  const reader = new ByteReader(async () => {
    try {
      return await rpcStream.read();
    } catch {
      return null;
    }
  });
  const readExactly = (n: number) => reader.readExactly(n);
  const write = (b: Uint8Array) => rpcStream.write(b);

  await writeStreamHello(write, "rpc");
  const rpc = new RpcClient(readExactly, write, { observer });
  const rpcProxy = new RpcProxy();
  rpcProxy.attach(rpc);

  return {
    endpointInstanceId,
    secure,
    mux,
    rpc,
    rpcProxy,
    close: () => {
      rpcProxy.detach();
      rpc.close();
      mux.close();
      secure.close();
    }
  };
}

// defaultWebSocketFactory constructs a browser WebSocket.
function defaultWebSocketFactory(url: string): WebSocketLike {
  return new WebSocket(url) as unknown as WebSocketLike;
}

// waitOpen resolves when the websocket opens or rejects on error/close.
function waitOpen(ws: WebSocketLike): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const onOpen = () => {
      cleanup();
      resolve();
    };
    const onErr = () => {
      cleanup();
      reject(new Error("websocket error"));
    };
    const onClose = () => {
      cleanup();
      reject(new Error("websocket closed"));
    };
    const cleanup = () => {
      ws.removeEventListener("open", onOpen);
      ws.removeEventListener("error", onErr);
      ws.removeEventListener("close", onClose);
    };
    ws.addEventListener("open", onOpen);
    ws.addEventListener("error", onErr);
    ws.addEventListener("close", onClose);
  });
}

// randomBytes uses the Web Crypto API for nonces and IDs.
function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}
