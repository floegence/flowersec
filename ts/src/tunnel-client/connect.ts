import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import { Role as TunnelRole, type Attach } from "../gen/flowersec/tunnel/v1.gen.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { WebSocketBinaryTransport, type WebSocketLike } from "../ws-client/binaryTransport.js";
import { clientHandshake } from "../e2ee/handshake.js";
import { YamuxSession } from "../yamux/session.js";
import { ByteReader } from "../yamux/byteReader.js";
import { RpcClient } from "../rpc/client.js";
import { writeStreamHello } from "../rpc/streamHello.js";
import { RpcProxy } from "../rpc-proxy/rpcProxy.js";

export type TunnelConnectOptions = Readonly<{
  endpointInstanceId?: string;
  clientFeatures?: number;
  maxHandshakePayload?: number;
  maxRecordBytes?: number;
  wsFactory?: (url: string) => WebSocketLike;
}>;

export async function connectTunnelClientRpc(grant: ChannelInitGrant, opts: TunnelConnectOptions = {}) {
  const ws = (opts.wsFactory ?? defaultWebSocketFactory)(grant.tunnel_url);
  await waitOpen(ws);

  const endpointInstanceId = opts.endpointInstanceId ?? base64urlEncode(randomBytes(24));
  const attach: Attach = {
    v: 1,
    channel_id: grant.channel_id,
    role: TunnelRole.Role_client,
    token: grant.token,
    endpoint_instance_id: endpointInstanceId
  };
  ws.send(JSON.stringify(attach));

  const transport = new WebSocketBinaryTransport(ws);
  const psk = base64urlDecode(grant.e2ee_psk_b64u);
  const suite = grant.default_suite as unknown as 1 | 2;
  const secure = await clientHandshake(transport, {
    channelId: grant.channel_id,
    suite,
    psk,
    clientFeatures: opts.clientFeatures ?? 0,
    maxHandshakePayload: opts.maxHandshakePayload ?? 8 * 1024,
    maxRecordBytes: opts.maxRecordBytes ?? (1 << 20)
  });

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
  const rpc = new RpcClient(readExactly, write);
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

function defaultWebSocketFactory(url: string): WebSocketLike {
  return new WebSocket(url) as unknown as WebSocketLike;
}

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

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}
