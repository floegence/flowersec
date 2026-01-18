import crypto from "node:crypto";
import process from "node:process";

import {
  ByteReader,
  RpcClient,
  RpcProxy,
  WebSocketBinaryTransport,
  YamuxSession,
  base64urlDecode,
  base64urlEncode,
  clientHandshake,
  writeStreamHello
} from "../../ts/dist/index.js";
import { createNodeWsFactory } from "../../ts/dist/node/index.js";
import { Role as TunnelRole } from "../../ts/dist/gen/flowersec/tunnel/v1.gen.js";

// node-tunnel-client-advanced is the "advanced" Node.js tunnel client example.
//
// It manually assembles the protocol stack:
// WebSocket connect -> tunnel attach (text) -> E2EE handshake -> Yamux -> RPC, plus an "echo" stream.
//
// Use this version when you want to understand or customize each layer.
// For the minimal helper-based version, see examples/ts/node-tunnel-client.mjs.
//
// Notes:
// - The tunnel server enforces Origin allow-list; set FSEC_ORIGIN to an allowed Origin (e.g. http://127.0.0.1:5173).
// - Tunnel attach tokens are one-time use; mint a new channel init for each connection attempt.
// - Input JSON can be either the full controlplane response {"grant_client":...,"grant_server":...}
//   or just the grant_client object itself.
async function readStdinUtf8() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

function pickGrantClient(obj) {
  if (obj && typeof obj === "object" && obj.grant_client != null) return obj.grant_client;
  return obj;
}

function waitOpen(ws, timeoutMs) {
  return new Promise((resolve, reject) => {
    let done = false;
    const t = setTimeout(() => {
      cleanup();
      reject(new Error("connect timeout"));
    }, timeoutMs);
    t.unref?.();

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
      if (done) return;
      done = true;
      clearTimeout(t);
      ws.removeEventListener("open", onOpen);
      ws.removeEventListener("error", onErr);
      ws.removeEventListener("close", onClose);
    };
    ws.addEventListener("open", onOpen);
    ws.addEventListener("error", onErr);
    ws.addEventListener("close", onClose);
  });
}

function waitNotify(proxy, typeId, timeoutMs) {
  return new Promise((resolve, reject) => {
    let unsub = () => {};
    const t = setTimeout(() => {
      unsub();
      reject(new Error("timeout waiting for notification"));
    }, timeoutMs);
    t.unref?.();
    unsub = proxy.onNotify(typeId, (payload) => {
      clearTimeout(t);
      unsub();
      resolve(payload);
    });
  });
}

async function main() {
  const input = await readStdinUtf8();
  const readyOrGrant = JSON.parse(input);
  const grant = pickGrantClient(readyOrGrant);

  // Explicit Origin header value used by the tunnel allow-list.
  const origin = process.env.FSEC_ORIGIN ?? "";
  if (!origin) throw new Error("missing FSEC_ORIGIN (explicit Origin header value)");

  // Step 1: WebSocket connect.
  const ws = createNodeWsFactory()(grant.tunnel_url, origin);
  await waitOpen(ws, 10_000);

  // Step 2: tunnel attach (plaintext JSON). This is only for pairing/auth; it does not protect data.
  const endpointInstanceId = base64urlEncode(crypto.randomBytes(24));
  const attach = {
    v: 1,
    channel_id: grant.channel_id,
    role: TunnelRole.Role_client,
    token: grant.token,
    endpoint_instance_id: endpointInstanceId
  };
  ws.send(JSON.stringify(attach));

  // Step 3: E2EE handshake over the websocket binary transport.
  const transport = new WebSocketBinaryTransport(ws);
  const psk = base64urlDecode(grant.e2ee_psk_b64u);
  const suite = grant.default_suite;
  const secure = await clientHandshake(transport, {
    channelId: grant.channel_id,
    suite,
    psk,
    clientFeatures: 0,
    maxHandshakePayload: 8 * 1024,
    maxRecordBytes: 1 << 20,
    timeoutMs: 10_000
  });

  // Step 4: Yamux session over the secure channel.
  const conn = {
    read: () => secure.read(),
    write: (b) => secure.write(b),
    close: () => secure.close()
  };
  const mux = new YamuxSession(conn, { client: true });

  // Step 5: RPC stream (first yamux stream) with StreamHello="rpc".
  const rpcStream = await mux.openStream();
  const rpcReader = new ByteReader(async () => {
    try {
      return await rpcStream.read();
    } catch {
      return null;
    }
  });
  const readExactly = (n) => rpcReader.readExactly(n);
  const write = (b) => rpcStream.write(b);
  await writeStreamHello(write, "rpc");

  // Step 6: RpcClient + RpcProxy: typed request/notify over type_id routing.
  const rpc = new RpcClient(readExactly, write);
  const rpcProxy = new RpcProxy();
  rpcProxy.attach(rpc);

  try {
    // In these demos, type_id=1 responds {"ok":true} and the server also emits notify type_id=2.
    const notified = waitNotify(rpcProxy, 2, 2000);
    const resp = await rpcProxy.call(1, {});
    console.log("rpc response:", JSON.stringify(resp.payload));
    console.log("rpc notify:", JSON.stringify(await notified));

    // Open a separate yamux stream ("echo") to show multiplexing.
    const echo = await mux.openStream();
    const echoReader = new ByteReader(async () => {
      try {
        return await echo.read();
      } catch {
        return null;
      }
    });
    await writeStreamHello((b) => echo.write(b), "echo");
    const msg = new TextEncoder().encode("hello over yamux stream: echo");
    await echo.write(msg);
    const got = await echoReader.readExactly(msg.length);
    console.log("echo response:", JSON.stringify(new TextDecoder().decode(got)));
    await echo.close();
  } finally {
    // Best-effort shutdown. secure.close() will close the underlying transport (websocket).
    rpcProxy.detach();
    rpc.close();
    mux.close();
    secure.close();
  }
}

await main();
