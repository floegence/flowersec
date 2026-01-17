import { createRequire } from "node:module";
import process from "node:process";

import { ByteReader, connectTunnelClientRpc, writeStreamHello } from "../../ts/dist/index.js";

// node-tunnel-client is the "simple" Node.js tunnel client example.
//
// It uses the high-level helper connectTunnelClientRpc(), which internally performs:
// - WebSocket connect (requires explicit Origin in Node)
// - tunnel attach (text)
// - E2EE handshake
// - Yamux session
// - RPC wiring (rpcProxy)
//
// Notes:
// - The tunnel server enforces Origin allow-list; set FSEC_ORIGIN to an allowed Origin (e.g. http://127.0.0.1:5173).
// - In Node, you MUST provide wsFactory so the helper can set the Origin header (browsers set Origin automatically).
// - Tunnel attach tokens are one-time use; mint a new channel init for each connection attempt.
// - Input JSON can be either the full controlplane response {"grant_client":...,"grant_server":...}
//   or just the grant_client object itself.
const require = createRequire(import.meta.url);
const WS = require("ws");

async function readStdinUtf8() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

function pickGrantClient(obj) {
  if (obj && typeof obj === "object" && obj.grant_client != null) return obj.grant_client;
  return obj;
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

  // connectTunnelClientRpc() returns an RPC-ready client and a yamux session for extra streams.
  const client = await connectTunnelClientRpc(grant, {
    origin,
    wsFactory: (url, origin) => new WS(url, { headers: { Origin: origin } })
  });

  try {
    // Subscribe to notify type_id=2 and call request type_id=1 (see server_endpoint/direct_demo).
    const notified = waitNotify(client.rpcProxy, 2, 2000);
    const resp = await client.rpcProxy.call(1, {});
    console.log("rpc response:", JSON.stringify(resp.payload));
    console.log("rpc notify:", JSON.stringify(await notified));

    // Open a separate yamux stream ("echo") to show multiplexing over the same secure channel.
    const echo = await client.mux.openStream();
    const reader = new ByteReader(async () => {
      try {
        return await echo.read();
      } catch {
        return null;
      }
    });
    await writeStreamHello((b) => echo.write(b), "echo");
    const msg = new TextEncoder().encode("hello over yamux stream: echo");
    await echo.write(msg);
    const got = await reader.readExactly(msg.length);
    console.log("echo response:", JSON.stringify(new TextDecoder().decode(got)));
    await echo.close();
  } finally {
    client.close();
  }
}

await main();
