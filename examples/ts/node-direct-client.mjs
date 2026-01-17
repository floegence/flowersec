import { createRequire } from "node:module";
import process from "node:process";

import { ByteReader, connectDirect } from "../../ts/dist/index.js";

// node-direct-client is the "simple" Node.js direct (no tunnel) client example.
//
// It uses the high-level helper connectDirect(), which internally performs:
// - WebSocket connect (requires explicit Origin in Node)
// - E2EE handshake
// - Yamux session
// - RPC wiring (rpcProxy)
//
// Notes:
// - The direct demo server enforces Origin allow-list; set FSEC_ORIGIN to an allowed Origin (e.g. http://127.0.0.1:5173).
// - In Node, you MUST provide wsFactory so the helper can set the Origin header (browsers set Origin automatically).
// - Input JSON is the output of examples/go/direct_demo.
const require = createRequire(import.meta.url);
const WS = require("ws");

async function readStdinUtf8() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
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
  const info = JSON.parse(input);

  // Explicit Origin header value used by the server allow-list.
  const origin = process.env.FSEC_ORIGIN ?? "";
  if (!origin) throw new Error("missing FSEC_ORIGIN (explicit Origin header value)");

  // connectDirect() returns an RPC-ready session and a yamux session for extra streams.
  const client = await connectDirect(info, {
    origin,
    wsFactory: (url, origin) => new WS(url, { headers: { Origin: origin } })
  });

  try {
    // Subscribe to notify type_id=2 and call request type_id=1 (see direct_demo).
    const notified = waitNotify(client.rpcProxy, 2, 2000);
    const resp = await client.rpcProxy.call(1, {});
    console.log("rpc response:", JSON.stringify(resp.payload));
    console.log("rpc notify:", JSON.stringify(await notified));

    // Open a separate yamux stream ("echo") to show multiplexing over the same secure channel.
    // Note: client.openStream(kind) automatically writes the StreamHello(kind) preface.
    const echo = await client.openStream("echo");
    const reader = new ByteReader(async () => {
      try {
        return await echo.read();
      } catch {
        return null;
      }
    });
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
