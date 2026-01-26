import process from "node:process";

import { connectTunnelNode } from "../../flowersec-ts/dist/node/index.js";
import { createDemoSession } from "../../flowersec-ts/dist/_examples/flowersec/demo/v1.facade.gen.js";
import { createByteReader } from "../../flowersec-ts/dist/streamio/index.js";

// node-tunnel-client is the "simple" Node.js tunnel client example.
//
// It uses the high-level helper connectTunnelNode(), which internally performs:
// - WebSocket connect (requires explicit Origin in Node)
// - tunnel attach (text)
// - E2EE handshake
// - Yamux session
// - RPC stream
//
// Notes:
// - The tunnel server enforces Origin allow-list; set FSEC_ORIGIN to an allowed Origin (e.g. http://127.0.0.1:5173).
// - In Node, connectTunnelNode() automatically sets wsFactory so the Origin header is sent correctly.
// - Tunnel attach tokens are one-time use; mint a new channel init for each connection attempt.
// - Input JSON can be either the controlplane response {"grant_client":...}
//   or just the grant_client object itself.
async function readStdinUtf8() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

function waitHello(demo, timeoutMs) {
  return new Promise((resolve, reject) => {
    let unsub = () => {};
    const t = setTimeout(() => {
      unsub();
      reject(new Error("timeout waiting for notification"));
    }, timeoutMs);
    t.unref?.();
    unsub = demo.onHello((payload) => {
      clearTimeout(t);
      unsub();
      resolve(payload);
    });
  });
}

async function main() {
  const input = await readStdinUtf8();
  const readyOrGrant = JSON.parse(input);

  // Explicit Origin header value used by the tunnel allow-list.
  const origin = process.env.FSEC_ORIGIN ?? "";
  if (!origin) throw new Error("missing FSEC_ORIGIN (explicit Origin header value)");

  // connectTunnelNode() returns an RPC-ready session and supports extra yamux streams via openStream(kind).
  const sess = createDemoSession(await connectTunnelNode(readyOrGrant, { origin }));

  try {
    const notified = waitHello(sess.demo, 2000);
    const resp = await sess.demo.ping({});
    console.log("rpc response:", JSON.stringify(resp));
    console.log("rpc notify:", JSON.stringify(await notified));

    // Open a separate yamux stream ("echo") to show multiplexing over the same secure channel.
    // Note: openStream(kind) automatically writes the StreamHello(kind) preface.
    const echo = await sess.openStream("echo");
    const reader = createByteReader(echo);
    const msg = new TextEncoder().encode("hello over yamux stream: echo");
    await echo.write(msg);
    const got = await reader.readExactly(msg.length);
    console.log("echo response:", JSON.stringify(new TextDecoder().decode(got)));
    await echo.close();
  } finally {
    sess.close();
  }
}

await main();
