import process from "node:process";

import { connectDirectNode } from "../../flowersec-ts/dist/node/index.js";
import { createDemoClient } from "../../flowersec-ts/dist/gen/flowersec/demo/v1.rpc.gen.js";
import { ByteReader } from "../../flowersec-ts/dist/yamux/index.js";

// node-direct-client is the "simple" Node.js direct (no tunnel) client example.
//
// It uses the high-level helper connectDirect(), which internally performs:
// - WebSocket connect (requires explicit Origin in Node)
// - E2EE handshake
// - Yamux session
// - RPC stream
//
// Notes:
// - The direct demo server enforces Origin allow-list; set FSEC_ORIGIN to an allowed Origin (e.g. http://127.0.0.1:5173).
// - In Node, connectDirectNode() automatically sets wsFactory so the Origin header is sent correctly.
// - Input JSON is the output of examples/go/direct_demo.

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
  const info = JSON.parse(input);

  // Explicit Origin header value used by the server allow-list.
  const origin = process.env.FSEC_ORIGIN ?? "";
  if (!origin) throw new Error("missing FSEC_ORIGIN (explicit Origin header value)");

  // connectDirectNode() returns an RPC-ready session and supports extra yamux streams via openStream(kind).
  const client = await connectDirectNode(info, { origin });

  try {
    const demo = createDemoClient(client.rpc);
    const notified = waitHello(demo, 2000);
    const resp = await demo.ping({});
    console.log("rpc response:", JSON.stringify(resp));
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
