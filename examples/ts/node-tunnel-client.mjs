import { createRequire } from "node:module";
import process from "node:process";

import { ByteReader, connectTunnelClientRpc, writeStreamHello } from "../../ts/dist/index.js";

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

  const client = await connectTunnelClientRpc(grant, {
    wsFactory: (url) => new WS(url)
  });

  try {
    const notified = waitNotify(client.rpcProxy, 2, 2000);
    const resp = await client.rpcProxy.call(1, {});
    console.log("rpc response:", JSON.stringify(resp.payload));
    console.log("rpc notify:", JSON.stringify(await notified));

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
