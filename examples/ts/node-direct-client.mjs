import process from "node:process";
import { createRequire } from "node:module";

import {
  base64urlDecode,
  ByteReader,
  clientHandshake,
  RpcClient,
  RpcProxy,
  WebSocketBinaryTransport,
  writeStreamHello,
  YamuxSession
} from "../../ts/dist/index.js";

const require = createRequire(import.meta.url);
const WS = require("ws");

async function readStdinUtf8() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

function waitOpen(ws) {
  return new Promise((resolve, reject) => {
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

async function connectDirectClientRpc(info) {
  const ws = new WS(info.ws_url);
  await waitOpen(ws);

  const transport = new WebSocketBinaryTransport(ws);
  const psk = base64urlDecode(info.e2ee_psk_b64u);
  const suite = info.default_suite;
  const secure = await clientHandshake(transport, {
    channelId: info.channel_id,
    suite,
    psk,
    clientFeatures: 0,
    maxHandshakePayload: 8 * 1024,
    maxRecordBytes: 1 << 20
  });

  const conn = {
    read: () => secure.read(),
    write: (b) => secure.write(b),
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
  const readExactly = (n) => reader.readExactly(n);
  const write = (b) => rpcStream.write(b);

  await writeStreamHello(write, "rpc");
  const rpc = new RpcClient(readExactly, write);
  const rpcProxy = new RpcProxy();
  rpcProxy.attach(rpc);

  return {
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

async function main() {
  const input = await readStdinUtf8();
  const info = JSON.parse(input);
  const client = await connectDirectClientRpc(info);
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
