import { expect, test } from "@playwright/test";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createProxyServiceWorkerScript } from "../dist/proxy/serviceWorker.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const serviceWorkerScript = createProxyServiceWorkerScript({
  proxyPathPrefix: "/proxy/",
  stripProxyPathPrefix: true,
  runtimeRegistrationToken: "browser-smoke",
});

let server: http.Server;
let origin: string;

test.beforeAll(async () => {
  server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/sw.js") {
      response.writeHead(200, {
        "cache-control": "no-store",
        "content-type": "text/javascript; charset=utf-8",
        "service-worker-allowed": "/",
      });
      response.end(serviceWorkerScript);
      return;
    }
    if (url.pathname.startsWith("/dist/")) {
      const relative = url.pathname.slice(1);
      const file = path.resolve(packageRoot, relative);
      if (!file.startsWith(path.join(packageRoot, "dist") + path.sep) || !fs.existsSync(file)) {
        response.writeHead(404).end();
        return;
      }
      response.writeHead(200, { "content-type": "text/javascript; charset=utf-8" });
      response.end(fs.readFileSync(file));
      return;
    }
    if (url.pathname === "/") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(browserPage());
      return;
    }
    response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
    response.end("network fallback should not be used");
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (address == null || typeof address === "string") throw new Error("browser smoke server did not bind TCP");
  origin = `http://127.0.0.1:${address.port}`;
});

test.afterAll(async () => {
  if (server == null) return;
  await new Promise<void>((resolve, reject) => server.close((error) => error == null ? resolve() : reject(error)));
});

test("generated Service Worker proxies HTTP and browser WebSocket patch traffic", { tag: "@webkit-smoke" }, async ({ page }) => {
  await page.goto(origin, { waitUntil: "networkidle" });
  await page.evaluate(async () => {
    await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    await navigator.serviceWorker.ready;
  });
  if (!await page.evaluate(() => navigator.serviceWorker.controller != null)) {
    await page.reload({ waitUntil: "networkidle" });
  }
  await expect.poll(() => page.evaluate(() => navigator.serviceWorker.controller?.scriptURL.endsWith("/sw.js") ?? false)).toBe(true);

  const result = await page.evaluate(async () => await (window as any).runFlowersecBrowserSmoke());
  expect(result).toEqual({
    controlled: true,
    httpStatus: 200,
    httpBody: "hello world",
    responseChunksSent: 4,
    errorStatus: 418,
    errorBody: "proxy denied",
    websocketMessage: "echo:ping",
    websocketCloseCode: 1000,
    websocketTextFrames: ["ping"],
  });
});

function browserPage(): string {
  return String.raw`<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Flowersec browser smoke</title></head>
  <body>
    <script type="module">
      const encoder = new TextEncoder();
      const decoder = new TextDecoder();
      let responseChunksSent = 0;

      navigator.serviceWorker.addEventListener("message", (event) => {
        const message = event.data;
        if (!message || message.type !== "flowersec-proxy:fetch") return;
        const port = event.ports[0];
        const denied = message.req.path === "/error";
        const chunks = (denied ? ["proxy ", "denied"] : ["hello ", "world"]).map((value) => encoder.encode(value));
        port.postMessage({
          type: "flowersec-proxy:response_meta",
          status: denied ? 418 : 200,
          headers: [{ name: "content-type", value: "text/plain; charset=utf-8" }],
        });
        let index = 0;
        port.onmessage = (creditEvent) => {
          if (creditEvent.data?.type !== "flowersec-proxy:response_credit") return;
          if (index < chunks.length) {
            const chunk = chunks[index++];
            responseChunksSent += 1;
            port.postMessage({ type: "flowersec-proxy:response_chunk", data: chunk.buffer }, [chunk.buffer]);
          } else {
            port.postMessage({ type: "flowersec-proxy:response_end" });
            port.close();
          }
        };
        port.start();
      });

      async function registerRuntime() {
        const controller = navigator.serviceWorker.controller;
        if (!controller) throw new Error("Service Worker is not controlling the page");
        const channel = new MessageChannel();
        const acknowledged = new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error("runtime registration timed out")), 2000);
          channel.port1.onmessage = (event) => {
            clearTimeout(timer);
            event.data?.ok === true ? resolve(undefined) : reject(new Error("runtime registration rejected"));
          };
        });
        controller.postMessage({ type: "flowersec-proxy:register-runtime", token: "browser-smoke" }, [channel.port2]);
        await acknowledged;
      }

      function frameBytes(op, payload) {
        const out = new Uint8Array(5 + payload.length);
        out[0] = op;
        new DataView(out.buffer).setUint32(1, payload.length);
        out.set(payload, 5);
        return out;
      }

      function frame(op, text) {
        return frameBytes(op, encoder.encode(text));
      }

      class BrowserSmokeStream {
        chunks = [];
        waiters = [];
        incoming = new Uint8Array();
        textFrames = [];

        push(chunk) {
          const waiter = this.waiters.shift();
          if (waiter) waiter(chunk); else this.chunks.push(chunk);
        }

        async read() {
          const chunk = this.chunks.shift();
          if (chunk) return chunk;
          return await new Promise((resolve) => this.waiters.push(resolve));
        }

        async write(chunk) {
          const joined = new Uint8Array(this.incoming.length + chunk.length);
          joined.set(this.incoming);
          joined.set(chunk, this.incoming.length);
          this.incoming = joined;
          while (this.incoming.length >= 5) {
            const length = new DataView(this.incoming.buffer, this.incoming.byteOffset, this.incoming.byteLength).getUint32(1);
            if (this.incoming.length < 5 + length) return;
            const op = this.incoming[0];
            const payload = this.incoming.slice(5, 5 + length);
            this.incoming = this.incoming.slice(5 + length);
            if (op === 1) {
              const text = decoder.decode(payload);
              this.textFrames.push(text);
              this.push(frame(1, "echo:" + text));
            } else if (op === 8) {
              this.push(frameBytes(8, new Uint8Array([3, 232])));
            }
          }
        }

        async close() {}
        reset() { this.push(null); }
      }

      window.runFlowersecBrowserSmoke = async () => {
        await registerRuntime();

        const response = await fetch("/proxy/hello");
        const reader = response.body.getReader();
        const received = [];
        while (true) {
          const next = await reader.read();
          if (next.done) break;
          received.push(next.value);
        }
        const httpBody = received.map((chunk) => decoder.decode(chunk, { stream: true })).join("") + decoder.decode();

        const errorResponse = await fetch("/proxy/error");
        const errorBody = await errorResponse.text();

        const { installWebSocketPatch } = await import("/dist/proxy/wsPatch.js");
        const stream = new BrowserSmokeStream();
        const patch = installWebSocketPatch({
          runtime: {
            limits: { maxWsFrameBytes: 1024, maxWsBufferedAmountBytes: 1024 },
            openWebSocketStream: async () => ({ stream, protocol: "browser-smoke" }),
          },
        });
        const socket = new WebSocket(location.origin.replace("http", "ws") + "/socket", ["browser-smoke"]);
        const websocketMessage = await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error("WebSocket smoke timed out")), 2000);
          socket.onerror = (event) => {
            clearTimeout(timer);
            reject(new Error(event.message || "WebSocket smoke failed"));
          };
          socket.onopen = () => socket.send("ping");
          socket.onmessage = (event) => {
            clearTimeout(timer);
            resolve(event.data);
          };
        });
        const websocketCloseCode = await new Promise((resolve) => {
          socket.onclose = (event) => resolve(event.code);
          socket.close(1000, "done");
        });
        patch.uninstall();

        return {
          controlled: navigator.serviceWorker.controller != null,
          httpStatus: response.status,
          httpBody,
          responseChunksSent,
          errorStatus: errorResponse.status,
          errorBody,
          websocketMessage,
          websocketCloseCode,
          websocketTextFrames: stream.textFrames,
        };
      };
    </script>
  </body>
</html>`;
}
