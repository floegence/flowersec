import { expect, test } from "@playwright/test";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let server: http.Server;
let origin: string;
let appServer: http.Server;
let appOrigin: string;

test.beforeAll(async () => {
  appServer = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname.startsWith("/dist/")) {
      const file = path.resolve(packageRoot, url.pathname.slice(1));
      if (!file.startsWith(path.join(packageRoot, "dist") + path.sep) || !fs.existsSync(file)) {
        response.writeHead(404).end();
        return;
      }
      response.writeHead(200, { "content-type": "text/javascript; charset=utf-8" });
      response.end(fs.readFileSync(file));
      return;
    }
    if (url.pathname === "/cross-origin-frame.html") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(crossOriginFramePage());
      return;
    }
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("not found");
  });
  await listen(appServer);
  appOrigin = serverOrigin(appServer, "cross-origin Window bridge server");

  server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (url.pathname.startsWith("/dist/")) {
      const file = path.resolve(packageRoot, url.pathname.slice(1));
      if (!file.startsWith(path.join(packageRoot, "dist") + path.sep) || !fs.existsSync(file)) {
        response.writeHead(404).end();
        return;
      }
      response.writeHead(200, { "content-type": "text/javascript; charset=utf-8" });
      response.end(fs.readFileSync(file));
      return;
    }
    if (url.pathname === "/frame.html") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(framePage());
      return;
    }
    if (url.pathname === "/") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(parentPage());
      return;
    }
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("not found");
  });
  await listen(server);
  origin = serverOrigin(server, "Window bridge server");
});

test.afterAll(async () => {
  await Promise.all([close(server), close(appServer)]);
});

test.beforeEach(async ({ page }) => {
  await page.goto(origin, { waitUntil: "networkidle" });
  await expect.poll(() => page.evaluate(() => (window as any).windowBridgeReady === true)).toBe(true);
});

test("real iframe bridge applies backpressure and controller dispose clears the pending acknowledgement", async ({ page }) => {
  const result = await page.evaluate(async () => await (window as any).runSlowConsumerAndControllerDispose());

  expect(result).toEqual({
    readCallsBeforeConsumption: 1,
    readCallsWhileSlow: 1,
    firstChunk: [1, 2, 3],
    readCallsAfterConsumption: 2,
    secondRead: {
      ok: false,
      message: "proxy controller Window bridge is disposed",
    },
    resetReasons: ["proxy controller Window bridge is disposed"],
  });
});

test("real iframe app rejects a controller without the v2 acknowledgement capability", async ({ page }) => {
  const result = await page.evaluate(async () => await (window as any).runCapabilityMismatch());

  expect(result).toEqual({
    ok: false,
    message: "proxy Window bridge does not support bidirectional stream acknowledgements",
  });
});

test("real iframe app dispose rejects a pending write and resets the controller stream once", async ({ page }) => {
  const result = await page.evaluate(async () => await (window as any).runAppDisposeDuringWrite());

  expect(result).toEqual({
    writes: [[9, 8, 7]],
    writeResult: {
      ok: false,
      message: "proxy app Window bridge is disposed",
    },
    resetReasons: ["proxy app Window bridge is disposed"],
  });
});

test("real iframe app dispose aborts a pending controller open", async ({ page }) => {
  const result = await page.evaluate(async () => await (window as any).runAppDisposeDuringPendingOpen());

  expect(result).toEqual({
    signalAborted: true,
    openResult: {
      ok: false,
      message: "proxy app Window bridge is disposed",
    },
    resetReasons: ["proxy app Window bridge is disposed"],
  });
});

test("cross-origin iframe negotiates the v2 bridge without same-origin access", async ({ page }) => {
  const result = await page.evaluate(async () => await (window as any).runCrossOriginBridge());

  expect(result).toEqual({
    ok: true,
    protocol: "cross-origin-e2e",
    resetReasons: ["proxy app Window bridge is disposed"],
  });
});

function parentPage(): string {
  return String.raw`<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Flowersec Window bridge E2E</title></head>
  <body>
    <main>Flowersec Window bridge E2E</main>
    <button type="button" data-testid="run-mismatch">Run mismatch check</button>
    <pre data-testid="result">Ready</pre>
    <iframe id="app-frame" src="/frame.html" title="Flowersec app bridge"></iframe>
    <iframe
      id="cross-origin-app-frame"
      src="${appOrigin}/cross-origin-frame.html?controllerOrigin=${encodeURIComponent(origin)}"
      title="Flowersec cross-origin app bridge"
      onload="this.dataset.loaded='true'"
    ></iframe>
    <script type="module">
      import { registerProxyControllerWindow } from "/dist/proxy/controllerWindow.js";

      const frame = document.querySelector("#app-frame");
      const crossOriginFrame = document.querySelector("#cross-origin-app-frame");
      await new Promise((resolve) => {
        if (frame.contentDocument?.readyState === "complete") resolve();
        else frame.addEventListener("load", resolve, { once: true });
      });
      await new Promise((resolve) => {
        if (crossOriginFrame.dataset.loaded === "true") resolve();
        else crossOriginFrame.addEventListener("load", resolve, { once: true });
      });
      const crossOriginAppOrigin = new URL(crossOriginFrame.src).origin;

      const waitFor = async (condition) => {
        for (let index = 0; index < 100; index++) {
          if (condition()) return;
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
        throw new Error("timed out waiting for Window bridge state");
      };

      const createRuntime = ({ chunks = [], blockWrites = false, blockOpen = false, protocol = "e2e" } = {}) => {
        const state = {
          readCalls: 0,
          writes: [],
          resetReasons: [],
          openSignal: null,
          resolveOpen: null,
        };
        let rejectPendingRead = null;
        let rejectPendingWrite = null;
        const stream = {
          async read() {
            state.readCalls += 1;
            const chunk = chunks.shift();
            if (chunk != null) return new Uint8Array(chunk);
            return await new Promise((_resolve, reject) => { rejectPendingRead = reject; });
          },
          async write(chunk) {
            state.writes.push(Array.from(chunk));
            if (!blockWrites) return;
            return await new Promise((_resolve, reject) => { rejectPendingWrite = reject; });
          },
          async close() {},
          reset(error) {
            state.resetReasons.push(error.message);
            rejectPendingRead?.(error);
            rejectPendingRead = null;
            rejectPendingWrite?.(error);
            rejectPendingWrite = null;
          },
        };
        const opened = { stream, protocol };
        return {
          state,
          runtime: {
            limits: { maxWsBufferedAmountBytes: 1024 },
            dispatchFetch() { throw new Error("fetch is not used in this E2E"); },
            async openWebSocketStream(_path, options = {}) {
              state.openSignal = options.signal ?? null;
              if (!blockOpen) return opened;
              return await new Promise((resolve) => {
                state.resolveOpen = () => resolve(opened);
              });
            },
            dispose() {},
          },
        };
      };

      const registerController = (runtime) => registerProxyControllerWindow({
        runtime,
        allowedOrigins: [location.origin],
        expectedSource: frame.contentWindow,
        targetWindow: window,
      });

      window.runSlowConsumerAndControllerDispose = async () => {
        const { runtime, state } = createRuntime({ chunks: [[1, 2, 3], [4, 5, 6]] });
        const controller = registerController(runtime);
        await frame.contentWindow.startBridge("/slow-consumer");
        await waitFor(() => state.readCalls === 1);
        const readCallsBeforeConsumption = state.readCalls;
        await new Promise((resolve) => setTimeout(resolve, 50));
        const readCallsWhileSlow = state.readCalls;
        const firstChunk = await frame.contentWindow.readNext();
        await waitFor(() => state.readCalls === 2);
        const readCallsAfterConsumption = state.readCalls;

        controller.dispose();
        controller.dispose();
        await new Promise((resolve) => setTimeout(resolve, 10));
        const secondRead = await frame.contentWindow.readNextResult();
        frame.contentWindow.disposeBridge();
        frame.contentWindow.disposeBridge();
        return {
          readCallsBeforeConsumption,
          readCallsWhileSlow,
          firstChunk,
          readCallsAfterConsumption,
          secondRead,
          resetReasons: state.resetReasons,
        };
      };

      window.runCapabilityMismatch = async () => {
        const onMessage = (event) => {
          if (event.source !== frame.contentWindow || event.origin !== location.origin) return;
          if (event.data?.type !== "flowersec-proxy:ws_open") return;
          const port = event.ports[0];
          port.postMessage({
            type: "flowersec-proxy:ws_open_ack",
            protocol: "legacy",
            capabilities: [],
          });
        };
        window.addEventListener("message", onMessage);
        try {
          return await frame.contentWindow.startBridgeResult("/mismatch");
        } finally {
          window.removeEventListener("message", onMessage);
          frame.contentWindow.disposeBridge();
        }
      };

      window.runAppDisposeDuringWrite = async () => {
        const { runtime, state } = createRuntime({ blockWrites: true });
        const controller = registerController(runtime);
        await frame.contentWindow.startBridge("/pending-write");
        frame.contentWindow.startWrite([9, 8, 7]);
        await waitFor(() => state.writes.length === 1);
        frame.contentWindow.disposeBridge();
        frame.contentWindow.disposeBridge();
        const writeResult = await frame.contentWindow.writeResult();
        await waitFor(() => state.resetReasons.length === 1);
        controller.dispose();
        controller.dispose();
        return {
          writes: state.writes,
          writeResult,
          resetReasons: state.resetReasons,
        };
      };

      window.runAppDisposeDuringPendingOpen = async () => {
        const { runtime, state } = createRuntime({ blockOpen: true });
        const controller = registerController(runtime);
        const opening = frame.contentWindow.startBridgeResult("/pending-open");
        await waitFor(() => state.openSignal != null && state.resolveOpen != null);
        frame.contentWindow.disposeBridge();
        frame.contentWindow.disposeBridge();
        await waitFor(() => state.openSignal.aborted === true);
        const signalAborted = state.openSignal.aborted;
        state.resolveOpen();
        const openResult = await opening;
        await waitFor(() => state.resetReasons.length === 1);
        controller.dispose();
        controller.dispose();
        return {
          signalAborted,
          openResult,
          resetReasons: state.resetReasons,
        };
      };

      window.runCrossOriginBridge = async () => {
        const { runtime, state } = createRuntime({ protocol: "cross-origin-e2e" });
        const controller = registerProxyControllerWindow({
          runtime,
          allowedOrigins: [crossOriginAppOrigin],
          expectedSource: crossOriginFrame.contentWindow,
          targetWindow: window,
        });
        const requestId = crypto.randomUUID();
        const result = await new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            cleanup();
            reject(new Error("timed out waiting for cross-origin Window bridge"));
          }, 5000);
          const cleanup = () => {
            clearTimeout(timer);
            window.removeEventListener("message", onMessage);
          };
          const onMessage = (event) => {
            if (event.origin !== crossOriginAppOrigin || event.source !== crossOriginFrame.contentWindow) return;
            if (event.data?.type !== "flowersec-e2e:cross-origin-result" || event.data?.requestId !== requestId) return;
            cleanup();
            resolve(event.data.result);
          };
          window.addEventListener("message", onMessage);
          crossOriginFrame.contentWindow.postMessage({
            type: "flowersec-e2e:cross-origin-open",
            requestId,
          }, crossOriginAppOrigin);
        });
        await waitFor(() => state.resetReasons.length === 1);
        controller.dispose();
        return { ...result, resetReasons: state.resetReasons };
      };

      document.querySelector('[data-testid="run-mismatch"]').addEventListener("click", async () => {
        const result = await window.runCapabilityMismatch();
        document.querySelector('[data-testid="result"]').textContent = JSON.stringify(result);
      });

      window.windowBridgeReady = true;
    </script>
  </body>
</html>`;
}

function framePage(): string {
  return String.raw`<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Flowersec app bridge frame</title></head>
  <body>
    <main>Flowersec app bridge frame</main>
    <script type="module">
      import { registerProxyAppWindow } from "/dist/proxy/appWindow.js";

      let handle = null;
      let stream = null;
      let pendingWrite = null;

      window.startBridge = async (path) => {
        handle = registerProxyAppWindow({
          controllerOrigin: location.origin,
          controllerWindow: parent,
          targetWindow: window,
          maxWsBufferedAmountBytes: 1024,
        });
        const opened = await handle.runtime.openWebSocketStream(path, { protocols: ["e2e"] });
        stream = opened.stream;
        return opened.protocol;
      };

      window.startBridgeResult = async (path) => {
        try {
          await window.startBridge(path);
          return { ok: true, message: "" };
        } catch (error) {
          return { ok: false, message: error instanceof Error ? error.message : String(error) };
        }
      };

      window.readNext = async () => Array.from(await stream.read());
      window.readNextResult = async () => {
        try {
          return { ok: true, value: Array.from(await stream.read()) };
        } catch (error) {
          return { ok: false, message: error instanceof Error ? error.message : String(error) };
        }
      };

      window.startWrite = (bytes) => {
        pendingWrite = stream.write(new Uint8Array(bytes)).then(
          () => ({ ok: true, message: "" }),
          (error) => ({ ok: false, message: error instanceof Error ? error.message : String(error) }),
        );
      };
      window.writeResult = async () => await pendingWrite;
      window.disposeBridge = () => handle?.dispose();
    </script>
  </body>
</html>`;
}

function crossOriginFramePage(): string {
  return String.raw`<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Flowersec cross-origin app bridge frame</title></head>
  <body>
    <main>Flowersec cross-origin app bridge frame</main>
    <script type="module">
      import { registerProxyAppWindow } from "/dist/proxy/appWindow.js";

      const controllerOrigin = new URL(location.href).searchParams.get("controllerOrigin");
      if (controllerOrigin == null || controllerOrigin === "") throw new Error("missing controller origin");

      window.addEventListener("message", async (event) => {
        if (event.origin !== controllerOrigin || event.source !== parent) return;
        if (event.data?.type !== "flowersec-e2e:cross-origin-open") return;
        let handle = null;
        let result;
        try {
          handle = registerProxyAppWindow({
            controllerOrigin,
            controllerWindow: parent,
            targetWindow: window,
            maxWsBufferedAmountBytes: 1024,
          });
          const opened = await handle.runtime.openWebSocketStream("/cross-origin", {
            protocols: ["cross-origin-e2e"],
          });
          result = { ok: true, protocol: opened.protocol };
        } catch (error) {
          result = { ok: false, message: error instanceof Error ? error.message : String(error) };
        }
        parent.postMessage({
          type: "flowersec-e2e:cross-origin-result",
          requestId: event.data.requestId,
          result,
        }, controllerOrigin);
        handle?.dispose();
      });
    </script>
  </body>
</html>`;
}

async function listen(target: http.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    target.once("error", reject);
    target.listen(0, "127.0.0.1", resolve);
  });
}

function serverOrigin(target: http.Server, name: string): string {
  const address = target.address();
  if (address == null || typeof address === "string") throw new Error(`${name} did not bind TCP`);
  return `http://127.0.0.1:${address.port}`;
}

async function close(target: http.Server | undefined): Promise<void> {
  if (target == null) return;
  await new Promise<void>((resolve, reject) => {
    target.close((error) => error == null ? resolve() : reject(error));
    target.closeAllConnections?.();
  });
}
