import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "@playwright/test";

import { createBrowserRunnerHost } from "../scripts/browser-runner-installation.mjs";
import { startBrowserModuleSite, type BrowserModuleSite } from "./browser-module-site.js";

test("Chromium runs the current WebSocket client profile", async ({ page, browser, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium");
  test.setTimeout(60_000);
  const encoded = process.env.FLOWERSEC_PARITY_READY_BASE64;
  const manifestPath = process.env.FLOWERSEC_BROWSER_INSTALLATION_MANIFEST;
  const historyDirectory = process.env.FLOWERSEC_BROWSER_HISTORY_DIRECTORY;
  if (encoded === undefined || manifestPath === undefined || historyDirectory === undefined) throw new Error("original parity ready material, host installation and history paths are required");
  const ready = JSON.parse(Buffer.from(encoded, "base64").toString("utf8")) as {
    wire_revision: number; source: string; carrier: string; artifact_json: string; trust_pem: string; origin: string; path: "direct" | "tunnel";
  };
  if (ready.wire_revision !== 4 || ready.source !== "preauthorized_pool" || ready.carrier !== "websocket" || (ready.path !== "direct" && ready.path !== "tunnel")) throw new Error("unsupported current browser parity deployment");
  const portText = process.env.FLOWERSEC_BROWSER_SITE_PORT;
  const host = await createBrowserRunnerHost(manifestPath, historyDirectory);
  let site: BrowserModuleSite | undefined;
  try {
    site = await startBrowserModuleSite({ ...(portText === undefined ? {} : { port: Number(portText) }), host });
    if (ready.origin !== site.origin) throw new Error("original peer origin differs from actual browser module origin");
    host.setOrigin(site.origin);
    await page.goto(site.origin, { waitUntil: "networkidle" });
    await host.publishRuntime({ engine: browserName, version: browser.version(), userAgent: await page.evaluate(() => navigator.userAgent) });
    const runtime = JSON.parse(await readFile(join(historyDirectory, "browser-runtime.json"), "utf8")) as { runtime_id: string };
    const materialHash = createHash("sha256").update(ready.artifact_json).digest("hex");
    // The independently authorized deployment owner installs policy only after
    // observing this actual browser runtime. This test never creates that policy.
    await expect.poll(async () => {
      try {
        const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as { installations?: Record<string, { runtime_id?: string }> };
        return manifest.installations?.[materialHash]?.runtime_id;
      } catch { return undefined; }
    }, { timeout: 15_000 }).toBe(runtime.runtime_id);
    const installation = await host.install(ready.artifact_json);
    if (installation.application_schema !== "parity" || installation.carrier !== "wss") throw new Error("original parity application installation is missing");
    const result = await page.evaluate(async ({ installation, artifactJSON, path }) => {
      const sdk = await import("/dist/browser/index.js");
      const current = await import("/dist/interop/browserRunner.js");
      const owner = await current.installBrowserRunner(installation, artifactJSON);
      const signal = AbortSignal.timeout(30_000);
      let service: Awaited<ReturnType<typeof owner.bindEcho>> | undefined;
      let stream: Awaited<ReturnType<Awaited<ReturnType<typeof owner.connect>>["openStream"]>> | undefined;
      let reset: typeof stream;
      try {
        const session = await owner.connect(signal);
        if (await owner.spendCount() !== 1) throw new Error("original parity material was not committed once");
        service = await owner.bindEcho(signal);
        const codec = new TextEncoder(), decoder = new TextDecoder("utf-8", { fatal: true });
        const call = async (method: typeof owner.method, value: string) => {
          const response = await service!.call(method, codec.encode(JSON.stringify({ value })), { signal, responseLimitBytes: 4096, timeoutMS: 10000n });
          if (response.kind !== "value" || response.encoding !== "typed") throw new Error("parity RPC did not return a typed value");
          try {
            const payload = JSON.parse(decoder.decode(response.value));
            if (payload?.value !== value) throw new Error("parity RPC value differs");
          } finally { response.release(); }
        };
        const write = async (target: NonNullable<typeof stream>, value: Uint8Array) => {
          const progress = await target.write(value, { signal });
          if (progress.phase !== "terminal" || progress.terminal_reason !== "complete" || progress.accepted_bytes !== BigInt(value.length)) throw new Error("parity Stream write failed");
        };
        if (owner.notificationMethod === undefined || owner.completionMethod === undefined || owner.datagramBarrierMethod === undefined) throw new Error("original parity methods are missing");
        await call(owner.method, "ping");
        const notification = await service.notify(owner.notificationMethod, codec.encode(JSON.stringify({ value: "notify" })), { signal, timeoutMS: 10000n });
        if (notification.submission !== "submitted") throw new Error("parity notification was not submitted");
        stream = await session.openStream("parity.echo", { signal, metadata: sdk.createStreamMetadata({ cell: path }) });
        await write(stream, codec.encode("hello"));
        await stream.closeWrite({ signal });
        const received = new Uint8Array(16);
        let length = 0;
        for (;;) {
          const response = await stream.read(16n, { signal });
          if (response.wait_status !== "ready" || response.stream_status === "aborted" || response.stream_status === "error" || response.length > received.length - length) throw new Error("parity echo stream failed");
          received.set(response.data, length); length += response.length;
          if (response.stream_status === "eof") break;
          if (response.length === 0) throw new Error("empty open parity Stream read");
        }
        if (decoder.decode(received.subarray(0, length)) !== "world") throw new Error("parity stream response differs");
        const finished = await stream.finish({ signal });
        if (!finished.send_drained) throw new Error("parity stream FIN did not drain");
        await stream.close({ signal }); stream = undefined;
        await call(owner.method, "ping");
        reset = await session.openStream("parity.reset", { signal });
        await write(reset, codec.encode("reset"));
        await reset.closeWrite({ signal });
        const resetRead = await reset.read(16n, { signal });
        if (resetRead.wait_status !== "ready" || resetRead.stream_status !== "aborted") throw new Error("parity reset did not report its authenticated failure");
        await reset.close({ signal }); reset = undefined;
        await call(owner.method, "ping");
        await call(owner.datagramBarrierMethod, "datagram-ready");
        await owner.waitNotification(signal);
        await session.rekey({ signal });
        await session.probeLiveness({ signal });
        await call(owner.completionMethod, "complete");
        const finalNotification = await service.notify(owner.notificationMethod, codec.encode(JSON.stringify({ value: "notify" })), { signal, timeoutMS: 10000n });
        if (finalNotification.submission !== "submitted") throw new Error("post-rekey parity notification was not submitted");
        await call(owner.method, "notifications-observed");
        const drained = await session.drain({ timeoutMS: 5000n }).wait({ signal });
        if (drained.outcome !== "drained") throw new Error("current browser parity communication did not drain");
        await session.waitTermination({ signal });
        const spendCount = await owner.spendCount();
        service.close(); service = undefined;
        await session.close();
        if ((await session.waitCleanup()).status !== "complete") throw new Error("original parity Session cleanup incomplete");
        return { success: true, spendCount };
      } finally {
        service?.close();
        await stream?.close();
        await reset?.close();
        await owner.close();
      }
    }, { installation, artifactJSON: ready.artifact_json, path: ready.path });
    expect(result).toEqual({ success: true, spendCount: 1 });
  } finally {
    await site?.close();
    await host.close();
  }
});
