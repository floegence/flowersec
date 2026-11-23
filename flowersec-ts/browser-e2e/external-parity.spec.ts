import { expect, test } from "@playwright/test";

import { startBrowserModuleSite } from "./browser-module-site.js";

test("Chromium runs the WebSocket client profile", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "requires Chromium");
  const encoded = process.env.FLOWERSEC_PARITY_READY_BASE64;
  if (encoded === undefined) {
    throw new Error("FLOWERSEC_PARITY_READY_BASE64 is required for the external browser parity test");
  }
  test.setTimeout(60_000);
  const ready = JSON.parse(Buffer.from(encoded, "base64").toString("utf8")) as {
    artifact_json: string; trust_pem: string; origin: string; path: "direct" | "tunnel";
  };
  const site = await startBrowserModuleSite(Number(process.env.FLOWERSEC_BROWSER_SITE_PORT));
  try {
    await page.goto(site.origin, { waitUntil: "networkidle" });
    const result = await page.evaluate(async ({ artifactJSON, path }) => {
      const sdk = await import("/dist/browser/index.js");
      const session = await sdk.connect(
        sdk.createArtifactLease(sdk.parseArtifact(artifactJSON), async () => undefined),
      );
      const echo = await session.rpc.call(7001, { value: "ping" }, (payload) => payload);
      if (!echo.ok || echo.payload.value !== "ping") throw new Error("RPC echo failed");
      await session.rpc.notify(7002, { value: "notify" });
      const stream = await session.openStream("parity.echo", { metadata: sdk.createStreamMetadata({ cell: path }) });
      await stream.write(new TextEncoder().encode("hello"));
      await stream.closeWrite();
      if (new TextDecoder().decode(await stream.read()) !== "world") throw new Error("stream FIN failed");
      if (await stream.read() !== null) throw new Error("stream FIN did not reach EOF");
      const streamCleanup = await session.rpc.call(7001, { value: "ping" }, (payload) => payload);
      if (!streamCleanup.ok || streamCleanup.payload.value !== "ping") throw new Error("stream cleanup barrier failed");
      const reset = await session.openStream("parity.reset");
      await reset.write(new TextEncoder().encode("reset"));
      await reset.closeWrite();
      let resetObserved = false;
      try { await reset.read(); } catch { resetObserved = true; }
      finally { await reset.close().catch(() => undefined); }
      if (!resetObserved) throw new Error("stream reset failed");
      const resetCleanup = await session.rpc.call(7001, { value: "ping" }, (payload) => payload);
      if (!resetCleanup.ok || resetCleanup.payload.value !== "ping") throw new Error("reset cleanup barrier failed");
      await session.rekey();
      await session.probeLiveness();
      const completion = await session.rpc.call(7003, { value: "complete" }, (payload) => payload);
      if (!completion.ok || completion.payload.value !== "complete") throw new Error("completion barrier failed");
      await session.close();
      return true;
    }, { artifactJSON: ready.artifact_json, path: ready.path });
    expect(result).toBe(true);
  } finally {
    await site.close();
  }
});
