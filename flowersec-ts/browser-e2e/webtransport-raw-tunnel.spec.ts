import { expect, test } from "@playwright/test";
import { execFile, spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { promisify } from "node:util";

import { startBrowserModuleSite } from "./browser-module-site.js";

test("Chromium runs a WebTransport to raw QUIC tunnel through the Go relay", async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  const binary = testInfo.outputPath(process.platform === "win32" ? "tunnel-peer.exe" : "tunnel-peer");
  await promisify(execFile)("go", ["build", "-o", binary, "./internal/cmd/browser-webtransport-peer"], {
    cwd: new URL("../../flowersec-go/", import.meta.url), timeout: 75_000,
  });
  const site = await startBrowserModuleSite();
  const peer = spawn(binary, ["--raw-quic-tunnel", "--origin", site.origin], { stdio: ["ignore", "pipe", "pipe"] });
  const stderr: string[] = [];
  peer.stderr.setEncoding("utf8").on("data", (chunk: string) => stderr.push(chunk));
  peer.on("error", (error) => stderr.push(error.message));
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    peer.once("close", (code, signal) => resolve({ code, signal }));
  });
  const lines = createInterface({ input: peer.stdout })[Symbol.asyncIterator]();
  try {
    await page.goto(site.origin);
    const ready = await lines.next();
    expect(ready.done, stderr.join("")).toBeFalsy();
    const { artifact_json, certificate_hash } = JSON.parse(ready.value) as { artifact_json: string; certificate_hash: string };
    const wire = JSON.parse(artifact_json) as { path: { kind: string; candidates: Array<{ id: string; url: string; carrier: string; tls: unknown }> } };
    expect(wire.path.kind).toBe("tunnel");
    expect(wire.path.candidates).toHaveLength(2);
    const browser = wire.path.candidates.find((candidate) => candidate.id === "browser-leg");
    expect(certificate_hash).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(browser).toMatchObject({ carrier: "webtransport", tls: { mode: "pin", pins: [{ value_b64u: certificate_hash }] } });
    expect(wire.path.candidates.find((candidate) => candidate.id === "server-leg")).toMatchObject({ carrier: "raw_quic" });

    const result = await page.evaluate(async ({ artifact, ingress, topology }) => {
      const sdk = await import("/dist/browser/index.js");
      let spends = 0;
      const session = await sdk.connect(sdk.createArtifactLease(sdk.parseArtifact(artifact), async () => { spends++; }), { tunnelIngressURL: ingress });
      try {
        const stream = await session.openStream("accept.bridge", { metadata: sdk.createStreamMetadata({ topology }) });
        const request = new TextEncoder().encode(`request:${topology}`);
        if (await stream.write(request) !== request.length) throw new Error("short tunnel request write");
        await stream.closeWrite();
        const expected = new TextEncoder().encode(`reply:${topology}`);
        let offset = 0;
        for (;;) {
          const chunk: Uint8Array | null = await stream.read();
          if (chunk === null) break;
          for (const byte of chunk) {
            if (byte !== expected[offset++]) throw new Error("unexpected tunnel reply bytes");
          }
        }
        return { spends, replyBytes: offset };
      } finally {
        await session.close();
      }
    }, { artifact: artifact_json, ingress: browser!.url, topology: "browser_tunnel_wt_quic" });
    expect(result).toEqual({ spends: 1, replyBytes: Buffer.byteLength("reply:browser_tunnel_wt_quic") });
    const termination = await exited;
    expect(termination, stderr.join("")).toEqual({ code: 0, signal: null });
  } finally {
    if (peer.exitCode === null && peer.signalCode === null) peer.kill("SIGKILL");
    await exited;
    await site.close();
  }
});
