import { expect, test, type Page } from "@playwright/test";
import { execFileSync, spawn } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { once } from "node:events";
import { mkdirSync, readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { startBrowserModuleSite } from "./browser-module-site.js";
import { createAcceptor, parseArtifact } from "../src/node/index.js";
import { decodeArtifactV3JSON, encodeArtifactV3JSON } from "../src/v3/artifact.js";

test.skip(process.env.FLOWERSEC_BROWSER_DRAFT02 !== "1", "explicit native listener compatibility suite");

async function exercise(page: Page, origin: string, artifact: string) {
  await page.goto(origin);
  const result = await page.evaluate(async (json) => {
    const sdk = await import("/dist/browser/index.js");
    let spends = 0;
    const session = await sdk.connect(sdk.createArtifactLease(sdk.parseArtifact(json), async () => { spends++; }));
    try {
      const outcome = await session.unreliableMessages.send(new TextEncoder().encode("browser"), { expiresAtUnixMs: Date.now() + 5000 });
      const reply = await session.unreliableMessages.receive({ signal: AbortSignal.timeout(5000) });
      return { spends, outcome, reply: new TextDecoder().decode(reply) };
    } finally {
      await session.close();
    }
  }, artifact);
  expect(result).toEqual({ spends: 1, outcome: "accepted", reply: "browser" });
}

test("Chromium runs a Flowersec session to a Rust draft02 listener", async ({ page }) => {
  test.setTimeout(120_000);
  const site = await startBrowserModuleSite();
  const child = spawn("cargo", ["test", "--quiet", "--locked", "--lib", "browser_draft02_listener_peer", "--", "--ignored", "--nocapture"], {
    cwd: new URL("../../flowersec-rust/", import.meta.url), env: { ...process.env, FLOWERSEC_BROWSER_DRAFT02_ORIGIN: site.origin }, stdio: ["ignore", "pipe", "inherit"],
  });
  const exited = once(child, "close");
  try {
    let artifact: string | undefined;
    for await (const line of createInterface({ input: child.stdout })) {
      if (line.startsWith("{")) { artifact = line; break; }
    }
    expect(artifact, "Rust listener must publish one artifact").toBeDefined();
    await exercise(page, site.origin, artifact!);
    expect((await exited)[0]).toBe(0);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    try { await exited; } finally { await site.close(); }
  }
});

test("Chromium runs a Flowersec session to a Node draft02 listener", async ({ page }, testInfo) => {
  mkdirSync(testInfo.outputDir, { recursive: true });
  const key = testInfo.outputPath("key.pem");
  const cert = testInfo.outputPath("cert.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-sha256",
    "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", key, "-out", cert,
  ]);
  const certificate = readFileSync(cert, "utf8");
  const pin = createHash("sha256").update(new X509Certificate(certificate).raw).digest("base64url");
  const fixture = JSON.parse(readFileSync(new URL("../../testdata/transport_v5/artifact_vectors.json", import.meta.url), "utf8"));
  const base = decodeArtifactV3JSON(fixture.positive.find((item: { id: string }) => item.id === "direct-mixed-security").artifact_json);
  const site = await startBrowserModuleSite();
  let acceptor: Awaited<ReturnType<typeof createAcceptor>> | undefined;
  try {
    let artifact: string;
    const listener = await createAcceptor({
      listeners: [{
        carrier: "webtransport", path: "direct", allowedOrigins: [site.origin], host: "127.0.0.1", port: 0,
        tls: { certificate, privateKey: readFileSync(key, "utf8") },
      }],
      maxInboundStreams: base.session.max_inbound_streams,
      authorize: async () => ({ accepted: true, artifact: parseArtifact(artifact) }),
    });
    acceptor = listener;
    artifact = new TextDecoder().decode(encodeArtifactV3JSON({ ...base, path: { ...base.path, candidates: [{
      carrier: "webtransport", id: "wt", wire_profile: "flowersec-direct/5",
      url: `https://127.0.0.1:${listener.addresses()[0]!.port}/flowersec/webtransport/v5/direct`,
      tls: { mode: "pin", pins: [{ algorithm: "sha-256", value_b64u: pin, not_after_unix_s: Math.floor(Date.now() / 1000) + 600 }] },
    }] } }));
    const echo = async () => {
      const peer = await listener.accept({ signal: AbortSignal.timeout(10000) });
      const channel = peer.session.unreliableMessages!;
      const message = await channel.receive({ signal: AbortSignal.timeout(5000) });
      expect(new TextDecoder().decode(message)).toBe("browser");
      expect(await channel.send(message, { expiresAtUnixMs: Date.now() + 5000 })).toBe("accepted");
      await peer.session.waitTermination();
    };
    await Promise.all([exercise(page, site.origin, artifact), echo()]);
  } finally {
    try { await acceptor?.close(); } finally { await site.close(); }
  }
});
