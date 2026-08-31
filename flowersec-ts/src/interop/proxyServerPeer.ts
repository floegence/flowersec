import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  createAcceptor,
  parseArtifact,
  ProxyServer,
  SessionHandlers,
} from "../node/index.js";
import { testCertificatePEM, testPrivateKeyPEM } from "../testSupport/tlsFixture.js";

const ORIGIN = "https://app.example";
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== "--upstream" || args[1] === undefined) {
  throw new Error("usage: proxyServerPeer --upstream http://127.0.0.1:<port>");
}

await run(args[1]).catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});

async function run(upstream: string): Promise<void> {
  const parsedUpstream = new URL(upstream);
  if (parsedUpstream.protocol !== "http:" || parsedUpstream.hostname !== "127.0.0.1" || parsedUpstream.pathname !== "/") {
    throw new Error("proxy peer upstream must be a loopback HTTP origin");
  }

  const proxy = new ProxyServer({
    upstream,
    upstreamOrigin: upstream,
    allowedOrigins: [ORIGIN],
    maxConcurrentStreams: 4,
    maxJsonFrameBytes: 4096,
    maxChunkBytes: 8,
    maxBodyBytes: 8,
    maxWebSocketFrameBytes: 32,
    defaultHTTPRequestTimeoutMs: 1_000,
    maxHTTPRequestTimeoutMs: 1_000,
    extraRequestHeaders: ["cookie", "origin", "x-request-id"],
    extraResponseHeaders: ["x-visible"],
    blockedResponseHeaders: ["location"],
    extraWebSocketHeaders: ["x-request-id"],
    forbiddenCookieNames: ["secret"],
    forbiddenCookieNamePrefixes: ["private_"],
    onError: (error: unknown) => console.error(error instanceof Error ? error.message : String(error)),
  });
  const handlers = new SessionHandlers({ maxConcurrentStreams: 4 });
  proxy.register(handlers);

  let trustedArtifact: ReturnType<typeof parseArtifact> | undefined;
  const acceptor = await createAcceptor({
    listeners: [{
      carrier: "websocket",
      path: "direct",
      host: "127.0.0.1",
      port: 0,
      allowedOrigins: [ORIGIN],
      tls: { certificate: testCertificatePEM, privateKey: testPrivateKeyPEM },
    }],
    maxInboundStreams: 16,
    authorize: async () => trustedArtifact === undefined
      ? { accepted: false, retryable: false, reason: "invalid_credential" }
      : { accepted: true, artifact: trustedArtifact },
    resolveHandlers: () => handlers,
  });

  try {
    const address = acceptor.addresses()[0];
    if (address === undefined) throw new Error("Node ProxyServer listener did not bind");
    const artifactJSON = await issueArtifact(
      `wss://localhost:${address.port}/flowersec/v3/direct`,
    );
    trustedArtifact = parseArtifact(artifactJSON);
    const acceptedPromise = acceptor.accept();
    process.stdout.write(`${JSON.stringify({
      runtime: "node-typescript",
      artifact_json: artifactJSON,
      origin: ORIGIN,
      trust_pem: testCertificatePEM,
    })}\n`);

    const accepted = await acceptedPromise;
    const serving = accepted.serve().catch((error: unknown) => error);
    await accepted.session.waitTermination().catch(() => undefined);
    await serving;
  } finally {
    await proxy.close();
    await acceptor.close();
  }
}

async function issueArtifact(endpoint: string): Promise<string> {
  const child = spawn("go", ["run", "./internal/cmd/parity-artifact-issuer"], {
    cwd: fileURLToPath(new URL("../../../flowersec-go", import.meta.url)),
    env: { ...process.env, FLOWERSEC_SERVER_PARITY_PEER: "1" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  child.stdin.end(`${JSON.stringify({ mode: "direct", endpoint })}\n`);
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const code = await new Promise<number | null>((resolve) => child.once("exit", resolve));
  if (code !== 0) throw new Error(`proxy artifact issuer failed: ${Buffer.concat(stderr).toString("utf8")}`);
  const response = JSON.parse(Buffer.concat(stdout).toString("utf8")) as { artifact_json?: string };
  if (response.artifact_json === undefined) throw new Error("proxy artifact issuer omitted artifact");
  return response.artifact_json;
}
