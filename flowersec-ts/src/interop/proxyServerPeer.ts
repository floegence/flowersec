import { ProxyServer } from "../node/index.js";
import { createCurrentPeerServer } from "./currentServer.js";

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
  const owner = await createCurrentPeerServer(environment => proxy.register(environment, { applicationBytes: 65536n, authorize: () => true }), ORIGIN);
  try {
    const acceptedPromise = owner.acceptor.accept();
    process.stdout.write(`${JSON.stringify({
      runtime: "node-typescript", artifact_json: owner.artifactJSON, origin: ORIGIN,
      trust_pem: owner.trustPEM, wire_revision: 4,
    })}\n`);
    const accepted = await acceptedPromise;
    await accepted.session.waitTermination();
  } finally { await proxy.close(); await owner.close(); }
}
