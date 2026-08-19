import {
  authorizeRuntime,
  createAcceptor,
  createEndpointSet,
  Issuer,
  parseArtifact,
  ProxyServer,
  SessionHandlers,
  type AuthorizationRecord,
} from "../node/v2.js";

const ORIGIN = "https://app.example";
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== "--upstream" || args[1] === undefined) {
  throw new Error("usage: proxyServerPeer --upstream http://127.0.0.1:<port>");
}

void run(args[1]).catch((error: unknown) => {
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
    onError: (error) => console.error(error instanceof Error ? error.message : String(error)),
  });
  const handlers = new SessionHandlers({ maxConcurrentStreams: 4 });
  proxy.register(handlers);

  let record: AuthorizationRecord | undefined;
  const acceptor = await createAcceptor({
    listeners: [{
      carrier: "websocket",
      path: "direct",
      host: "127.0.0.1",
      port: 0,
      allowedOrigins: [ORIGIN],
    }],
    maxInboundStreams: 8,
    authorize: async (request) => {
      if (record === undefined) throw new Error("authorization record is unavailable");
      const artifact = parseArtifact(record.artifactJSON);
      authorizeRuntime(request, record, "proxy-matrix-node");
      return { decision: "allow", artifact };
    },
    resolveHandlers: () => handlers,
  });

  try {
    const address = acceptor.addresses()[0];
    if (address === undefined) throw new Error("Node ProxyServer listener did not bind");
    const issued = new Issuer().issueDirect({
      session: { channelId: "browser-proxy-node", maxInboundStreams: 8 },
      endpoints: createEndpointSet(`ws://127.0.0.1:${address.port}/flowersec/v2/direct`),
      rendezvousGroupId: "browser-proxy-node",
      listenerAudience: "browser-proxy-matrix",
      upstreamAddress: `${address.host}:${address.port}`,
    });
    record = issued.authorizationRecord();
    const acceptedPromise = acceptor.accept();
    process.stdout.write(`${JSON.stringify({
      runtime: "node-typescript",
      artifact_json: new TextDecoder().decode(issued.artifactJSON()),
      origin: ORIGIN,
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
