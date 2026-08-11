import { createInterface } from "node:readline";

import {
  createAcceptor,
  createArtifactLease,
  createEndpointSet,
  createStreamMetadata,
  createTunnelRuntime,
  connect,
  Issuer,
  parseArtifact,
  SessionError,
  SessionHandlers,
  type ByteStream,
  type JsonValue,
  type Session,
  type TunnelAuthorizationDecision,
} from "../node/index.js";

const RUNTIME = "node-typescript";
const ORIGIN = "https://client.example";
const ECHO_RPC = 7001;
const NOTIFY_RPC = 7002;
const COMPLETE_RPC = 7003;
const DATAGRAM_READY_RPC = 7005;
const ECHO_KIND = "parity.echo";
const RESET_KIND = "parity.reset";
const ENDPOINT_CASES = [
  "rpc",
  "notification",
  "stream-metadata",
  "stream-fin",
  "stream-reset",
  "rekey",
  "liveness",
  "close",
  "cancel",
  "cleanup",
] as const;
const DIRECT_CASES = ["admission", ...ENDPOINT_CASES] as const;
const RELAY_CASES = [
  "admission",
  "pairing",
  "opaque-forwarding",
  "close",
  "cancel",
  "cleanup",
] as const;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const TEST_CERT_DER_B64 =
  "MIIBjzCCAUGgAwIBAgIUW8hQEpQsUJN9a6qqF2g6hsNpSm8wBQYDK2VwMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjA3MjAxOTAxMjFaFw0zNjA3MTcxOTAxMjFaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAqMAUGAytlcAMhAAihki/Jec+1EaC6E6PsSxjMYFAazrgkNiUIlbj/+A/0o4GkMIGhMB0GA1UdDgQWBBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAfBgNVHSMEGDAWgBQCuKxQmMQkAAy9KkfuD+WOmrrMbTAsBgNVHREEJTAjgglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EArZng3XitiH2E1pW/NTxQvEOBXJYpYE8coQmLV4yTjfI43CWHMG6lIrwk/so67oe6Z2R4iHGjUm3Tuy50Fl8hBw==";
const TEST_KEY_DER_B64 =
  "MC4CAQAwBQYDK2VwBCIEICxYUWHqGoh0CBBohsaNg/NThm1n3UeWCzYuq6jS+Qi6";

type Role =
  "server" | "client" | "relay" | "tunnel-endpoint-a" | "tunnel-endpoint-b";

type TLSFixture = Readonly<{
  tls: Readonly<{
    certificate_chain_pem: string;
    private_key_pem: string;
    root_certificate_pem: string;
    root_certificate_der_base64: string;
    leaf_certificate_der_base64: string;
  }>;
}>;

type Ready = Readonly<{
  type: "ready";
  runtime: string;
  carrier: string;
  path: "direct";
  artifact_json: string;
  trust_pem: string;
  origin: string;
}>;

type RelayReady = Readonly<{
  type: "relay-ready";
  runtime: string;
  carrier: string;
  path: "tunnel";
  endpoint_url: string;
  trust_pem: string;
  trust_roots_der: readonly string[];
  server_certificate_der: string;
  origin: string;
}>;

type TunnelAuthorizationWire = Readonly<{
  decision: "allow";
  credentialId: string;
  leaseId: string;
  expiresAtUnixSeconds: number;
  expectedPeerEndpointInstanceId: string;
  allowReplacement: boolean;
}>;

type Topology = Readonly<{
  id: string;
  endpoint_a: string;
  endpoint_b: string;
  tunnel_runtime: string;
  ingress_carrier_a: string;
  ingress_carrier_b: string;
}>;

type EndpointBReady = Readonly<{
  type: "endpoint-b-ready";
  runtime: string;
  carrier: string;
  path: "tunnel";
  endpoint_a_artifact_json: string;
  endpoint_b_artifact_json: string;
  relay: RelayReady;
  authorizations: readonly TunnelAuthorizationWire[];
}>;

type TunnelInput = Readonly<{
  topology: Topology;
  relay: RelayReady;
  endpoint_b: EndpointBReady;
}>;

type TunnelArtifactClaims = Readonly<{
  session: Readonly<{ init_expire_at_unix_s: number }>;
  path: Readonly<{ expected_peer_endpoint_instance_id: string }>;
}>;

class SignalQueue {
  readonly #values: undefined[] = [];
  readonly #waiters: Array<() => void> = [];

  push(): void {
    const waiter = this.#waiters.shift();
    if (waiter === undefined) this.#values.push(undefined);
    else waiter();
  }

  async shift(): Promise<void> {
    if (this.#values.length > 0) {
      this.#values.shift();
      return;
    }
    await new Promise<void>((resolve) => this.#waiters.push(resolve));
  }
}

class PeerInput {
  readonly #lines = createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  })[Symbol.asyncIterator]();

  async next<T>(): Promise<T> {
    const item = await this.#lines.next();
    if (item.done || item.value.trim() === "")
      throw new Error("peer stdin ended before the next protocol message");
    return JSON.parse(item.value) as T;
  }
}

type HandlerState = Readonly<{
  handlers: SessionHandlers;
  notifications: SignalQueue;
  activeStreams: { value: number };
}>;

function createHandlers(path: "direct" | "tunnel"): HandlerState {
  const handlers = new SessionHandlers({ maxConcurrentStreams: 16 });
  const notifications = new SignalQueue();
  const activeStreams = { value: 0 };
  handlers.handleRPC(ECHO_RPC, async (payload) =>
    validValuePayload(payload, "ping")
      ? { payload }
      : { error: { code: 400, message: "invalid echo payload" } },
  );
  handlers.handleRPC(COMPLETE_RPC, async (payload) => {
    if (!validValuePayload(payload, "complete"))
      return { error: { code: 400, message: "invalid completion payload" } };
    notifications.push();
    return { payload };
  });
  handlers.handleRPC(DATAGRAM_READY_RPC, async (payload) => {
    if (!validValuePayload(payload, "datagram-ready"))
      return {
        error: { code: 400, message: "invalid datagram barrier payload" },
      };
    notifications.push();
    return { payload };
  });
  handlers.handleNotification(NOTIFY_RPC, (payload) => {
    if (!validValuePayload(payload, "notify"))
      throw new Error("invalid notification payload");
    notifications.push();
  });
  handlers.handleStream(ECHO_KIND, async (incoming) => {
    activeStreams.value++;
    try {
      if (incoming.metadata.values.cell !== path)
        throw new Error("invalid stream metadata");
      if (decoder.decode(await readAll(incoming.stream)) !== "hello")
        throw new Error("invalid stream payload");
      await writeAll(incoming.stream, encoder.encode("world"));
    } finally {
      activeStreams.value--;
    }
  });
  handlers.handleStream(RESET_KIND, async (incoming) => {
    if (decoder.decode(await readAll(incoming.stream)) !== "reset")
      throw new Error("invalid reset stream payload");
    throw new Error("intentional parity reset");
  });
  return { handlers, notifications, activeStreams };
}

function validValuePayload(payload: JsonValue, expected: string): boolean {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload))
    return false;
  return (payload as Readonly<Record<string, JsonValue>>).value === expected;
}

async function writeAll(stream: ByteStream, bytes: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < bytes.length) {
    const written = await stream.write(bytes.subarray(offset));
    if (written < 1 || written > bytes.length - offset)
      throw new Error("invalid stream write count");
    offset += written;
  }
}

async function readAll(stream: ByteStream): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const chunk = await stream.read();
    if (chunk === null) break;
    chunks.push(chunk);
    length += chunk.length;
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

async function callBarrier(
  session: Session,
  typeId: number,
  value: string,
  label = "peer",
): Promise<void> {
  const result = await session.rpc.call(
    typeId,
    { value },
    (payload) => payload,
  );
  if (!result.ok || !validValuePayload(result.payload, value))
    throw new Error(
      `${label} RPC barrier ${typeId} failed: ${JSON.stringify(result)}`,
    );
}

async function assertCancellableWait(session: Session): Promise<void> {
  const cancellation = new AbortController();
  cancellation.abort();
  try {
    await session.waitTermination({ signal: cancellation.signal });
  } catch (error) {
    if (error instanceof SessionError && error.code === "canceled") return;
    throw error;
  }
  throw new Error("termination wait ignored cancellation");
}

async function clientStreams(
  session: Session,
  path: "direct" | "tunnel",
): Promise<void> {
  const stream = await session.openStream(ECHO_KIND, {
    metadata: createStreamMetadata({ cell: path }),
  });
  await writeAll(stream, encoder.encode("hello"));
  await stream.closeWrite();
  if (decoder.decode(await readAll(stream)) !== "world")
    throw new Error("echo stream did not preserve metadata and FIN");
  await stream.close();

  const reset = await session.openStream(RESET_KIND);
  let resetObserved = false;
  try {
    await writeAll(reset, encoder.encode("reset"));
    await reset.closeWrite();
    await readAll(reset);
    resetObserved = reset.terminalError !== undefined;
  } catch (error) {
    resetObserved =
      error instanceof SessionError && error.code === "stream_reset";
  } finally {
    await reset.close().catch(() => undefined);
  }
  if (!resetObserved) throw new Error("reset stream did not fail");
}

async function serverStreams(
  session: Session,
  path: "direct" | "tunnel",
): Promise<void> {
  const incoming = await session.acceptStream();
  if (incoming.kind !== ECHO_KIND || incoming.metadata.values.cell !== path)
    throw new Error("invalid echo stream metadata");
  if (decoder.decode(await readAll(incoming.stream)) !== "hello")
    throw new Error("invalid echo stream payload");
  await writeAll(incoming.stream, encoder.encode("world"));
  await incoming.stream.closeWrite();
  await incoming.stream.close();

  const reset = await session.acceptStream();
  if (
    reset.kind !== RESET_KIND ||
    decoder.decode(await readAll(reset.stream)) !== "reset"
  )
    throw new Error("invalid reset stream payload");
  await reset.stream.reset();
  await reset.stream.close().catch(() => undefined);
}

async function exerciseClient(
  session: Session,
  state: HandlerState,
  path: "direct" | "tunnel",
): Promise<void> {
  await callBarrier(session, ECHO_RPC, "ping", "client");
  await session.rpc.notify(NOTIFY_RPC, { value: "notify" });
  await state.notifications.shift();
  await clientStreams(session, path);
  await assertCancellableWait(session);
  await callBarrier(session, ECHO_RPC, "ping", "client cleanup");
  await callBarrier(
    session,
    DATAGRAM_READY_RPC,
    "datagram-ready",
    "client datagram",
  );
  await session.rekey();
  await session.probeLiveness();
  await callBarrier(session, COMPLETE_RPC, "complete", "client completion");
  await session.rpc.notify(NOTIFY_RPC, { value: "notify" });
}

async function exerciseServer(
  session: Session,
  state: HandlerState,
  path: "direct" | "tunnel",
  streamsServed: boolean,
): Promise<void> {
  const streams = streamsServed
    ? Promise.resolve()
    : serverStreams(session, path);
  await state.notifications.shift();
  await callBarrier(session, ECHO_RPC, "ping", "server");
  await session.rpc.notify(NOTIFY_RPC, { value: "notify" });
  await state.notifications.shift();
  await streams;
  await session.waitTermination();
}

function fixture(): TLSFixture {
  const certificate = pem("CERTIFICATE", TEST_CERT_DER_B64);
  return {
    tls: {
      certificate_chain_pem: certificate,
      private_key_pem: pem("PRIVATE KEY", TEST_KEY_DER_B64),
      root_certificate_pem: certificate,
      root_certificate_der_base64: TEST_CERT_DER_B64,
      leaf_certificate_der_base64: TEST_CERT_DER_B64,
    },
  };
}

function pem(label: string, encoded: string): string {
  const lines = encoded.match(/.{1,64}/g);
  if (lines === null) throw new Error("invalid embedded TLS fixture");
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

async function connectArtifact(
  artifactJSON: string,
  relay: Pick<RelayReady, "origin" | "trust_pem">,
  handlers: SessionHandlers,
): Promise<Session> {
  return await connect(
    createArtifactLease(parseArtifact(artifactJSON), async () => undefined),
    {
      origin: relay.origin,
      tls: { ca: relay.trust_pem },
      handlers,
    },
  );
}

async function runServer(tls: TLSFixture): Promise<void> {
  const issuedByLookup = new Map<string, ReturnType<typeof parseArtifact>>();
  const state = createHandlers("direct");
  const acceptor = await createAcceptor({
    listeners: [
      {
        carrier: "websocket",
        path: "direct",
        host: "127.0.0.1",
        port: 0,
        tls: {
          certificate: tls.tls.certificate_chain_pem,
          privateKey: tls.tls.private_key_pem,
        },
        allowedOrigins: [ORIGIN],
      },
    ],
    maxInboundStreams: 16,
    authorize: async (request) => {
      const artifact = issuedByLookup.get(request.lookupKey());
      return artifact === undefined
        ? { decision: "reject" as const, reason: "invalid_credential" }
        : { decision: "allow" as const, artifact };
    },
    resolveHandlers: () => state.handlers,
  });
  try {
    const address = acceptor.addresses()[0];
    if (address === undefined)
      throw new Error("direct WSS listener did not bind");
    const issued = new Issuer().issueDirect({
      session: { channelId: "node-direct-parity", maxInboundStreams: 16 },
      endpoints: createEndpointSet(
        `wss://localhost:${address.port}/flowersec/v2/direct`,
      ),
      rendezvousGroupId: "node-direct-parity",
      listenerAudience: "server-parity",
      upstreamAddress: "127.0.0.1:1",
    });
    const artifactJSON = decoder.decode(issued.artifactJSON());
    issuedByLookup.set(issued.lookupKey(), parseArtifact(artifactJSON));
    const accepting = acceptor.accept();
    writeJSON({
      type: "ready",
      runtime: RUNTIME,
      carrier: "websocket",
      path: "direct",
      artifact_json: artifactJSON,
      trust_pem: tls.tls.root_certificate_pem,
      origin: ORIGIN,
    });
    const accepted = await accepting;
    const serving = accepted.serve().catch((error: unknown) => error);
    await exerciseServer(accepted.session, state, "direct", true);
    await serving;
    await accepted.close().catch(() => undefined);
    writeJSON(
      result(
        "server-result",
        "direct",
        DIRECT_CASES,
        state.activeStreams.value,
      ),
    );
  } finally {
    await acceptor.close();
  }
}

async function runClient(input: PeerInput): Promise<void> {
  const ready = await input.next<Ready>();
  if (
    ready.type !== "ready" ||
    ready.carrier !== "websocket" ||
    ready.path !== "direct" ||
    ready.artifact_json === ""
  )
    throw new Error("invalid direct ready message");
  const state = createHandlers("direct");
  const session = await connectArtifact(
    ready.artifact_json,
    ready,
    state.handlers,
  );
  await exerciseClient(session, state, "direct");
  await session.close().catch((error: unknown) => {
    if (!(error instanceof SessionError) || error.code !== "closed")
      throw error;
  });
  writeJSON(
    result("client-result", "direct", DIRECT_CASES, state.activeStreams.value),
  );
}

async function runRelay(tls: TLSFixture, input: PeerInput): Promise<void> {
  const decisions = new Map<
    string,
    Extract<TunnelAuthorizationDecision, Readonly<{ decision: "allow" }>>
  >();
  const released = new Set<string>();
  const runtime = createTunnelRuntime({
    listeners: [
      {
        carrier: "websocket",
        host: "127.0.0.1",
        port: 0,
        tls: {
          certificate: tls.tls.certificate_chain_pem,
          privateKey: tls.tls.private_key_pem,
        },
        allowedOrigins: [ORIGIN],
      },
    ],
    maxInboundStreams: 16,
    maxPendingLegs: 16,
    maxActivePairs: 8,
    authorize: async (request) =>
      decisions.get(request.lookupKey()) ?? {
        decision: "reject",
        reason: "invalid_credential",
      },
    release: (leaseId) => {
      released.add(leaseId);
    },
  });
  try {
    await runtime.start();
    const address = runtime.addresses()[0];
    if (address === undefined)
      throw new Error("tunnel WSS listener did not bind");
    writeJSON({
      type: "relay-ready",
      runtime: RUNTIME,
      carrier: "websocket",
      path: "tunnel",
      endpoint_url: `wss://localhost:${address.port}/flowersec/v2/tunnel`,
      trust_pem: tls.tls.root_certificate_pem,
      trust_roots_der: [tls.tls.root_certificate_der_base64],
      server_certificate_der: tls.tls.leaf_certificate_der_base64,
      origin: ORIGIN,
    });
    const configure = await input.next<{
      type: string;
      authorizations: readonly TunnelAuthorizationWire[];
    }>();
    if (
      configure.type !== "configure" ||
      !Array.isArray(configure.authorizations) ||
      configure.authorizations.length === 0
    )
      throw new Error("invalid tunnel relay configuration");
    for (const item of configure.authorizations) {
      if (
        item.decision !== "allow" ||
        item.credentialId === "" ||
        item.leaseId === "" ||
        item.expectedPeerEndpointInstanceId === "" ||
        item.expiresAtUnixSeconds <= Math.floor(Date.now() / 1000)
      ) {
        throw new Error("invalid secret-free tunnel authorization");
      }
      decisions.set(item.credentialId, {
        decision: "allow",
        credentialId: item.credentialId,
        leaseId: item.leaseId,
        expiresAtUnixSeconds: item.expiresAtUnixSeconds,
        expectedPeerEndpointInstanceId: item.expectedPeerEndpointInstanceId,
        allowReplacement: item.allowReplacement,
      });
    }
    const close = await input.next<{ type: string }>();
    if (close.type !== "close")
      throw new Error("invalid tunnel relay close command");
  } finally {
    await runtime.close();
  }
  writeJSON({
    type: "relay-result",
    runtime: RUNTIME,
    carrier: "websocket",
    path: "tunnel",
    cases: RELAY_CASES,
    active_pairs: 0,
    active_legs: 0,
    active_sessions: 0,
    application_handlers: 0,
    observed_plaintext: false,
    released_leases: released.size,
  });
}

async function runTunnelEndpointB(input: PeerInput): Promise<void> {
  const envelope = await input.next<TunnelInput>();
  const { topology, relay } = envelope;
  validateTunnelDimensions(topology, relay, "endpoint_b");
  const pair = new Issuer().issueTunnelPair({
    session: { channelId: `parity-${topology.id}`, maxInboundStreams: 16 },
    endpoints: createEndpointSet(relay.endpoint_url),
    rendezvousGroupId: topology.id,
    listenerAudience: "server-parity",
    firstEndpointId: `${topology.id}-a`,
    secondEndpointId: `${topology.id}-b`,
  });
  const firstJSON = decoder.decode(pair.first.artifactJSON());
  const secondJSON = decoder.decode(pair.second.artifactJSON());
  const ready: EndpointBReady = {
    type: "endpoint-b-ready",
    runtime: RUNTIME,
    carrier: "websocket",
    path: "tunnel",
    endpoint_a_artifact_json: firstJSON,
    endpoint_b_artifact_json: secondJSON,
    relay,
    authorizations: [
      authorizationWire(pair.first, firstJSON, "lease-endpoint-a"),
      authorizationWire(pair.second, secondJSON, "lease-endpoint-b"),
    ],
  };
  writeJSON(ready);
  const command = await input.next<{ type: string }>();
  if (command.type !== "connect")
    throw new Error("endpoint B did not receive connect command");
  const state = createHandlers("tunnel");
  const session = await connectArtifact(secondJSON, relay, state.handlers);
  await exerciseServer(session, state, "tunnel", false);
  await session.close().catch(() => undefined);
  writeJSON(
    result(
      "endpoint-b-result",
      "tunnel",
      ENDPOINT_CASES,
      state.activeStreams.value,
    ),
  );
}

async function runTunnelEndpointA(input: PeerInput): Promise<void> {
  const envelope = await input.next<TunnelInput>();
  validateTunnelDimensions(
    envelope.topology,
    envelope.endpoint_b.relay,
    "endpoint_a",
  );
  const ready = envelope.endpoint_b;
  if (
    ready.type !== "endpoint-b-ready" ||
    ready.carrier !== "websocket" ||
    ready.path !== "tunnel" ||
    ready.endpoint_a_artifact_json === ""
  )
    throw new Error("invalid endpoint B ready message");
  const state = createHandlers("tunnel");
  const session = await connectArtifact(
    ready.endpoint_a_artifact_json,
    ready.relay,
    state.handlers,
  );
  await exerciseClient(session, state, "tunnel");
  await session.close().catch(() => undefined);
  writeJSON(
    result(
      "endpoint-a-result",
      "tunnel",
      ENDPOINT_CASES,
      state.activeStreams.value,
    ),
  );
}

function validateTunnelDimensions(
  topology: Topology,
  relay: RelayReady,
  endpoint: "endpoint_a" | "endpoint_b",
): void {
  if (
    topology[endpoint] !== RUNTIME ||
    topology.tunnel_runtime !== relay.runtime ||
    topology.ingress_carrier_a !== "websocket" ||
    topology.ingress_carrier_b !== "websocket" ||
    relay.type !== "relay-ready" ||
    relay.carrier !== "websocket" ||
    relay.path !== "tunnel"
  ) {
    throw new Error("invalid tunnel topology dimensions");
  }
}

function authorizationWire(
  issued: ReturnType<Issuer["issueDirect"]>,
  artifactJSON: string,
  leaseId: string,
): TunnelAuthorizationWire {
  const artifact = JSON.parse(artifactJSON) as TunnelArtifactClaims;
  if (
    !Number.isSafeInteger(artifact.session.init_expire_at_unix_s) ||
    artifact.path.expected_peer_endpoint_instance_id === ""
  )
    throw new Error("issued tunnel artifact omitted relay claims");
  return {
    decision: "allow",
    credentialId: issued.lookupKey(),
    leaseId,
    expiresAtUnixSeconds: artifact.session.init_expire_at_unix_s,
    expectedPeerEndpointInstanceId:
      artifact.path.expected_peer_endpoint_instance_id,
    allowReplacement: false,
  };
}

function result(
  type: string,
  path: "direct" | "tunnel",
  cases: readonly string[],
  activeStreams: number,
): Record<string, unknown> {
  return {
    type,
    runtime: RUNTIME,
    carrier: "websocket",
    path,
    cases,
    active_sessions: 0,
    active_streams: activeStreams,
  };
}

function writeJSON(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

function parseArguments(
  arguments_: readonly string[],
): Readonly<{ role: Role; carrier: "websocket" }> {
  const roles = new Set<Role>([
    "server",
    "client",
    "relay",
    "tunnel-endpoint-a",
    "tunnel-endpoint-b",
  ]);
  const role = arguments_[0] as Role;
  if (process.env.FLOWERSEC_SERVER_PARITY_PEER !== "1")
    throw new Error("server parity peer is test-only");
  if (
    arguments_.length !== 3 ||
    !roles.has(role) ||
    arguments_[1] !== "--carrier"
  )
    throw new Error("invalid server parity peer arguments");
  if (arguments_[2] !== "websocket")
    throw new Error(
      `Node.js production carrier is unsupported by this peer: ${arguments_[2] ?? "missing"}`,
    );
  return { role, carrier: "websocket" };
}

async function main(): Promise<void> {
  const { role } = parseArguments(process.argv.slice(2));
  switch (role) {
    case "server":
      await runServer(fixture());
      break;
    case "client":
      await runClient(new PeerInput());
      break;
    case "relay":
      await runRelay(fixture(), new PeerInput());
      break;
    case "tunnel-endpoint-a":
      await runTunnelEndpointA(new PeerInput());
      break;
    case "tunnel-endpoint-b":
      await runTunnelEndpointB(new PeerInput());
      break;
  }
}

await main().catch((error: unknown) => {
  process.stderr.write(
    `${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
});
