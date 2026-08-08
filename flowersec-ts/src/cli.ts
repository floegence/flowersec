#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { createArtifactLeaseV2 } from "./v2/artifactLease.js";
import { buildFSB2RequestV2, encodeFSB2RequestV2 } from "./v2/artifact.js";
import { parseArtifact, unwrapArtifact } from "./v2/opaqueArtifact.js";
import { connect } from "./node/connectSession.js";
import { startNodeWebTransportServerV2 } from "./node/webTransportServer.js";
import { acceptNativeSessionV2 } from "./connector/sessionAcceptor.js";
import type { SessionV2 as PublicSessionV2, InternalSessionV2 } from "./v2/contract.js";
import { nodeSessionRuntimeV2 } from "./node/sessionRuntime.js";
import { claimSpendMarker } from "./cliSpendMarker.js";

type Arguments = Readonly<{ mode: "client" | "server"; values: Readonly<Record<string, string>> }>;

const args = parseArguments(process.argv.slice(2));
if (args.mode === "client") await runClient(args.values);
else await runServer(args.values);

async function runClient(values: Readonly<Record<string, string>>): Promise<void> {
  const artifactPath = required(values, "artifact");
  const origin = required(values, "origin");
  const spendMarker = required(values, "spend-marker");
  requireWebTransport(values);
  const artifact = parseArtifact(readFileSync(artifactPath));
  let session: PublicSessionV2 | undefined;
  const lease = createArtifactLeaseV2(artifact, async () => claimSpendMarker(spendMarker));
  try {
    session = await connect(lease, {
      origin,
      ...(values["certificate-hash"] === undefined ? {} : {
        tls: { serverCertificateHash: decodeHash(values["certificate-hash"]!) },
      }),
    });
    const stream = await session.openStream("cli");
    await stream.write(new TextEncoder().encode("flowersec-ts-cli"));
    await stream.closeWrite();
    const response = await stream.read();
    if (response === null || new TextDecoder().decode(response) !== "flowersec-ts-cli") {
      throw new Error("CLI server returned an invalid stream response");
    }
    process.stdout.write("GREEN\n");
  } finally {
    await session?.close();
  }
}

async function runServer(values: Readonly<Record<string, string>>): Promise<void> {
  const artifact = unwrapArtifact(parseArtifact(readFileSync(required(values, "artifact"))));
  requireWebTransport(values);
  const server = await startNodeWebTransportServerV2({
    host: values.host ?? "127.0.0.1",
    port: Number.parseInt(required(values, "port"), 10),
    path: values.path ?? "/flowersec/webtransport/v2/direct",
    certificate: readFileSync(required(values, "certificate"), "utf8"),
    privateKey: readFileSync(required(values, "private-key"), "utf8"),
    carrierPath: artifact.path.kind,
    inboundBidirectionalStreamCapacity: artifact.session.max_inbound_streams + 2,
  });
  process.stdout.write(JSON.stringify(server.address()) + "\n");
  const abort = new AbortController();
  const stop = () => abort.abort(new Error("CLI server stopped"));
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  try {
    const session = await acceptNativeSessionV2(
      await server.accept({ signal: abort.signal }),
      async (request) => {
        const chosen = artifact.path.candidates.find(({ id }) => id === request.request.chosen_candidate_id);
        if (request.request.pathKind !== artifact.path.kind || chosen?.carrier !== "webtransport") {
          throw new Error("CLI server rejected an unexpected artifact candidate");
        }
        const expected = encodeFSB2RequestV2(buildFSB2RequestV2(artifact, request.request.chosen_candidate_id));
        if (!bytesEqual(expected, request.raw)) throw new Error("CLI server rejected an unbound artifact");
        return { accepted: true, artifact };
      },
      { runtime: nodeSessionRuntimeV2, signal: abort.signal },
    );
    await echoOnce(session);
    await session.close();
  } finally {
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    await server.close();
  }
}

async function echoOnce(session: InternalSessionV2): Promise<void> {
  const incoming = await session.acceptStream();
  const payload = await incoming.stream.read();
  if (payload === null) throw new Error("CLI stream closed before payload");
  await incoming.stream.write(payload);
  await incoming.stream.closeWrite();
}

function parseArguments(raw: readonly string[]): Arguments {
  const [mode, ...rest] = raw;
  if (mode !== "client" && mode !== "server") throw new Error("usage: flowersec-ts-cli <client|server> options");
  const values: Record<string, string> = {};
  for (let index = 0; index < rest.length; index++) {
    const token = rest[index]!;
    if (!token.startsWith("--") || index + 1 >= rest.length || rest[index + 1]!.startsWith("--")) {
      throw new Error(`invalid CLI option ${token}`);
    }
    values[token.slice(2)] = rest[++index]!;
  }
  return { mode, values };
}

function required(values: Readonly<Record<string, string>>, name: string): string {
  const value = values[name];
  if (value === undefined || value === "") throw new Error(`missing --${name}`);
  return value;
}

function decodeHash(value: string): Uint8Array {
  if (!/^[0-9a-fA-F]{64}$/.test(value)) throw new Error("--certificate-hash must be 32-byte SHA-256 hex");
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function requireWebTransport(values: Readonly<Record<string, string>>): void {
  if (values.transport !== "webtransport") {
    throw new Error("--transport webtransport is required");
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let different = 0;
  for (let index = 0; index < left.length; index++) different |= left[index]! ^ right[index]!;
  return different === 0;
}
