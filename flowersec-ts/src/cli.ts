#!/usr/bin/env node
import { readFileSync } from "node:fs";

import { acceptNativeSessionV2 } from "./connector/sessionAcceptor.js";
import { claimSpendMarker } from "./cliSpendMarker.js";
import { connect } from "./node/connectSession.js";
import { nodeSessionRuntimeV2 } from "./node/sessionRuntime.js";
import { startNodeWebSocketServer } from "./node/webSocketServer.js";
import type { Session } from "./public/contract.js";
import { createArtifactLeaseV2 } from "./v2/artifactLease.js";
import { buildFSB2RequestV2, encodeFSB2RequestV2 } from "./v2/artifact.js";
import type { InternalSessionV2 } from "./v2/contract.js";
import { parseArtifact, unwrapArtifact } from "./v2/opaqueArtifact.js";

type Arguments = Readonly<{ mode: "client" | "server"; values: Readonly<Record<string, string>> }>;

const args = parseArguments(process.argv.slice(2));
if (args.mode === "client") await runClient(args.values);
else await runServer(args.values);

async function runClient(values: Readonly<Record<string, string>>): Promise<void> {
  requireWebSocket(values);
  const artifact = parseArtifact(readFileSync(required(values, "artifact")));
  const lease = createArtifactLeaseV2(artifact, async () => claimSpendMarker(required(values, "spend-marker")));
  let session: Session | undefined;
  try {
    session = await connect(lease, {
      origin: required(values, "origin"),
      ...(values.ca === undefined ? {} : { tls: { ca: readFileSync(values.ca, "utf8") } }),
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
  requireWebSocket(values);
  const artifact = unwrapArtifact(parseArtifact(readFileSync(required(values, "artifact"))));
  if (artifact.path.kind !== "direct") throw new Error("CLI server requires a direct artifact");
  const certificatePath = values.certificate;
  const privateKeyPath = values["private-key"];
  if ((certificatePath === undefined) !== (privateKeyPath === undefined)) {
    throw new Error("--certificate and --private-key must be provided together");
  }
  const server = await startNodeWebSocketServer({
    host: values.host ?? "127.0.0.1",
    port: Number.parseInt(required(values, "port"), 10),
    path: "direct",
    allowedOrigins: [required(values, "origin")],
    inboundBidirectionalStreamCapacity: artifact.session.max_inbound_streams + 2,
    ...(certificatePath === undefined || privateKeyPath === undefined ? {} : {
      tls: {
        certificate: readFileSync(certificatePath, "utf8"),
        privateKey: readFileSync(privateKeyPath, "utf8"),
      },
    }),
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
        if (request.request.pathKind !== "direct" || chosen?.carrier !== "websocket") {
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

function requireWebSocket(values: Readonly<Record<string, string>>): void {
  if (values.transport !== "websocket") throw new Error("--transport websocket is required");
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let different = 0;
  for (let index = 0; index < left.length; index++) different |= left[index]! ^ right[index]!;
  return different === 0;
}
