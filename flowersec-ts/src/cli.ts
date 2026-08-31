#!/usr/bin/env node
import { readFileSync } from "node:fs";

import { claimSpendMarker } from "./cliSpendMarker.js";
import { createArtifactLease, parseArtifact } from "./facade.js";
import {
  connect,
  createAcceptor,
  type AcceptedSession,
} from "./node/index.js";
import type { Session } from "./public/contract.js";

type Arguments = Readonly<{
  mode: "client" | "server";
  values: Readonly<Record<string, string>>;
}>;

await main();

async function main(): Promise<void> {
  try {
    const args = parseArguments(process.argv.slice(2));
    if (args.mode === "client") await runClient(args.values);
    else await runServer(args.values);
  } catch (error) {
    const code = errorCode(error);
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  }
}

async function runClient(values: Readonly<Record<string, string>>): Promise<void> {
  requireWebSocket(values);
  const artifact = parseArtifact(readFileSync(required(values, "artifact")));
  const lease = createArtifactLease(
    artifact,
    async () => claimSpendMarker(required(values, "spend-marker")),
  );
  let session: Session | undefined;
  try {
    session = await connect(lease, {
      origin: required(values, "origin"),
      ...(values.ca === undefined
        ? {}
        : { roots: readFileSync(values.ca, "utf8") }),
    });
    const stream = await session.openStream("cli");
    await stream.write(new TextEncoder().encode("flowersec-ts-cli"));
    await stream.closeWrite();
    const response = await stream.read();
    if (response === null || new TextDecoder().decode(response) !== "flowersec-ts-cli") {
      throw new Error("invalid_response");
    }
    process.stdout.write("GREEN\n");
  } finally {
    await session?.close().catch(() => undefined);
  }
}

async function runServer(values: Readonly<Record<string, string>>): Promise<void> {
  requireWebSocket(values);
  const artifact = parseArtifact(readFileSync(required(values, "artifact")));
  const certificate = readFileSync(required(values, "certificate"), "utf8");
  const privateKey = readFileSync(required(values, "private-key"), "utf8");
  const acceptor = await createAcceptor({
    listeners: [{
      carrier: "websocket",
      path: "direct",
      host: values.host ?? "127.0.0.1",
      port: parsePort(required(values, "port")),
      tls: { certificate, privateKey },
      allowedOrigins: [required(values, "origin")],
    }],
    maxInboundStreams: parseMaxInboundStreams(required(values, "max-inbound-streams")),
    authorize: async () => ({ accepted: true, artifact }),
  });
  process.stdout.write(`${JSON.stringify(acceptor.addresses()[0])}\n`);
  const abort = new AbortController();
  let stopping = false;
  let accepted: AcceptedSession | undefined;
  const stop = () => {
    stopping = true;
    abort.abort(new Error("canceled"));
    void accepted?.close().catch(() => undefined);
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  try {
    accepted = await acceptor.accept({ signal: abort.signal });
    await echoOnce(accepted.session);
  } catch (error) {
    if (!stopping) throw error;
  } finally {
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    await accepted?.close().catch(() => undefined);
    await acceptor.close().catch(() => undefined);
  }
}

async function echoOnce(session: Session): Promise<void> {
  const incoming = await session.acceptStream();
  if (incoming.kind !== "cli") throw new Error("invalid_stream_kind");
  const payload = await incoming.stream.read();
  if (payload === null) throw new Error("missing_payload");
  await incoming.stream.write(payload);
  await incoming.stream.closeWrite();
}

function parseArguments(raw: readonly string[]): Arguments {
  const [mode, ...rest] = raw;
  if (mode !== "client" && mode !== "server") {
    throw new Error("usage: flowersec-ts-cli <client|server> options");
  }
  const values: Record<string, string> = {};
  for (let index = 0; index < rest.length; index++) {
    const token = rest[index]!;
    if (!token.startsWith("--") || index + 1 >= rest.length || rest[index + 1]!.startsWith("--")) {
      throw new Error(`invalid_option:${token}`);
    }
    const name = token.slice(2);
    if (Object.hasOwn(values, name)) throw new Error(`duplicate_option:${token}`);
    values[name] = rest[++index]!;
  }
  return { mode, values };
}

function required(values: Readonly<Record<string, string>>, name: string): string {
  const value = values[name];
  if (value === undefined || value === "") throw new Error(`missing_option:${name}`);
  return value;
}

function requireWebSocket(values: Readonly<Record<string, string>>): void {
  if (values.transport !== "websocket") throw new Error("websocket_required");
}

function parsePort(value: string): number {
  if (!/^\d{1,5}$/u.test(value)) throw new Error("invalid_port");
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
    throw new Error("invalid_port");
  }
  return port;
}

function parseMaxInboundStreams(value: string): number {
  if (!/^\d{1,3}$/u.test(value)) throw new Error("invalid_max_inbound_streams");
  const maximum = Number(value);
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 128) {
    throw new Error("invalid_max_inbound_streams");
  }
  return maximum;
}

function errorCode(error: unknown): string {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string" && /^[a-z][a-z0-9_]*$/u.test(code)) return code;
  }
  if (error instanceof Error && /^[a-z][a-z0-9_:<> -]*$/u.test(error.message)) {
    return error.message;
  }
  return "operation_failed";
}
