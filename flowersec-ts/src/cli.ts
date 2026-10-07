#!/usr/bin/env node
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createAcceptor, Acceptor, type AcceptorOptions } from "./node/acceptorCurrent.js";
import { V4ReaderCursor, type V4ConnectionMaterialSource, type V4Session, type V4TransportEnvironment } from "./v4/public.js";
import type { V4ConnectionRequirements } from "./generated/transportV4APIResults.js";
import type { OperationOptions } from "./public/contract.js";

/** A trusted application module supplies keys, authority namespaces and the
 * configured current provider. CLI code never infers those trust decisions
 * from an unverified artifact, hostname or a previous protocol's credential. */
export interface CLIClientSetup {
  readonly environment: V4TransportEnvironment;
  readonly source: V4ConnectionMaterialSource;
  readonly requirements?: Partial<V4ConnectionRequirements>;
  readonly kind?: string;
  readonly close?: () => Promise<void> | void;
}
export interface CLIServerSetup {
  /** The original prepared acceptor can carry an authenticated server-local
   * allow; a trusted module may also supply an ordinary listener configuration. */
  readonly acceptor: AcceptorOptions | Acceptor;
  readonly close?: () => Promise<void> | void;
}
export interface CLIConfiguration {
  client?(values: Readonly<Record<string, string>>, operation: OperationOptions): Promise<CLIClientSetup> | CLIClientSetup;
  server?(values: Readonly<Record<string, string>>, operation: OperationOptions): Promise<CLIServerSetup> | CLIServerSetup;
}
interface Arguments { readonly mode: "client" | "server"; readonly values: Readonly<Record<string, string>> }

await main();
async function main(): Promise<void> {
  const abort = new AbortController();
  const stop = () => abort.abort();
  process.once("SIGINT", stop); process.once("SIGTERM", stop);
  try {
    const args = parseArguments(process.argv.slice(2)), path = args.values.config;
    if (path === undefined || path.length === 0) throw new Error("missing_option:config");
    // This is an explicitly selected local application module, never executable
    // content from a peer, signed credential, database record or CLI response.
    const configured = await import(pathToFileURL(resolve(path)).href) as { default?: CLIConfiguration; configuration?: CLIConfiguration };
    const config = configured.default ?? configured.configuration;
    if (config === undefined || config === null || typeof config !== "object") throw new Error("invalid_configuration");
    if (args.mode === "client") await runClient(config, args.values, abort.signal);
    else await runServer(config, args.values, abort.signal);
  } catch (error) {
    process.stderr.write(`${errorCode(error)}\n`); process.exitCode = 1;
  } finally { process.removeListener("SIGINT", stop); process.removeListener("SIGTERM", stop); }
}
async function runClient(config: CLIConfiguration, values: Readonly<Record<string, string>>, signal: AbortSignal): Promise<void> {
  if (typeof config.client !== "function") throw new Error("client_configuration_required");
  const setup = await config.client(values, { signal });
  let session: V4Session | undefined, payload: Uint8Array | undefined;
  try {
    if (signal.aborted) throw new Error("canceled");
    payload = new TextEncoder().encode(values.message ?? "flowersec-ts-cli");
    if (payload.length < 1 || payload.length > 1048576) throw new Error("message_too_large");
    session = await setup.environment.connect(setup.source, setup.requirements, { signal });
    const stream = await session.openStream(setup.kind ?? "cli", { signal });
    try {
      const written = await stream.write(payload, { signal });
      if (written.accepted_bytes !== BigInt(payload.length)) throw new Error("write_incomplete");
      await stream.closeWrite({ signal });
      const cursor = new V4ReaderCursor(stream, { exact: BigInt(payload.length) });
      try {
        const reply = await cursor.readExactly({ signal });
        if (reply.error !== undefined || reply.data.length !== payload.length || reply.data.some((byte, i) => byte !== payload![i])) throw new Error("invalid_response");
      } finally { cursor.close(); }
      await stream.finish({ signal });
      process.stdout.write("GREEN\n");
    } finally { await stream.close().catch(() => undefined); }
  } finally {
    payload?.fill(0);
    await session?.close().catch(() => undefined);
    await setup.close?.();
  }
}
async function runServer(config: CLIConfiguration, values: Readonly<Record<string, string>>, signal: AbortSignal): Promise<void> {
  if (typeof config.server !== "function") throw new Error("server_configuration_required");
  const setup = await config.server(values, { signal });
  let acceptor: Acceptor | undefined;
  try {
    if (signal.aborted) throw new Error("canceled");
    acceptor = setup.acceptor instanceof Acceptor ? setup.acceptor : await createAcceptor(setup.acceptor, { signal });
    process.stdout.write(`${JSON.stringify(acceptor.addresses())}\n`);
    const accepted = await acceptor.accept({ signal });
    try { await accepted.serve({ signal }); }
    finally { await accepted.close(); }
  } finally { await acceptor?.close(); await setup.close?.(); }
}
function parseArguments(raw: readonly string[]): Arguments {
  const [mode, ...rest] = raw;
  if (mode !== "client" && mode !== "server") throw new Error("usage: flowersec-ts-cli <client|server> --config <module> options");
  const values: Record<string, string> = Object.create(null) as Record<string, string>;
  for (let index = 0; index < rest.length; index++) {
    const token = rest[index]!;
    if (!/^--[a-z][a-z0-9-]*$/u.test(token) || index + 1 >= rest.length || rest[index + 1]!.startsWith("--")) throw new Error("invalid_option");
    const name = token.slice(2);
    if (Object.hasOwn(values, name)) throw new Error("duplicate_option");
    values[name] = rest[++index]!;
  }
  return { mode, values: Object.freeze(values) };
}
function errorCode(error: unknown): string {
  if (error !== null && typeof error === "object") {
    try {
      const code = (error as { code?: unknown }).code;
      if (typeof code === "string" && /^[a-z][a-z0-9_]{0,127}$/u.test(code)) return code;
      if (error instanceof Error && /^[a-z][a-z0-9_:<> -]{0,255}$/u.test(error.message)) return error.message;
    } catch { /* Application exceptions keep the bounded opaque fallback. */ }
  }
  return "operation_failed";
}
