import { Agent, type RequestOptions } from "node:https";
import { Duplex } from "node:stream";
import { connect as tlsConnect, type ConnectionOptions } from "node:tls";

/** An explicit byte transport. The SDK always performs target TLS above it.
 * A configured path is mandatory: route failures never fall back to direct TCP.
 * Implementations must honor signal and return an owned, unencrypted Duplex.
 */
export type NodeConnectionPath = Readonly<{
  connect(target: Readonly<{ hostname: string; port: number; signal: AbortSignal }>): Promise<Duplex>;
}>;

/** Internal shared route admission, including disposal of a late result. */
export async function openConnectionPath(
  path: NodeConnectionPath,
  hostname: string,
  port: number,
  signal: AbortSignal,
): Promise<Duplex> {
  if (signal.aborted) throw new Error("Connection path canceled");
  return await new Promise<Duplex>((resolve, reject) => {
    let settled = false;
    const abort = (): void => {
      if (settled) return;
      settled = true;
      reject(new Error("Connection path canceled"));
    };
    signal.addEventListener("abort", abort, { once: true });
    void Promise.resolve().then(async () => await path.connect({ hostname, port, signal })).then((stream) => {
      if (!(stream instanceof Duplex)) throw new Error("Invalid connection path stream");
      if (settled || signal.aborted) { stream.destroy(); return; }
      settled = true;
      signal.removeEventListener("abort", abort);
      resolve(stream);
    }).catch(() => {
      signal.removeEventListener("abort", abort);
      if (settled) return;
      settled = true;
      reject(new Error("Connection path failed"));
    });
  });
}

export type ConnectionPathAgentOptions = Readonly<{
  connectionPath: NodeConnectionPath;
  ca?: ConnectionOptions["ca"];
  connectTimeoutMs?: number;
  signal?: AbortSignal;
}>;

/** HTTPS bootstrap and host bridges use the same explicit path as Session.
 * The Agent preserves the requested host, CA verification and SNI. It provides
 * no TLS bypass, redirects or direct-connect fallback. Destroying the Agent
 * cancels route attempts as well as closing established sockets.
 */
export function createConnectionPathAgent(options: ConnectionPathAgentOptions): Agent {
  const timeout = options.connectTimeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || typeof options.connectionPath?.connect !== "function") {
    throw new Error("Invalid connection path options");
  }
  return new ConnectionPathAgent(options, timeout);
}

class ConnectionPathAgent extends Agent {
  readonly #options: ConnectionPathAgentOptions;
  readonly #timeout: number;
  readonly #lifetime = new AbortController();

  constructor(options: ConnectionPathAgentOptions, timeout: number) {
    super({ keepAlive: true, maxCachedSessions: 0 });
    this.#options = options;
    this.#timeout = timeout;
  }

  override createConnection(options: RequestOptions, callback?: (err: Error | null, stream: Duplex) => void): Duplex | undefined {
    if (callback === undefined) throw new Error("Connection path Agent requires an asynchronous callback");
    const fail = (error: Error): void => callback(error, undefined as unknown as Duplex);
    const hostname = options.host ?? options.servername;
    const port = Number(options.port ?? 443);
    if (typeof hostname !== "string" || hostname === "" || !Number.isSafeInteger(port) || port < 1 || port > 65535) {
      queueMicrotask(() => fail(new Error("Invalid connection path target")));
      return undefined;
    }
    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), this.#timeout);
    const signals = [this.#lifetime.signal, timeout.signal];
    if (this.#options.signal !== undefined) signals.push(this.#options.signal);
    if (options.signal !== undefined) signals.push(options.signal);
    const signal = AbortSignal.any(signals);
    void openConnectionPath(this.#options.connectionPath, hostname, port, signal).then((transport) => {
      if (signal.aborted) { clearTimeout(timer); transport.destroy(); fail(new Error("Connection path canceled")); return; }
      // Only SDK-owned TLS options are accepted. Agent request overrides cannot
      // turn off verification or replace the connection factory.
      let socket;
      try { socket = tlsConnect({
        host: hostname, port, socket: transport,
        ...(hostname.includes(":") || /^\d+\.\d+\.\d+\.\d+$/u.test(hostname) ? {} : { servername: hostname }),
        minVersion: "TLSv1.3", rejectUnauthorized: true,
        ...(this.#options.ca === undefined ? {} : { ca: this.#options.ca }),
      }); } catch {
        clearTimeout(timer); transport.destroy(); fail(new Error("Connection path TLS failed")); return;
      }
      const abort = (): void => { socket.destroy(new Error("Connection path canceled")); };
      signal.addEventListener("abort", abort, { once: true });
      socket.once("secureConnect", () => { clearTimeout(timer); signal.removeEventListener("abort", abort); });
      socket.once("close", () => { clearTimeout(timer); signal.removeEventListener("abort", abort); transport.destroy(); });
      callback(null, socket);
    }, () => { clearTimeout(timer); fail(new Error("Connection path failed")); });
    // Node's asynchronous Agent factory reports exclusively via callback.
    return undefined;
  }

  override destroy(): void { this.#lifetime.abort(); super.destroy(); }
}
