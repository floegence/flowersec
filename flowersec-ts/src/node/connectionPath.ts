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
    // Register a real socket synchronously. Node only counts an asynchronous
    // factory result after its callback, which otherwise bypasses maxSockets
    // while many routes are still dialing.
    const transport = new DeferredPath(this.#options.connectionPath, hostname, port, signal);
    const socket = tlsConnect({
      host: hostname, port, socket: transport,
      ...(hostname.includes(":") || /^\d+\.\d+\.\d+\.\d+$/u.test(hostname) ? {} : { servername: hostname }),
      minVersion: "TLSv1.3", rejectUnauthorized: true,
      ...(this.#options.ca === undefined ? {} : { ca: this.#options.ca }),
    });
    // TLS may detach its own listener before asynchronous construction settles.
    transport.on("error", (error: Error) => socket.destroy(error));
    const abort = (): void => { socket.destroy(new Error("Connection path canceled")); };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) queueMicrotask(abort);
    socket.once("secureConnect", () => { clearTimeout(timer); signal.removeEventListener("abort", abort); });
    socket.once("close", () => { clearTimeout(timer); signal.removeEventListener("abort", abort); transport.destroy(); });
    return socket;
  }

  override destroy(): void { this.#lifetime.abort(); super.destroy(); }
}

/** Buffer only stream high-water marks while the explicit route is pending. */
class DeferredPath extends Duplex {
  #transport?: Duplex;
  readonly #lifetime = new AbortController();

  constructor(readonly path: NodeConnectionPath, readonly hostname: string, readonly port: number, readonly signal: AbortSignal) {
    super({ allowHalfOpen: true, readableHighWaterMark: 64 * 1024, writableHighWaterMark: 64 * 1024 });
  }

  override _construct(callback: (error?: Error | null) => void): void {
    const signal = AbortSignal.any([this.signal, this.#lifetime.signal]);
    void openConnectionPath(this.path, this.hostname, this.port, signal).then(transport => {
      this.#transport = transport;
      transport.on("data", (data: Buffer) => { if (!this.push(data)) transport.pause(); });
      transport.once("end", () => this.push(null));
      transport.once("error", () => this.destroy(new Error("Connection path failed")));
      transport.once("close", () => { if (!transport.readableEnded) this.destroy(new Error("Connection path closed")); });
      transport.pause();
      callback();
    }, () => callback(this.destroyed ? null : new Error("Connection path failed")));
  }

  override _read(): void { this.#transport?.resume(); }
  override _write(chunk: Buffer, encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.#transport!.write(chunk, encoding, callback);
  }
  override _final(callback: (error?: Error | null) => void): void { this.#transport!.end(callback); }
  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.#lifetime.abort();
    this.#transport?.destroy();
    callback(error);
  }

  override destroy(error?: Error): this {
    // _destroy waits for _construct; cancel route acquisition before that wait.
    this.#lifetime.abort();
    return super.destroy(error);
  }
}
