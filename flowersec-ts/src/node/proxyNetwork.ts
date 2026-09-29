import { lookup } from "node:dns/promises";
import { isIP, Socket, SocketAddress } from "node:net";
import { checkServerIdentity, connect as connectTLS, createSecureContext, getCACertificates, type SecureContext } from "node:tls";

import { WireHostWorkspace } from "../v4/runtime/host.js";

const MAX_ADDRESSES = 64;
const CONNECT_TIMEOUT_MS = 10_000;
type Address = Readonly<{ text: string; family: 4 | 6; value: bigint }>;
type Prefix = Readonly<{ family: 4 | 6; value: bigint; shift: bigint }>;
export type ProxyConnection = Readonly<{ socket: Socket; closed: Promise<void>; close(): Promise<void> }>;

function invalid(): never { throw new Error("invalid proxy network policy"); }

function address(raw: string): Address {
  if (raw.includes("%")) invalid();
  const family = isIP(raw);
  if (family === 0) invalid();
  let text = new SocketAddress({ address: raw, family: family === 4 ? "ipv4" : "ipv6" }).address;
  if (family === 4) return { text, family, value: ipv4Value(text) };
  // isIP validates syntax before this bounded numeric projection. Decimal
  // mapped tails and hexadecimal mapped addresses share the same authority.
  if (text.includes(".")) {
    const offset = text.lastIndexOf(":") + 1, tail = ipv4Value(text.slice(offset));
    text = text.slice(0, offset) + (tail >> 16n).toString(16) + ":" + (tail & 65535n).toString(16);
  }
  const halves = text.split("::"), left = halves[0] === "" ? [] : halves[0]!.split(":");
  const right = halves.length === 1 || halves[1] === "" ? [] : halves[1]!.split(":");
  const words = [...left, ...Array<string>(8 - left.length - right.length).fill("0"), ...right];
  const value = words.reduce((sum, word) => (sum << 16n) | BigInt("0x" + word), 0n);
  if (value >> 32n === 65535n) {
    const v4 = value & 0xffffffffn;
    return { family: 4, value: v4, text: [24n, 16n, 8n, 0n].map(shift => String((v4 >> shift) & 255n)).join(".") };
  }
  return { family: 6, value, text: new SocketAddress({ address: raw, family: "ipv6" }).address };
}
function ipv4Value(text: string): bigint { return text.split(".").reduce((sum, part) => (sum << 8n) | BigInt(part), 0n); }
function usable(value: Address): boolean {
  return value.value !== 0n && (value.family === 4 ? value.value >> 28n !== 14n : value.value >> 120n !== 255n);
}
function prefix(raw: string): Prefix {
  const parts = raw.split("/");
  if (parts.length > 2 || parts[0] === undefined) invalid();
  const originalFamily = isIP(parts[0]), value = address(parts[0]);
  const width = originalFamily === 4 ? 32 : 128;
  let bits = parts[1] === undefined ? width : /^(?:0|[1-9][0-9]{0,2})$/u.test(parts[1]) ? Number(parts[1]) : -1;
  if (bits < 0 || bits > width) invalid();
  if (originalFamily === 6 && value.family === 4) { if (bits < 96) invalid(); bits -= 96; }
  const shift = BigInt((value.family === 4 ? 32 : 128) - bits);
  if ((value.value >> shift) << shift !== value.value) invalid();
  return { family: value.family, value: value.value, shift };
}

/** Compile the spelling before URL parsing can rewrite ambiguous numeric hosts. */
export function proxyUpstreamHost(raw: string): string {
  const match = /^https?:\/\/(\[[^\]]+\]|[^:/?#@\\]+)(?::([1-9][0-9]{0,4}))?\/?$/u.exec(raw);
  if (match === null || match[0] !== raw || match[2] !== undefined && Number(match[2]) > 65535) invalid();
  const host = match[1]!.startsWith("[") ? match[1]!.slice(1, -1) : match[1]!;
  if (isIP(host) !== 0) { address(host); return host.toLowerCase(); }
  new WireHostWorkspace().host(host);
  return host;
}

/** One private policy and connection entrance serve both HTTP and WebSocket. */
export class ProxyNetworkPolicy {
  readonly #numeric: Address | undefined;
  readonly #prefixes: readonly Prefix[];
  readonly #operations = new Set<Promise<void>>();
  readonly #tls: SecureContext | undefined;
  #closed = false;

  constructor(readonly host: string, readonly port: number, ranges: readonly string[], private readonly maximum: number, secure = false) {
    if (!Number.isInteger(port) || port < 1 || port > 65535 || ranges.length > MAX_ADDRESSES || maximum < 1) invalid();
    this.#numeric = isIP(host) === 0 ? undefined : address(host);
    this.#tls = secure ? createSecureContext({ ca: getCACertificates("default") }) : undefined;
    if (this.#numeric === undefined) { new WireHostWorkspace().host(host); if (ranges.length === 0) invalid(); }
    this.#prefixes = ranges.map(prefix);
    if (this.#numeric !== undefined) {
      if (!usable(this.#numeric) || ranges.length !== 0 && !this.#allows(this.#numeric)) invalid();
      this.#prefixes = [{ family: this.#numeric.family, value: this.#numeric.value, shift: 0n }];
    }
  }

  #allows(value: Address): boolean {
    return usable(value) && this.#prefixes.some(range => range.family === value.family && value.value >> range.shift === range.value >> range.shift);
  }
  #check(signal: AbortSignal): void { signal.throwIfAborted(); if (this.#closed) throw new Error("proxy network closed"); }

  async connect(secure: boolean, signal: AbortSignal): Promise<ProxyConnection> {
    this.#check(signal);
    if (secure !== (this.#tls !== undefined)) invalid();
    if (this.#operations.size >= this.maximum) throw new Error("proxy network capacity exhausted");
    const timeout = new AbortController(), timer = setTimeout(() => timeout.abort(new Error("proxy connection timed out")), CONNECT_TIMEOUT_MS);
    const preparationSignal = AbortSignal.any([signal, timeout.signal]);
    const prepared = this.#prepare(secure, signal, preparationSignal).finally(() => clearTimeout(timer));
    // A timed-out native resolver cannot be canceled. Keep its actual tail in
    // this finite policy pool until completion; its late result cannot dial.
    const operation = prepared.then(connection => connection.closed, () => undefined).finally(() => { this.#operations.delete(operation); });
    this.#operations.add(operation);
    try { return await abortable(prepared, preparationSignal); }
    catch (error) { void prepared.then(connection => connection.close(), () => undefined); throw error; }
  }

  async #prepare(secure: boolean, ownerSignal: AbortSignal, signal: AbortSignal): Promise<ProxyConnection> {
    const results = this.#numeric === undefined ? await lookup(this.host, { all: true, verbatim: true }) : [{ address: this.#numeric.text, family: this.#numeric.family }];
    this.#check(signal);
    if (results.length === 0 || results.length > MAX_ADDRESSES) invalid();
    const addresses = results.map(result => { const value = address(result.address); if (!this.#allows(value)) invalid(); return value; });
    let lastError: unknown = new Error("proxy connection failed");
    for (const candidate of addresses.slice(0, 3)) {
      this.#check(signal);
      const tcp = ownSocket(new Socket({ allowHalfOpen: false }), ownerSignal);
      try {
        const ready = socketReady(tcp.socket, "connect", signal);
        tcp.socket.connect({ host: candidate.text, port: this.port, family: candidate.family, autoSelectFamily: false });
        await ready;
      } catch (error) { lastError = error; await tcp.close(); continue; }
      try {
        this.#check(signal);
        const peer = tcp.socket.remoteAddress === undefined ? invalid() : address(tcp.socket.remoteAddress);
        if (peer.family !== candidate.family || peer.value !== candidate.value || tcp.socket.remotePort !== this.port || !this.#allows(peer)) invalid();
        if (!secure) return tcp;
        const tls = ownSocket(connectTLS({ socket: tcp.socket, secureContext: this.#tls, servername: isIP(this.host) === 0 ? this.host : "", rejectUnauthorized: true,
          ALPNProtocols: ["http/1.1"], checkServerIdentity: (_name, certificate) => checkServerIdentity(this.host, certificate) }), ownerSignal);
        try { await socketReady(tls.socket, "secureConnect", signal); this.#check(signal); }
        catch (error) { await tls.close(); throw error; }
        return { socket: tls.socket, closed: Promise.all([tls.closed, tcp.closed]).then(() => undefined),
          close: async () => { await tls.close(); await tcp.close(); } };
      } catch (error) { await tcp.close(); throw error; }
    }
    this.#check(signal);
    throw lastError;
  }

  async close(): Promise<void> { this.#closed = true; await Promise.all(this.#operations); }
}

function ownSocket(socket: Socket, signal: AbortSignal): ProxyConnection {
  const abort = (): void => { socket.destroy(); };
  const ignoreError = (): void => { /* The current native operation observes failure. */ };
  socket.on("error", ignoreError);
  const closed = new Promise<void>(resolve => socket.once("close", () => {
    signal.removeEventListener("abort", abort); socket.removeListener("error", ignoreError); resolve();
  }));
  signal.addEventListener("abort", abort, { once: true });
  if (signal.aborted) abort();
  return { socket, closed, close: async () => { socket.destroy(); await closed; } };
}
function socketReady(socket: Socket, event: "connect" | "secureConnect", signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = (): void => { socket.off(event, ready); socket.off("error", failed); socket.off("close", closed); signal.removeEventListener("abort", aborted); };
    const ready = (): void => { cleanup(); resolve(); }, failed = (error: unknown): void => { cleanup(); reject(error); };
    const closed = (): void => failed(new Error("proxy connection closed")), aborted = (): void => failed(signal.reason);
    socket.once(event, ready); socket.once("error", failed); socket.once("close", closed); signal.addEventListener("abort", aborted, { once: true });
    if (signal.aborted) aborted(); else if (socket.destroyed) closed();
  });
}
function abortable<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = (): void => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
    if (signal.aborted) abort();
  });
}
