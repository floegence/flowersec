import { X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type EnvironmentDependency } from "../v4/runtime/environment.js";
import { TrustedDeadline, timerChunk } from "../v4/runtime/deadline.js";
import { equalCredential, requireCredential } from "../v4/runtime/credentialSupport.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { captureNodeRawQUIC, sameNodeRawQUICOptions, nativeRawQUICQueueBytes, type NodeRawQUICOptions } from "./rawQUICCurrent.js";
import { loadCurrentNativeTransport, loadCurrentNativeWebTransport, bindCurrentNativeListener, type NativeRawListener } from "./nativeTransportCurrent.js";

export interface TunnelListenerPreparationOptions {
  readonly environment: V4TransportEnvironment;
  readonly host: string; readonly port: number; readonly serverName: string;
  readonly tls: Readonly<{ certificateChainDER: readonly Uint8Array[]; privateKeyDER: Uint8Array }>;
  readonly carrier: NodeRawQUICOptions;
  readonly maxPairs: number; readonly handshakeMS: bigint; readonly preparationMS: bigint;
}
const capability = Symbol("original prepared tunnel listener"), owners = new WeakSet<TunnelListenerPreparation>();
/** A bounded physical TLS listener preparation. It provides an actual address
 * for issuer configuration, without accepting a hop, claiming a relay slot or
 * asserting any credential/admission fact. Its pending native queue stays with
 * this original owner until the authenticated runtime adopts the listener. */
export class TunnelListenerPreparation {
  readonly #runtime: ReturnType<typeof originalEnvironment>; readonly #options: TunnelListenerPreparationOptions;
  readonly #carrier: NodeRawQUICOptions; readonly #chain: readonly Uint8Array[]; readonly #key: Uint8Array;
  readonly #dependency: EnvironmentDependency; readonly #deadline: TrustedDeadline;
  readonly #done: Promise<void>; #resolve!: () => void;
  #listener: NativeRawListener | undefined; #binding: Promise<NativeRawListener> | undefined; #address: Readonly<{ host: string; port: number }> | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined; #closed = false; #taken = false; #ended = false; #released = false;
  constructor(token: symbol, options: TunnelListenerPreparationOptions) {
    requireCredential(token === capability); this.#runtime = originalEnvironment(options.environment);
    requireCredential(isIP(options.host) !== 0 && Number.isSafeInteger(options.port) && options.port >= 0 && options.port <= 65535 && typeof options.serverName === "string" && options.serverName.length > 0 && options.serverName.length <= 253 &&
      Number.isSafeInteger(options.maxPairs) && options.maxPairs >= 1 && options.maxPairs <= 4096 && typeof options.handshakeMS === "bigint" && options.handshakeMS > 0n && options.handshakeMS <= 60000n && typeof options.preparationMS === "bigint" && options.preparationMS > 0n && options.preparationMS <= 300000n &&
      Array.isArray(options.tls.certificateChainDER) && options.tls.certificateChainDER.length > 0 && options.tls.certificateChainDER.length <= 16 && options.tls.certificateChainDER.every(bytes => bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= 65536) &&
      options.tls.privateKeyDER instanceof Uint8Array && options.tls.privateKeyDER.length > 0 && options.tls.privateKeyDER.length <= 65536, "configuration_capacity");
    let dependency: EnvironmentDependency | undefined, carrier: NodeRawQUICOptions | undefined, chain: Uint8Array[] = [], key: Uint8Array | undefined;
    try {
      carrier = captureNodeRawQUIC(options.carrier, configured => {
        const tlsBytes = BigInt(options.tls.certificateChainDER.reduce((total, bytes) => total + bytes.length, 0) + options.tls.privateKeyDER.length), roots = BigInt((configured.trustRootsDER ?? []).reduce((total, bytes) => total + bytes.length, 0));
        dependency = this.#runtime.admitDependency("tunnel_listener_preparation", new ResourceVector([262144n + tlsBytes + roots + this.#runtime.resources.runtimeBytes,
          tlsBytes + configured.providerRuntimeBytes * BigInt(options.maxPairs + 1) + nativeRawQUICQueueBytes(configured) * BigInt(options.maxPairs), 0n, BigInt(options.maxPairs * 4 + 16), 4n, 4n, 1n, 0n, 0n, 0n, 1n]));
      });
      for (const bytes of options.tls.certificateChainDER) chain.push(new Uint8Array(bytes)); key = new Uint8Array(options.tls.privateKeyDER);
      const leaf = new X509Certificate(chain[0]!), now = this.#runtime.clock.sample(), interval = now.requireInterval(), from = BigInt(leaf.validFromDate.getTime()), until = BigInt(leaf.validToDate.getTime());
      requireCredential(interval.lowerMS >= from && interval.upperMS < until && (isIP(options.serverName) ? leaf.checkIP(options.serverName) === options.serverName : leaf.checkHost(options.serverName, { subject: "never" }) !== undefined), "credential_untrusted");
      this.#deadline = TrustedDeadline.ageAt(this.#runtime.clock, now, options.preparationMS, until); this.#dependency = dependency!; this.#carrier = carrier; this.#chain = Object.freeze(chain); this.#key = key;
      this.#options = Object.freeze({ ...options, carrier, tls: Object.freeze({ certificateChainDER: this.#chain, privateKeyDER: key }) }); this.#done = new Promise(resolve => { this.#resolve = resolve; }); owners.add(this);
      this.#dependency.onClose(() => { void this.close(); }); Object.freeze(this);
    } catch (error) { for (const bytes of chain) bytes.fill(0); for (const bytes of carrier?.trustRootsDER ?? []) bytes.fill(0); key?.fill(0); dependency?.release(); throw error; }
  }
  #check(): void { requireCredential(!this.#closed && !this.#taken && !this.#ended); this.#dependency.check(); this.#deadline.check(); }
  async bind(token: symbol): Promise<void> {
    requireCredential(token === capability && this.#listener === undefined && this.#binding === undefined); this.#check();
    try {
      this.#binding = bindCurrentNativeListener(this.#carrier.nativeCarrier === "webtransport" ? loadCurrentNativeWebTransport() : loadCurrentNativeTransport(), { host: this.#options.host, port: this.#options.port, path: "tunnel", certificateChainDer: this.#chain, privateKeyDer: this.#key,
        inboundBidirectionalStreamCapacity: this.#carrier.applicationStreams + 1, readBufferBytes: Math.min(16384, this.#carrier.streamBufferBytes), datagramQueueBytes: 65536,
        handshakeTimeoutMs: Number(this.#options.handshakeMS), pendingConnections: this.#options.maxPairs }, this.#options.serverName, this.#carrier.webTransport);
      this.#listener = await this.#binding;
      void this.#listener.waitTermination().then(() => { this.#ended = true; void this.close(); this.#cleanup(); }, () => { void this.close(); });
      this.#check(); const actual = this.#listener.address(); requireCredential(actual.host === this.#options.host && actual.port > 0 && actual.port <= 65535 && (this.#options.port === 0 || actual.port === this.#options.port)); this.#address = Object.freeze({ ...actual });
      const tick = (): void => { try { this.#check(); this.#timer = setTimeout(tick, timerChunk(this.#deadline.remainingMS())); } catch { void this.close(); } }; tick();
    } catch (error) { void this.close(); throw error; } finally { this.#binding = undefined; this.#cleanup(); }
  }
  address(): Readonly<{ host: string; port: number }> { this.#check(); requireCredential(this.#address !== undefined); return this.#address; }
  /** Internal single adoption by the configured relay runtime. Exact retained
   * TLS/configuration bytes bind this physical listener; a URL is insufficient. */
  adopt(options: Omit<TunnelListenerPreparationOptions, "preparationMS">, reference: ResourceReference): NativeRawListener {
    this.#check(); requireCredential(this.#listener !== undefined && this.#address !== undefined && this.#dependency.reference.sameEnvironment(reference) && originalEnvironment(options.environment) === this.#runtime &&
      options.host === this.#options.host && options.serverName === this.#options.serverName && (options.port === 0 || options.port === this.#address.port) && options.maxPairs === this.#options.maxPairs && options.handshakeMS === this.#options.handshakeMS &&
      sameNodeRawQUICOptions(options.carrier, this.#carrier) && options.tls.certificateChainDER.length === this.#chain.length &&
      options.tls.certificateChainDER.every((bytes, index) => equalCredential(bytes, this.#chain[index]!)) && equalCredential(options.tls.privateKeyDER, this.#key));
    this.#taken = true; if (this.#timer !== undefined) { clearTimeout(this.#timer); this.#timer = undefined; } return this.#listener;
  }
  close(): Promise<void> {
    if (this.#taken) return Promise.resolve();
    if (!this.#closed) { this.#closed = true; if (this.#timer !== undefined) { clearTimeout(this.#timer); this.#timer = undefined; } if (this.#listener === undefined && this.#binding === undefined) this.#ended = true; }
    this.#listener?.abort(); this.#cleanup(); return this.#done;
  }
  #cleanup(): void {
    if ((!this.#closed && !this.#taken) || !this.#ended || this.#binding !== undefined || this.#released) return; this.#released = true;
    for (const bytes of this.#chain) bytes.fill(0); for (const bytes of this.#carrier.trustRootsDER ?? []) bytes.fill(0); this.#key.fill(0); this.#dependency.release(); this.#resolve();
  }
}
export function isTunnelListenerPreparation(value: unknown): value is TunnelListenerPreparation { return value instanceof TunnelListenerPreparation && owners.has(value); }
export async function prepareTunnelListener(options: TunnelListenerPreparationOptions): Promise<TunnelListenerPreparation> {
  const owner = new TunnelListenerPreparation(capability, options); try { await owner.bind(capability); return owner; } catch (error) { await owner.close(); throw error; }
}
Object.freeze(TunnelListenerPreparation.prototype); Object.freeze(TunnelListenerPreparation);
