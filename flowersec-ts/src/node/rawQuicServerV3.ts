import { adaptNativeCarrierSessionV3, type CarrierSessionV3 } from "../v3/carrier.js";
import type { PathKind } from "../v3/contract.js";
import { createNativeWebTransportDriver, loadNativeTransportAddon, NativeTransportUnavailableError, type NativeRawQuicDriver, type NativeRawQuicListener } from "./nativeTransportAddon.js";
import { boundIngressURL } from "./listenerIngress.js";
import { validOrigin } from "./webSocketServerV3.js";
import { normalizeCertificateChain, normalizePrivateKey } from "./rawQuicTls.js";

export type NodeRawQuicListenerOptionsV3 = Readonly<{
  host: string;
  port: number;
  path: PathKind;
  tls: Readonly<{ certificate: string | Uint8Array; privateKey: string | Uint8Array }>;
  inboundBidirectionalStreamCapacity: number;
}>;

export type NodeRawQuicListenerV3 = Readonly<{
  address(): Readonly<{ host: string; port: number }>;
  accept(options?: Readonly<{ signal?: AbortSignal }>): Promise<CarrierSessionV3>;
  close(): Promise<void>;
}>;

export async function startNodeRawQuicListenerV3(
  driver: NativeRawQuicDriver,
  options: NodeRawQuicListenerOptionsV3,
): Promise<NodeRawQuicListenerV3> {
  validateOptions(options);
  let listener: NativeRawQuicListener;
  try {
    listener = await driver.bindRawQuic({
      host: options.host,
      port: options.port,
      path: options.path,
      certificateChainDer: normalizeCertificateChain(options.tls.certificate),
      privateKeyDer: normalizePrivateKey(options.tls.privateKey),
      inboundBidirectionalStreamCapacity: options.inboundBidirectionalStreamCapacity,
    });
  } catch (error) {
    if (error instanceof TypeError) throw error;
    throw new Error("Flowersec raw QUIC v5 listener failed to bind");
  }
  return Object.freeze({
    address: () => listener.address(),
    accept: async (operation = {}) => adaptNativeCarrierSessionV3(await listener.accept(operation)),
    close: async () => await listener.close(),
  });
}

export type NodeWebTransportListenerConfig = Readonly<{
  carrier: "webtransport"; host: string; port: number; publicURL?: string;
  tls: NodeRawQuicListenerOptionsV3["tls"]; allowedOrigins: readonly string[];
}>;

export function validateWebTransportListeners(listeners: readonly { carrier: string }[]): void {
  if (listeners.some(listener => listener.carrier === "webtransport" && "profile" in listener)) throw new TypeError("WebTransport listener profile was removed; omit profile for draft02 or configure a raw_quic listener for Go clients");
}

export async function startNodeWebTransportListener(options: NodeWebTransportListenerConfig & NodeRawQuicListenerOptionsV3): Promise<NodeRawQuicListenerV3> {
  validateOptions(options);
  if (!Array.isArray(options.allowedOrigins) || options.allowedOrigins.length < 1 || options.allowedOrigins.length > 64 ||
      new Set(options.allowedOrigins).size !== options.allowedOrigins.length || !options.allowedOrigins.every(validOrigin)) throw new TypeError("invalid WebTransport Origin policy");
  const url = new URL(boundIngressURL(options.path, "webtransport", { host: options.host, port: options.port || 443 }, options.publicURL));
  const driver = createNativeWebTransportDriver(loadNativeTransportAddon());
  if (driver === undefined) throw new NativeTransportUnavailableError();
  const listener = await driver.bind({ host: options.host, port: options.port, path: options.path, authorityHost: url.hostname,
    allowedOrigins: [...options.allowedOrigins], certificateChainDer: normalizeCertificateChain(options.tls.certificate),
    privateKeyDer: normalizePrivateKey(options.tls.privateKey), inboundBidirectionalStreamCapacity: options.inboundBidirectionalStreamCapacity });
  try {
    if (options.publicURL !== undefined && listener.address().port !== Number(url.port || 443)) throw new TypeError("WebTransport publicURL must use the bound port");
    return Object.freeze({ address: () => listener.address(), close: () => listener.close(),
      accept: async (operation = {}) => adaptNativeCarrierSessionV3(await listener.accept(operation)) });
  } catch (error) { await listener.close(); throw error; }
}

function validateOptions(options: NodeRawQuicListenerOptionsV3): void {
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65_535 ||
      !Number.isInteger(options.inboundBidirectionalStreamCapacity) ||
      options.inboundBidirectionalStreamCapacity < 3 || options.inboundBidirectionalStreamCapacity > 130 ||
      options.tls.certificate.length === 0 || options.tls.privateKey.length === 0) {
    throw new TypeError("invalid Node raw QUIC v5 listener options");
  }
}
