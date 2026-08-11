import type { CarrierSessionV2 } from "../v2/carrier.js";
import { adaptNativeCarrierSessionV2 } from "../v2/carrier.js";
import type { PathKind } from "../v2/contract.js";
import type {
  NativeRawQuicDriver,
  NativeRawQuicListener,
} from "./nativeTransportAddon.js";
import { normalizeCertificateChain, normalizePrivateKey } from "./rawQuicAdapter.js";

export type NodeRawQuicServerOptions = Readonly<{
  host: string;
  port: number;
  path: PathKind;
  tls: Readonly<{ certificate: string | Uint8Array; privateKey: string | Uint8Array }>;
  inboundBidirectionalStreamCapacity: number;
}>;

export type NodeRawQuicServer = Readonly<{
  address(): Readonly<{ host: string; port: number }>;
  accept(options?: Readonly<{ signal?: AbortSignal }>): Promise<CarrierSessionV2>;
  close(): Promise<void>;
}>;

export async function startNodeRawQuicServer(
  driver: NativeRawQuicDriver,
  options: NodeRawQuicServerOptions,
): Promise<NodeRawQuicServer> {
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
    throw new Error("Flowersec raw QUIC listener failed to bind");
  }
  return {
    address: () => listener.address(),
    accept: async (operation = {}) =>
      adaptNativeCarrierSessionV2(await listener.accept(operation)),
    close: async () => await listener.close(),
  };
}

function validateOptions(options: NodeRawQuicServerOptions): void {
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65_535 ||
    !Number.isInteger(options.inboundBidirectionalStreamCapacity) ||
    options.inboundBidirectionalStreamCapacity < 3 ||
    options.inboundBidirectionalStreamCapacity > 130) {
    throw new TypeError("invalid Node raw QUIC listener options");
  }
  if (options.tls.certificate.length === 0 || options.tls.privateKey.length === 0) {
    throw new TypeError("raw QUIC listener requires explicit TLS material");
  }
}
