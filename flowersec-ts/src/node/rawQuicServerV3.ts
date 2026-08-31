import { adaptNativeCarrierSessionV3, type CarrierSessionV3 } from "../v3/carrier.js";
import type { PathKind } from "../v3/contract.js";
import type { NativeRawQuicDriver, NativeRawQuicListener } from "./nativeTransportAddon.js";
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
    throw new Error("Flowersec raw QUIC v3 listener failed to bind");
  }
  return Object.freeze({
    address: () => listener.address(),
    accept: async (operation = {}) => adaptNativeCarrierSessionV3(await listener.accept(operation)),
    close: async () => await listener.close(),
  });
}

function validateOptions(options: NodeRawQuicListenerOptionsV3): void {
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65_535 ||
      !Number.isInteger(options.inboundBidirectionalStreamCapacity) ||
      options.inboundBidirectionalStreamCapacity < 3 || options.inboundBidirectionalStreamCapacity > 130 ||
      options.tls.certificate.length === 0 || options.tls.privateKey.length === 0) {
    throw new TypeError("invalid Node raw QUIC v3 listener options");
  }
}
