import { createRequire } from "node:module";

import {
  CarrierError,
  type NativeCarrierSessionV2,
  type NativeCarrierStreamV2,
} from "../v2/carrier.js";
import type { PathKind } from "../v2/contract.js";

export const NATIVE_TRANSPORT_CONTRACT_VERSION = 1;
const NATIVE_PACKAGE = "@floegence/flowersec-node-native";
const SERVER_PARITY_NATIVE_ADDON = "FLOWERSEC_SERVER_PARITY_NATIVE_ADDON";

export type NativeRawQuicConnectOptions = Readonly<{
  host: string;
  port: number;
  serverName: string;
  path: PathKind;
  trustRootsDer: readonly Uint8Array[];
  inboundBidirectionalStreamCapacity: number;
  handshakeTimeoutMs: number;
}>;

export type NativeRawQuicBindOptions = Readonly<{
  host: string;
  port: number;
  path: PathKind;
  certificateChainDer: readonly Uint8Array[];
  privateKeyDer: Uint8Array;
  inboundBidirectionalStreamCapacity: number;
  handshakeTimeoutMs?: number;
}>;

export type NativeRawQuicListener = Readonly<{
  address(): Readonly<{ host: string; port: number }>;
  accept(options?: Readonly<{ signal?: AbortSignal }>): Promise<NativeCarrierSessionV2>;
  close(): Promise<void>;
}>;

export type NativeRawQuicDriver = Readonly<{
  connectRawQuic(
    options: NativeRawQuicConnectOptions,
    operation?: Readonly<{ signal?: AbortSignal }>,
  ): Promise<NativeCarrierSessionV2>;
  bindRawQuic(options: NativeRawQuicBindOptions): Promise<NativeRawQuicListener>;
}>;

type NativeOperation<T> = Readonly<{
  result(): Promise<T>;
  cancel(): void;
}>;

type NativeRawQuicStreamBinding = Readonly<{
  read(): Promise<Uint8Array | null>;
  write(data: Uint8Array): Promise<number>;
  closeWrite(): Promise<void>;
  stopSending(): Promise<void>;
  reset(): Promise<void>;
  cancelPending?(): void;
  abort(): void;
}>;

type NativeRawQuicSessionBinding = Readonly<{
  kind: "raw_quic";
  path: PathKind;
  inboundBidirectionalStreamCapacity: number;
  maxDatagramSize?: number;
  localAddress(): Readonly<{ host: string; port: number }>;
  peerAddress(): Readonly<{ host: string; port: number }>;
  openStream(): NativeOperation<NativeRawQuicStreamBinding>;
  acceptStream(): NativeOperation<NativeRawQuicStreamBinding>;
  sendDatagram(data: Uint8Array): "accepted" | "dropped_budget" | "dropped_carrier" | "too_large" | "unavailable";
  receiveDatagram(): NativeOperation<Uint8Array>;
  waitTermination(): Promise<void>;
  close(code?: number, reason?: string): Promise<void>;
  abort(): void;
}>;

type NativeRawQuicListenerBinding = Readonly<{
  address(): Readonly<{ host: string; port: number }>;
  accept(): NativeOperation<NativeRawQuicSessionBinding>;
  close(): Promise<void>;
  abort(): void;
}>;

export type NativeTransportAddonBinding = Readonly<{
  contractVersion(): number;
  connectRawQuic(options: NativeRawQuicConnectOptions): NativeOperation<NativeRawQuicSessionBinding>;
  bindRawQuic(options: NativeRawQuicBindOptions): Promise<NativeRawQuicListenerBinding>;
}>;

export type NativeTransportAddon = NativeTransportAddonBinding;

export class NativeTransportUnavailableError extends Error {
  readonly code = "native_transport_unavailable";

  constructor() {
    super("Flowersec native transport is unavailable on this platform");
    this.name = "NativeTransportUnavailableError";
  }
}

type RequireFunction = (specifier: string) => unknown;

export function loadNativeTransportAddon(
  requireFunction: RequireFunction = createRequire(import.meta.url),
): NativeTransportAddonBinding {
  let candidate: unknown;
  try {
    candidate = requireFunction(nativePackageSpecifier());
  } catch {
    throw new NativeTransportUnavailableError();
  }
  if (!isNativeTransportAddon(candidate)) {
    throw new NativeTransportUnavailableError();
  }
  return candidate;
}

function nativePackageSpecifier(): string {
  if (process.env.FLOWERSEC_SERVER_PARITY_PEER === "1") {
    const override = process.env[SERVER_PARITY_NATIVE_ADDON];
    if (override !== undefined && override !== "") return override;
  }
  return NATIVE_PACKAGE;
}

export function tryLoadNativeTransportAddon(
  requireFunction: RequireFunction = createRequire(import.meta.url),
): NativeTransportAddonBinding | undefined {
  try {
    return loadNativeTransportAddon(requireFunction);
  } catch (error) {
    if (error instanceof NativeTransportUnavailableError) return undefined;
    throw error;
  }
}

export function createNativeRawQuicDriver(
  addon: NativeTransportAddonBinding = loadNativeTransportAddon(),
): NativeRawQuicDriver {
  return Object.freeze({
    async connectRawQuic(options, operation = {}) {
      const native = await settle(addon.connectRawQuic(options), operation.signal);
      return wrapSession(native);
    },
    async bindRawQuic(options) {
      const native = await addon.bindRawQuic(options);
      return Object.freeze({
        address: () => native.address(),
        accept: async (operation = {}) =>
          wrapSession(await settle(native.accept(), operation.signal)),
        async close() {
          await native.close();
        },
      });
    },
  });
}

function isNativeTransportAddon(value: unknown): value is NativeTransportAddonBinding {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<NativeTransportAddonBinding>;
  let contractVersion: number;
  try {
    contractVersion = typeof candidate.contractVersion === "function"
      ? candidate.contractVersion()
      : -1;
  } catch {
    return false;
  }
  return contractVersion === NATIVE_TRANSPORT_CONTRACT_VERSION &&
    typeof candidate.connectRawQuic === "function" &&
    typeof candidate.bindRawQuic === "function";
}

function wrapSession(native: NativeRawQuicSessionBinding): NativeCarrierSessionV2 {
  const unreliableDatagrams = native.maxDatagramSize === undefined
    ? undefined
    : Object.freeze({
        maxDatagramSize: native.maxDatagramSize,
        async send(
          data: Uint8Array,
          options: Readonly<{ signal?: AbortSignal; expiresAt?: number }> = {},
        ) {
          throwIfAborted(options.signal);
          if (options.expiresAt !== undefined && options.expiresAt <= Date.now()) {
            return "dropped_expired" as const;
          }
          const outcome = native.sendDatagram(data);
          switch (outcome) {
            case "accepted":
            case "dropped_budget":
            case "dropped_carrier":
              return outcome;
            case "too_large":
              throw new CarrierError("datagram_unavailable", "raw QUIC datagram exceeds the negotiated payload limit");
            case "unavailable":
              throw new CarrierError("datagram_unavailable", "raw QUIC datagrams are unavailable");
          }
        },
        async receive(options: Readonly<{ signal?: AbortSignal }> = {}) {
          return await settle(native.receiveDatagram(), options.signal);
        },
      });
  return Object.freeze({
    kind: native.kind,
    path: native.path,
    inboundBidirectionalStreamCapacity: native.inboundBidirectionalStreamCapacity,
    ...(unreliableDatagrams === undefined ? {} : { unreliableDatagrams }),
    async openStream(options = {}) {
      return wrapStream(await settle(native.openStream(), options.signal));
    },
    async acceptStream(options = {}) {
      return wrapStream(await settle(native.acceptStream(), options.signal));
    },
    async waitTermination() {
      await native.waitTermination();
    },
    async close(error) {
      await native.close(error?.code, error?.reason);
    },
    abort() {
      native.abort();
    },
  });
}

function wrapStream(native: NativeRawQuicStreamBinding): NativeCarrierStreamV2 {
  return Object.freeze({
    read: async () => await nativeStreamCall(native.read()),
    write: async (data) => await nativeStreamCall(native.write(data)),
    closeWrite: async () => await nativeStreamCall(native.closeWrite()),
    stopSending: async () => await nativeStreamCall(native.stopSending()),
    reset: async () => await nativeStreamCall(native.reset()),
    cancelPending: () => native.cancelPending?.(),
    abort: () => native.abort(),
  });
}

async function nativeStreamCall<T>(operation: Promise<T>): Promise<T> {
  try {
    return await operation;
  } catch (error) {
    const reason = error instanceof Error ? error.message : "";
    switch (reason) {
      case "reset": throw new CarrierError("reset", "raw QUIC stream reset", error);
      case "canceled": throw new CarrierError("aborted", "raw QUIC stream operation canceled", error);
      case "closed": throw new CarrierError("closed", "raw QUIC stream closed", error);
      default: throw error;
    }
  }
}

async function settle<T>(operation: NativeOperation<T>, signal?: AbortSignal): Promise<T> {
  if (signal?.aborted === true) {
    operation.cancel();
    throw new CarrierError("aborted", "native transport operation aborted");
  }
  if (signal === undefined) return await operation.result();
  return await new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener("abort", abort);
    const abort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      operation.cancel();
      reject(new CarrierError("aborted", "native transport operation aborted"));
    };
    signal.addEventListener("abort", abort, { once: true });
    void operation.result().then(
      (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      },
      (error) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      },
    );
  });
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) {
    throw new CarrierError("aborted", "native transport operation aborted");
  }
}
