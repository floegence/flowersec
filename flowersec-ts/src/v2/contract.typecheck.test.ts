import type {
  ByteStreamV2,
  CarrierKind,
  IncomingStreamV2,
  JsonObjectV2,
  PathKind,
  SessionV2,
  StreamOpenOptionsV2,
} from "./contract.js";
import type {
  CarrierSessionV2,
  CarrierStreamV2,
  NativeCarrierSessionV2,
  NativeCarrierStreamV2,
  WebSocketBinaryTransportV2,
  WebSocketResourcePolicyV2,
} from "./carrier.js";
import { expect, test } from "vitest";

type Assert<T extends true> = T;
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;

// eslint-disable-next-line @typescript-eslint/no-unused-vars
type _CarrierKindsAreFrozen = Assert<Equal<CarrierKind, "websocket" | "raw_quic" | "webtransport">>;
// eslint-disable-next-line @typescript-eslint/no-unused-vars
type _PathKindsAreFrozen = Assert<Equal<PathKind, "direct" | "tunnel">>;
// eslint-disable-next-line @typescript-eslint/no-unused-vars
type _CarrierCapacityIsRequired = Assert<Equal<CarrierSessionV2["inboundBidirectionalStreamCapacity"], number>>;
// eslint-disable-next-line @typescript-eslint/no-unused-vars
type _NativeCarrierCapacityIsRequired = Assert<Equal<NativeCarrierSessionV2["inboundBidirectionalStreamCapacity"], number>>;

function typecheckCarrierContract(
  carrier: CarrierSessionV2,
  carrierStream: CarrierStreamV2,
  native: NativeCarrierSessionV2,
  nativeStream: NativeCarrierStreamV2,
  binary: WebSocketBinaryTransportV2,
  policy: WebSocketResourcePolicyV2,
): void {
  const carrierCapacity: number = carrier.inboundBidirectionalStreamCapacity;
  const nativeCapacity: number = native.inboundBidirectionalStreamCapacity;
  void carrierCapacity;
  void nativeCapacity;
  void carrierStream;
  void nativeStream;
  void binary;
  void policy;

  // @ts-expect-error v2 carrier contracts never expose concrete Yamux sessions.
  void carrier.yamux;
  // @ts-expect-error physical stream capacity is a carrier property, not a Yamux policy field.
  void policy.maxInboundStreams;
}

function typecheckContract(
  session: SessionV2,
  stream: ByteStreamV2,
  incoming: IncomingStreamV2,
  metadata: JsonObjectV2,
  openOptions: StreamOpenOptionsV2,
): void {
  const path: PathKind = session.path;
  // @ts-expect-error carrier selection is an internal diagnostic, not session API.
  void session.chosenCarrier;
  const peerID: string | undefined = session.endpointInstanceId;
  const streamID: bigint = stream.id;
  const streamKind: string = stream.kind;
  const incomingID: bigint = incoming.id;
  const incomingKind: string = incoming.kind;
  const incomingMetadata: JsonObjectV2 = incoming.metadata;
  const incomingStream: ByteStreamV2 = incoming.stream;

  void path;
  void peerID;
  void streamID;
  void streamKind;
  void incomingID;
  void incomingKind;
  void incomingMetadata;
  void incomingStream;
  void metadata;
  void openOptions;

  void session.openStream("rpc", { metadata, signal: new AbortController().signal });
  void session.acceptStream({ signal: new AbortController().signal });
  void session.rekey({ signal: new AbortController().signal });
  void session.probeLiveness({ signal: new AbortController().signal });
  void session.close();
  void session.termination;
  void session.waitClosed();

  void stream.read({ signal: new AbortController().signal });
  void stream.write(new Uint8Array([1]), { signal: new AbortController().signal });
  void stream.closeWrite();
  void stream.reset();
  void stream.close();
  void stream.terminalError;

  // @ts-expect-error v2 streams never expose carrier-specific Yamux handles.
  void stream.yamuxStream;
  // @ts-expect-error v2 streams never expose carrier-specific QUIC handles.
  void stream.quicStream;
  // @ts-expect-error SessionV2 does not expose the v1 SecureChannel.
  void session.secure;
  // @ts-expect-error SessionV2 does not expose the v1 mux implementation.
  void session.mux;
}

test("keeps the v2 contract available for compile-time checks", () => {
  expect(typecheckContract).toBeTypeOf("function");
  expect(typecheckCarrierContract).toBeTypeOf("function");
});
