import { RpcClient } from "../rpc/client.js";
import { RpcRouter, RpcServer, type RpcServerOptions } from "../rpc/server.js";

import type {
  ByteStreamV2,
  IncomingStreamV2,
  JsonObjectV2,
  OperationOptionsV2,
  PathKind,
  StreamOpenOptionsV2,
  SessionV2 as SessionV2Contract,
  SessionTerminationV2,
} from "./contract.js";
import type { CarrierSessionV2, CarrierStreamV2 } from "./carrier.js";
import type { SessionContractV2 } from "./artifact.js";
import {
  computeClientConfirmV2,
  computeHandshakeH0V2,
  computeHandshakeH1V2,
  computeHandshakeH2V2,
  computeHandshakeH3V2,
  computeServerConfirmV2,
  computeSharedSecretV2,
  decodeClientFinishedV2,
  decodeClientInitV2,
  decodeHandshakeFrameV2,
  decodeServerFinishedV2,
  deriveHandshakePRKV2,
  deriveSessionPRKV2,
  encodeClientFinishedCoreV2,
  encodeClientFinishedV2,
  encodeClientInitV2,
  encodeControlPrefaceV2,
  encodeServerFinishedCoreV2,
  encodeServerFinishedV2,
  generateEphemeralKeyV2,
  parseControlPrefaceV2,
  validateClientInitV2,
  validateServerFinishedV2,
  type HandshakeExpectationsV2,
} from "./handshake.js";
import {
  DirectionV2,
  InnerTypeV2,
  computeFSS2HashV2,
  computeOpenHashV2,
  computeSetupMAC,
  decodeInnerRecordV2,
  decodeOpenACKV2,
  decodeOpenPayload,
  decodeOpenRejectV2,
  decodeRecordHeader,
  decodeSetupPrefaceV2,
  decodeStreamKeyUpdateACKV2,
  deriveControlMaterial,
  deriveEpochZero,
  deriveEpochRoots,
  deriveNextEpoch,
  deriveStreamMaterial,
  encodeInnerRecordV2,
  encodeOpenACKV2,
  encodeOpenPayload,
  encodeOpenRejectV2,
  encodeRecordHeader,
  encodeSetupPreface,
  encodeStreamKeyUpdateACKV2,
  openRecord,
  sealRecord,
  verifySetupMAC,
  type EpochRootsV2,
  type RecordHeaderV2,
  type CipherSuiteV2,
} from "./protocol.js";
import {
  StreamLifetimeLedgerV2,
  StreamLifetimeLedgerV2Error,
  maxLogicalStreamIDV2,
} from "./streamLifetimeLedger.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const MAX_DATA_BYTES = 16_384;
const MAX_BUFFERED_STREAM_BYTES = 4 * 1024 * 1024;
const RESERVED_RPC_KIND = "flowersec.rpc.v2";
const DEFAULT_IDLE_TIMEOUT_MS = 60_000;
const DEFAULT_CLOSE_TIMEOUT_MS = 5_000;

export type SessionRoleV2 = "client" | "server";

export type SessionDeadlinePhaseV2 = "establish" | "rekey_prepare" | "rekey_completion";

export type SessionDeadlineHandleV2 = Readonly<{
  signal: AbortSignal;
  cancel(): void;
}>;

export type SessionDeadlineFactoryV2 = (
  timeoutMs: number,
  phase: SessionDeadlinePhaseV2,
) => SessionDeadlineHandleV2;

export type SessionDeadlinesV2 = Readonly<{
  establishTimeoutMs: number;
  rekeyPrepareTimeoutMs: number;
  rekeyCompletionTimeoutMs: number;
  factory?: SessionDeadlineFactoryV2;
}>;

export type SessionConfigV2 = Readonly<{
  role: SessionRoleV2;
  path: PathKind;
  channelID: string;
  sessionContractHash: Uint8Array;
  suite: CipherSuiteV2;
  psk: Uint8Array;
  maxInboundStreams: number;
  localAdmissionBinding: Uint8Array;
  peerAdmissionBinding: Uint8Array;
  /** Required by admitted APIs to bind runtime limits and keys to the signed contract. */
  sessionContract?: SessionContractV2;
  localEndpointInstanceID: string;
  expectedPeerEndpointInstanceID: string;
  rpcRouter?: RpcRouter;
  rpcServerOptions?: RpcServerOptions;
  deadlines?: SessionDeadlinesV2;
  idleTimeoutMs?: number;
  closeTimeoutMs?: number;
}>;

export class SessionV2Error extends Error {
  constructor(
    readonly code:
      | "aborted"
      | "closed"
      | "going_away"
      | "handshake"
      | "open_rejected"
      | "protocol"
      | "resource_exhausted"
      | "timeout",
    message: string,
  ) {
    super(message);
    this.name = "SessionV2Error";
  }
}

type HandshakeMaterial = Readonly<{ h3: Uint8Array; sessionPRK: Uint8Array }>;

export async function establishSessionV2(
  carrier: CarrierSessionV2,
  config: SessionConfigV2,
  options: OperationOptionsV2 = {},
): Promise<SessionV2> {
  validateConfig(carrier, config);
  const establishDeadline = createSessionDeadline(config, "establish");
  const establishSignal = combineSignals(options.signal, establishDeadline.signal);
  throwIfAborted(establishSignal.signal);
  let control: CarrierStreamV2 | undefined;
  try {
    control = config.role === "client"
      ? await carrier.openStream(signalOptions(establishSignal.signal))
      : await carrier.acceptStream(signalOptions(establishSignal.signal));
    const reader = new ExactReader(control);
    const material = config.role === "client"
      ? await clientHandshake(control, reader, config, establishSignal.signal)
      : await serverHandshake(control, reader, config, establishSignal.signal);
    const session = new SessionV2(carrier, control, reader, config, material);
    await session.finishReadyBoundary();
    session.start();
    return session;
  } catch (error) {
    control?.abort(asError(error));
    carrier.abort({ code: 6, reason: "handshake failed" });
    if (error instanceof SessionV2Error) throw error;
    throw new SessionV2Error("handshake", `Flowersec v2 handshake failed: ${errorMessage(error)}`);
  } finally {
    establishSignal.cancel();
    establishDeadline.cancel();
  }
}

export class SessionV2 implements SessionV2Contract {
  readonly path: PathKind;
  readonly chosenCarrier: CarrierSessionV2["kind"];
  readonly endpointInstanceId: string | undefined;
  readonly rpc: RpcClient;
  readonly termination: Promise<SessionTerminationV2>;
  terminalError: Error | undefined;

  private readonly role: 1 | 2;
  private readonly sendDirection: DirectionV2;
  private readonly receiveDirection: DirectionV2;
  private readonly h3: Uint8Array;
  private readonly sendRoots = new Map<number, EpochRootsV2>();
  private readonly receiveRoots = new Map<number, EpochRootsV2>();
  private sendEpoch = 0;
  private receiveEpoch = 0;
  private controlSendEpoch = 0;
  private controlSendSequence = 0n;
  private controlReceiveEpoch = 0;
  private controlReceiveSequence = 0n;
  private controlWriteTail: Promise<void> = Promise.resolve();
  private nextLogicalID: bigint;
  private receivedGoAway = false;
  private receivedGoAwayLastAccepted = 0n;
  private receivedGoAwayReason = 0;
  private sentGoAway = false;
  private sentGoAwayLastAccepted = 0n;
  private sentGoAwayReason = 0;
  private closePromise: Promise<void> | undefined;
  private readonly streams = new Map<bigint, EncryptedStreamV2>();
  private readonly peerLedger: StreamLifetimeLedgerV2;
  private readonly outboundLedger: StreamLifetimeLedgerV2;
  private readonly incoming = new AsyncQueue<IncomingStreamV2>();
  private readonly outboundPermits: AsyncSemaphore;
  private readonly inboundPermits: AsyncSemaphore;
  private readonly pings = new Map<bigint, Deferred<void>>();
  private nextPing = 1n;
  private readonly rpcActivation = deferred<void>();
  private rpcStreamPromise: Promise<EncryptedStreamV2> | undefined;
  private rpcServing = false;
  private rekeyTail: Promise<void> = Promise.resolve();
  private nextTransition = 1n;
  private receiveTransition = 0n;
  private pendingSessionRekey: Readonly<{
    payload: Uint8Array;
    epoch: number;
    acknowledged: Deferred<void>;
    committed: { value: boolean };
  }> | undefined;
  private lastSessionRekeyACK: Uint8Array | undefined;
  private preparingSendEpoch: number | undefined;
  private pendingReceiveEpoch: number | undefined;
  private openFrozen = false;
  private openGate = deferred<void>();
  private outboundFrontierChanged = deferred<void>();
  private activeInboundResponders = 0;
  private localResponderFrozen = false;
  private peerResponderFrozen = false;
  private responderChanged = deferred<void>();
  private idleWatchdogStarted = false;
  private idleTimer: ReturnType<typeof setTimeout> | undefined;
  private readonly terminationState = deferred<SessionTerminationV2>();

  constructor(
    private readonly carrier: CarrierSessionV2,
    private readonly control: CarrierStreamV2,
    private readonly controlReader: ExactReader,
    private readonly config: SessionConfigV2,
    material: HandshakeMaterial,
  ) {
    this.path = config.path;
    this.termination = this.terminationState.promise;
    this.chosenCarrier = carrier.kind;
    this.endpointInstanceId = config.path === "tunnel" ? config.expectedPeerEndpointInstanceID : undefined;
    this.role = config.role === "client" ? 1 : 2;
    this.sendDirection = this.role === 1 ? DirectionV2.ClientToServer : DirectionV2.ServerToClient;
    this.receiveDirection = this.role === 1 ? DirectionV2.ServerToClient : DirectionV2.ClientToServer;
    this.nextLogicalID = this.role === 1 ? 1n : 2n;
    this.peerLedger = new StreamLifetimeLedgerV2(this.role === 1 ? 2 : 1);
    this.outboundLedger = new StreamLifetimeLedgerV2(this.role);
    this.h3 = material.h3.slice();
    this.sendRoots.set(0, deriveEpochZero(material.sessionPRK, this.sendDirection));
    this.receiveRoots.set(0, deriveEpochZero(material.sessionPRK, this.receiveDirection));
    this.outboundPermits = new AsyncSemaphore(config.maxInboundStreams);
    this.inboundPermits = new AsyncSemaphore(config.maxInboundStreams);
    const rpcReadState = { reader: undefined as ExactReader | undefined };
    this.rpc = new RpcClient(
      async (length) => {
        await this.rpcActivation.promise;
        const stream = await this.ensureRPCStream();
        rpcReadState.reader ??= new ExactReader(stream);
        return await rpcReadState.reader.readExactly(length);
      },
      async (payload) => {
        this.rpcActivation.resolve();
        const stream = await this.ensureRPCStream();
        await stream.write(payload);
      },
      { onTerminal: (error) => this.fail(error) },
    );
  }

  async openStream(kind: string, options: StreamOpenOptionsV2 = {}): Promise<ByteStreamV2> {
    if (kind === RESERVED_RPC_KIND) throw new SessionV2Error("open_rejected", "reserved RPC stream kind");
    return await this.openLogicalStream(kind, options, false);
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<IncomingStreamV2> {
    this.assertOpen();
    return await this.incoming.shift(options.signal);
  }

  async probeLiveness(options: OperationOptionsV2 = {}): Promise<number> {
    this.assertOpen();
    throwIfAborted(options.signal);
    const nonce = this.nextPing++;
    const pending = deferred<void>();
    this.pings.set(nonce, pending);
    const started = performance.now();
    try {
      await this.sendControl(InnerTypeV2.Ping, u64(nonce));
      await raceAbort(pending.promise, options.signal);
      return performance.now() - started;
    } finally {
      this.pings.delete(nonce);
    }
  }

  async rekey(options: OperationOptionsV2 = {}): Promise<void> {
    throwIfAborted(options.signal);
    const task = this.rekeyTail.then(async () => {
      throwIfAborted(options.signal);
      await this.rekeyOnce(options);
    });
    this.rekeyTail = task.catch(() => undefined);
    await raceAbort(task, options.signal);
  }

  close(): Promise<void> {
    this.closePromise ??= this.closeOnce();
    return this.closePromise;
  }

  async finishReadyBoundary(): Promise<void> {
    if (this.config.role === "server") {
      await this.sendControl(InnerTypeV2.SessionReady, new Uint8Array());
      const ready = await this.readControl();
      if (ready.type !== InnerTypeV2.SessionReadyACK) throw protocolError("expected SESSION_READY_ACK");
      return;
    }
    const ready = await this.readControl();
    if (ready.type !== InnerTypeV2.SessionReady) throw protocolError("expected SESSION_READY");
    await this.sendControl(InnerTypeV2.SessionReadyACK, new Uint8Array());
  }

  start(): void {
    this.startIdleWatchdog();
    void this.controlLoop();
    void this.acceptCarrierLoop();
  }

  rootForSend(epoch: number): EpochRootsV2 {
    const roots = this.sendRoots.get(epoch);
    if (roots === undefined) throw protocolError("missing send epoch roots");
    return roots;
  }

  rootForReceive(epoch: number): EpochRootsV2 {
    const roots = this.receiveRoots.get(epoch);
    if (roots === undefined) throw protocolError("missing receive epoch roots");
    return roots;
  }

  hasReceiveRoots(epoch: number): boolean {
    return this.receiveRoots.has(epoch);
  }

  installReceiveRoots(epoch: number, roots: EpochRootsV2): void {
    const existing = this.receiveRoots.get(epoch);
    if (existing !== undefined && !bytesEqual(existing.epochSecret, roots.epochSecret)) {
      throw protocolError("conflicting receive epoch roots");
    }
    this.receiveRoots.set(epoch, roots);
  }

  transcriptHash(): Uint8Array {
    return this.h3;
  }

  receiveDirectionValue(): DirectionV2 {
    return this.receiveDirection;
  }

  async sendStreamRecord(
    stream: EncryptedStreamV2,
    type: InnerTypeV2,
    payload: Uint8Array,
    signal?: AbortSignal,
  ): Promise<void> {
    const inner = encodeInnerRecordV2(type, payload);
    const roots = this.rootForSend(stream.sendEpoch);
    const material = deriveStreamMaterial(roots.streamRoot, this.h3, stream.id, this.sendDirection, stream.sendEpoch);
    const header: RecordHeaderV2 = {
      epoch: stream.sendEpoch,
      sequence: stream.sendSequence,
      ciphertextLength: inner.length + 16,
    };
    const ciphertext = sealRecord(this.config.suite, material, this.h3, stream.id, this.sendDirection, header, inner);
    stream.sendSequence += 1n;
    await writeAll(stream.carrier, encodeRecordHeader(header), signal);
    await writeAll(stream.carrier, ciphertext, signal);
    this.markAuthenticatedActivity();
  }

  async readStreamRecord(stream: EncryptedStreamV2): Promise<Readonly<{
    type: InnerTypeV2;
    payload: Uint8Array;
    header: RecordHeaderV2;
  }>> {
    const header = decodeRecordHeader(await stream.reader.readExactly(24));
    const priorACK = stream.priorACK !== undefined &&
      header.epoch === stream.priorACK.epoch && header.sequence === stream.priorACK.sequence;
    if (!priorACK && (header.epoch !== stream.receiveEpoch || header.sequence !== stream.receiveSequence)) {
      throw protocolError("unexpected stream epoch or sequence");
    }
    const roots = this.rootForReceive(header.epoch);
    const material = deriveStreamMaterial(roots.streamRoot, this.h3, stream.id, this.receiveDirection, header.epoch);
    const ciphertext = await stream.reader.readExactly(header.ciphertextLength);
    const inner = decodeInnerRecordV2(openRecord(
      this.config.suite,
      material,
      this.h3,
      stream.id,
      this.receiveDirection,
      header,
      ciphertext,
    ));
    if (priorACK) {
      if (inner.type !== InnerTypeV2.StreamKeyUpdateACK) throw protocolError("late old-epoch record is not rekey ACK");
      stream.priorACK = undefined;
      this.cleanupEpochRoots();
    } else {
      stream.receiveSequence += 1n;
    }
    this.markAuthenticatedActivity();
    return { ...inner, header };
  }

  async localReset(stream: EncryptedStreamV2, error: Error): Promise<void> {
    if (!stream.markTerminal(error)) return;
    await stream.carrier.reset().catch(() => undefined);
    try {
      await this.sendControl(InnerTypeV2.StreamReset, idReason(stream.id, 6));
      this.commitLocalReset(stream.id);
    } catch (cause) {
      this.fail(asError(cause));
    }
    this.releaseStream(stream);
  }

  releaseStream(stream: EncryptedStreamV2): void {
    if (this.streams.get(stream.id) !== stream) return;
    this.streams.delete(stream.id);
    stream.releasePermit();
    this.cleanupEpochRoots();
  }

  private async openLogicalStream(
    kind: string,
    options: StreamOpenOptionsV2,
    internal: boolean,
  ): Promise<EncryptedStreamV2> {
    this.assertOpen();
    throwIfAborted(options.signal);
    await this.waitOpenGate(options.signal);
    const releasePermit = internal ? () => undefined : await this.outboundPermits.acquire(options.signal);
    let stream: EncryptedStreamV2 | undefined;
    let carrierStream: CarrierStreamV2 | undefined;
    let id: bigint | undefined;
    let ledgerAllocated = false;
    try {
      this.assertOpen();
      await this.waitOpenGate(options.signal);
      if (this.sentGoAway || this.receivedGoAway) throw new SessionV2Error("going_away", "session is going away");
      id = this.nextLogicalID;
      if (id > maxLogicalStreamIDV2(this.role)) {
        await this.sendGoAway(5);
        throw new SessionV2Error("resource_exhausted", "logical stream lifetime ledger exhausted");
      }
      this.nextLogicalID += 2n;
      const setupAction = this.outboundLedger.validFSS2(id);
      ledgerAllocated = true;
      if (setupAction === "reset") {
        this.notifyOutboundFrontierChanged();
        throw new SessionV2Error("closed", "logical stream identity was already reset by peer");
      }
      carrierStream = await this.carrier.openStream(options);
      if (!this.localOpeningAllowedAfterGoAway(id)) {
        throw new SessionV2Error("going_away", "logical stream is beyond the peer GOAWAY boundary");
      }
      const roots = this.rootForSend(this.sendEpoch);
      const unsigned = {
        openerRole: this.role,
        logicalStreamID: id,
        initialSendEpoch: this.sendEpoch,
        setupMAC: new Uint8Array(32),
      } as const;
      const prefaceRaw = encodeSetupPreface({
        ...unsigned,
        setupMAC: computeSetupMAC(roots.setupRoot, this.h3, unsigned),
      });
      await writeAll(carrierStream, prefaceRaw, options.signal);
      if (!this.localOpeningAllowedAfterGoAway(id)) {
        throw new SessionV2Error("going_away", "logical stream is beyond the peer GOAWAY boundary");
      }
      const metadata = encodeMetadata(options.metadata ?? {});
      const openRaw = encodeOpenPayload({
        logicalStreamID: id,
        fss2Hash: computeFSS2HashV2(prefaceRaw),
        kind,
        metadata,
      });
      stream = new EncryptedStreamV2(
        this,
        carrierStream,
        id,
        kind,
        this.sendEpoch,
        this.receiveEpoch,
        releasePermit,
      );
      this.streams.set(id, stream);
      stream.setOpenHash(computeOpenHashV2(openRaw));
      await stream.send(InnerTypeV2.Open, openRaw, options.signal);
      stream.startPump();
      await raceAbort(stream.opened.promise, options.signal);
      if (!this.localOpeningAllowedAfterGoAway(id)) {
        throw new SessionV2Error("going_away", "logical stream is beyond the peer GOAWAY boundary");
      }
      return stream;
    } catch (error) {
      if (stream !== undefined) await this.localReset(stream, asError(error));
      else {
        await carrierStream?.reset().catch(() => undefined);
        if (id !== undefined && ledgerAllocated) {
          await this.commitOutboundReset(id).catch((cause) => this.fail(asError(cause)));
        }
        releasePermit();
      }
      throw error;
    }
  }

  private ensureRPCStream(): Promise<EncryptedStreamV2> {
    this.rpcActivation.resolve();
    this.rpcStreamPromise ??= this.openLogicalStream(RESERVED_RPC_KIND, {}, true);
    return this.rpcStreamPromise;
  }

  private async acceptCarrierLoop(): Promise<void> {
    try {
      while (this.terminalError === undefined) {
        const carrierStream = await this.carrier.acceptStream();
        void this.acceptCarrierStream(carrierStream).catch((error) => {
          void carrierStream.reset();
          if (error instanceof StreamLifetimeLedgerV2Error && error.code === "duplicate") {
            this.fail(protocolError(error.message));
          }
        });
      }
    } catch (error) {
      if (this.terminalError === undefined) this.fail(asError(error));
    }
  }

  private async acceptCarrierStream(carrierStream: CarrierStreamV2): Promise<void> {
    let responderHeld = false;
    let ledgerID: bigint | undefined;
    try {
      await this.enterInboundResponder();
      responderHeld = true;
      const reader = new ExactReader(carrierStream);
      let prefaceRaw: Uint8Array;
      let preface: ReturnType<typeof decodeSetupPrefaceV2>;
      prefaceRaw = await reader.readExactly(56);
      preface = decodeSetupPrefaceV2(prefaceRaw);
      const peerRole = this.role === 1 ? 2 : 1;
      if (preface.openerRole !== peerRole || preface.initialSendEpoch !== this.receiveEpoch) {
        await carrierStream.reset().catch(() => undefined);
        return;
      }
      const receiveRoots = this.rootForReceive(preface.initialSendEpoch);
      if (!verifySetupMAC(receiveRoots.setupRoot, this.h3, preface) || !this.acceptsPeerStreamAfterGoAway(preface.logicalStreamID)) {
        await carrierStream.reset().catch(() => undefined);
        return;
      }
      let setupAction: ReturnType<StreamLifetimeLedgerV2["validFSS2"]>;
      try {
        setupAction = this.peerLedger.validFSS2(preface.logicalStreamID);
      } catch (error) {
        if (error instanceof StreamLifetimeLedgerV2Error && error.code === "duplicate") throw error;
        await carrierStream.reset().catch(() => undefined);
        return;
      }
      if (setupAction === "reset") {
        await carrierStream.reset().catch(() => undefined);
        return;
      }
      ledgerID = preface.logicalStreamID;
      await this.acceptCarrierStreamAfterFSS2(carrierStream, reader, prefaceRaw, preface);
    } catch (error) {
      if (ledgerID !== undefined) await this.resetInboundBeforeDelivery(ledgerID, carrierStream);
      else await carrierStream.reset().catch(() => undefined);
      if (error instanceof StreamLifetimeLedgerV2Error && error.code === "duplicate") throw error;
    } finally {
      if (responderHeld) this.leaveInboundResponder();
    }
  }

  private async acceptCarrierStreamAfterFSS2(
    carrierStream: CarrierStreamV2,
    reader: ExactReader,
    prefaceRaw: Uint8Array,
    preface: ReturnType<typeof decodeSetupPrefaceV2>,
  ): Promise<void> {
    const temporary = new EncryptedStreamV2(
      this,
      carrierStream,
      preface.logicalStreamID,
      "",
      this.sendEpoch,
      preface.initialSendEpoch,
      () => undefined,
      reader,
    );
    const first = await this.readStreamRecord(temporary);
    if (first.type !== InnerTypeV2.Open) throw protocolError("OPEN must be first");
    const open = decodeOpenPayload(first.payload);
    if (open.logicalStreamID !== preface.logicalStreamID ||
        !bytesEqual(open.fss2Hash, computeFSS2HashV2(prefaceRaw))) {
      throw protocolError("OPEN binding mismatch");
    }
    this.peerLedger.validOpen(preface.logicalStreamID);
    const internalRPC = open.kind === RESERVED_RPC_KIND;
    if (internalRPC && decoder.decode(open.metadata) !== "{}") {
      await temporary.send(InnerTypeV2.OpenReject, encodeOpenRejectV2(computeOpenHashV2(first.payload), 4));
      await carrierStream.closeWrite();
      return;
    }
    const releasePermit = internalRPC ? () => undefined : this.inboundPermits.tryAcquire();
    if (releasePermit === undefined) {
      await temporary.send(InnerTypeV2.OpenReject, encodeOpenRejectV2(computeOpenHashV2(first.payload), 2));
      await carrierStream.closeWrite();
      return;
    }
    const stream = new EncryptedStreamV2(
      this,
      carrierStream,
      preface.logicalStreamID,
      open.kind,
      this.sendEpoch,
      preface.initialSendEpoch,
      releasePermit,
      reader,
    );
    stream.receiveSequence = temporary.receiveSequence;
    this.streams.set(stream.id, stream);
    await stream.send(InnerTypeV2.OpenACK, encodeOpenACKV2(computeOpenHashV2(first.payload)));
    stream.markOpen();
    stream.startPump();
    if (!this.acceptsPeerStreamAfterGoAway(stream.id)) {
      await this.localReset(stream, new SessionV2Error("going_away", "peer stream exceeds the sent GOAWAY boundary"));
      return;
    }
    if (internalRPC) {
      if (this.rpcServing) {
        await this.localReset(stream, protocolError("duplicate reserved RPC stream"));
        return;
      }
      this.rpcServing = true;
      const rpcReader = new ExactReader(stream);
      const server = new RpcServer({
        readExactly: async (length) => await rpcReader.readExactly(length),
        write: async (payload) => { await stream.write(payload); },
        close: () => { void stream.reset(); },
      }, this.config.rpcServerOptions, this.config.rpcRouter ?? new RpcRouter());
      void server.serve().catch((error) => {
        if (this.terminalError === undefined) this.fail(asError(error));
      });
      return;
    }
    this.incoming.push({
      id: stream.id,
      kind: stream.kind,
      metadata: decodeMetadata(open.metadata),
      stream,
    });
  }

  private async resetInboundBeforeDelivery(id: bigint, carrierStream: CarrierStreamV2): Promise<void> {
    await carrierStream.reset().catch(() => undefined);
    try {
      await this.sendControl(InnerTypeV2.StreamReset, idReason(id, 3));
      this.peerLedger.localResetCommitted(id);
    } catch (error) {
      this.fail(asError(error));
    }
  }

  private async sendControl(type: InnerTypeV2, payload: Uint8Array): Promise<void> {
    const task = this.controlWriteTail.then(async () => {
      if (this.terminalError !== undefined) throw this.terminalError;
      const inner = encodeInnerRecordV2(type, payload);
      const roots = this.rootForSend(this.controlSendEpoch);
      const material = deriveControlMaterial(
        roots.controlRoot,
        this.h3,
        this.sendDirection,
        this.controlSendEpoch,
      );
      const header = {
        epoch: this.controlSendEpoch,
        sequence: this.controlSendSequence,
        ciphertextLength: inner.length + 16,
      };
      const ciphertext = sealRecord(this.config.suite, material, this.h3, 0n, this.sendDirection, header, inner);
      this.controlSendSequence += 1n;
      await writeAll(this.control, encodeRecordHeader(header));
      await writeAll(this.control, ciphertext);
      this.markAuthenticatedActivity();
    });
    this.controlWriteTail = task.catch(() => undefined);
    await task;
  }

  private async readControl(): Promise<Readonly<{ type: InnerTypeV2; payload: Uint8Array }>> {
    const header = decodeRecordHeader(await this.controlReader.readExactly(24));
    const cutover = header.epoch === this.controlReceiveEpoch + 1 &&
      header.epoch <= this.receiveEpoch && header.sequence === 0n;
    if (!cutover && (header.epoch !== this.controlReceiveEpoch || header.sequence !== this.controlReceiveSequence)) {
      throw protocolError("unexpected control epoch or sequence");
    }
    const roots = this.rootForReceive(header.epoch);
    const material = deriveControlMaterial(roots.controlRoot, this.h3, this.receiveDirection, header.epoch);
    const ciphertext = await this.controlReader.readExactly(header.ciphertextLength);
    const inner = decodeInnerRecordV2(openRecord(
      this.config.suite,
      material,
      this.h3,
      0n,
      this.receiveDirection,
      header,
      ciphertext,
    ));
    if (cutover) {
      this.controlReceiveEpoch = header.epoch;
      this.controlReceiveSequence = 1n;
      this.cleanupEpochRoots();
    } else {
      this.controlReceiveSequence += 1n;
    }
    this.markAuthenticatedActivity();
    return inner;
  }

  private async controlLoop(): Promise<void> {
    try {
      while (this.terminalError === undefined) {
        const record = await this.readControl();
        switch (record.type) {
          case InnerTypeV2.Ping:
            await this.sendControl(InnerTypeV2.Pong, record.payload);
            break;
          case InnerTypeV2.Pong:
            this.pings.get(readU64(record.payload))?.resolve();
            break;
          case InnerTypeV2.StreamReset: {
            const { id, reason } = parseIDReason(record.payload);
            if (id === 0n || reason === 0) throw protocolError("invalid STREAM_RESET");
            this.streams.get(id)?.peerReset(new SessionV2Error("closed", "logical stream reset by peer"));
            if (this.isLocalLogicalID(id)) {
              this.outboundLedger.peerReset(id);
              this.notifyOutboundFrontierChanged();
            } else {
              this.peerLedger.peerReset(id);
            }
            break;
          }
          case InnerTypeV2.SessionKeyUpdate:
            await this.receiveSessionRekey(record.payload);
            break;
          case InnerTypeV2.SessionKeyUpdateACK:
            this.receiveSessionRekeyACK(record.payload);
            break;
          case InnerTypeV2.GoAway:
            await this.receiveGoAway(record.payload);
            break;
          case InnerTypeV2.SessionClose:
            if (record.payload.length !== 2 || readU16(record.payload, 0) === 0) {
              throw protocolError("invalid SESSION_CLOSE");
            }
            throw new SessionV2Error("closed", "Flowersec v2 session closed by peer");
          default:
            throw protocolError(`unexpected control type ${record.type}`);
        }
      }
    } catch (error) {
      if (this.terminalError === undefined) this.fail(asError(error));
    }
  }

  private async closeOnce(): Promise<void> {
    if (this.terminalError !== undefined) return;
    const closed = new SessionV2Error("closed", "Flowersec v2 session closed");
    const work = (async () => {
      try {
        await this.sendGoAway(1);
        await this.sendControl(InnerTypeV2.SessionClose, Uint8Array.of(0, 1));
      } catch {
        // Closing is best-effort once the bounded shutdown has started.
      }
      this.fail(closed, false);
      await this.carrier.close({ code: 1, reason: "session closed" }).catch(() => undefined);
    })();
    if (!await settleWithin(work, sessionCloseTimeoutMs(this.config))) {
      this.carrier.abort({ code: 1, reason: "session close deadline exceeded" });
      await work.catch(() => undefined);
    }
    this.fail(closed, false);
  }

  async waitClosed(): Promise<SessionTerminationV2> {
    return await this.termination;
  }

  private async rekeyOnce(options: OperationOptionsV2): Promise<void> {
    this.assertOpen();
    throwIfAborted(options.signal);
    this.openFrozen = true;
    this.openGate = deferred<void>();
    let committed = false;
    const prepareDeadline = createSessionDeadline(this.config, "rekey_prepare");
    const prepareSignal = combineSignals(options.signal, prepareDeadline.signal);
    let completionDeadline: SessionDeadlineHandleV2 | undefined;
    let completionSignal: SessionDeadlineHandleV2 | undefined;
    let respondersFrozen = false;
    try {
      await this.freezeInboundResponders(false, prepareSignal.signal);
      respondersFrozen = true;
      const currentEpoch = this.sendEpoch;
      if (currentEpoch === 0xffffffff) throw new SessionV2Error("resource_exhausted", "session epoch exhausted");
      const nextEpoch = currentEpoch + 1;
      const currentRoots = this.rootForSend(currentEpoch);
      const nextRoots = deriveEpochRoots(deriveNextEpoch(
        currentRoots.rekeyRoot,
        this.h3,
        this.sendDirection,
        nextEpoch,
      ));
      this.sendRoots.set(nextEpoch, nextRoots);
      this.preparingSendEpoch = nextEpoch;
      const transition = this.nextTransition++;
      const watermark = this.nextLogicalID > 2n ? this.nextLogicalID - 2n : 0n;
      await this.waitOutboundFrontier(watermark, prepareSignal.signal);
      prepareSignal.cancel();
      prepareDeadline.cancel();
      completionDeadline = createSessionDeadline(this.config, "rekey_completion");
      completionSignal = combineSignals(options.signal, completionDeadline.signal);
      committed = true;
      throwIfAborted(completionSignal.signal);
      const payload = concat(u64(transition), u32(nextEpoch), u64(watermark));
      const active = [...this.streams.values()].filter((stream) => stream.canRekeySend());
      const updates = active.map((stream) => stream.startSendRekey(transition, nextEpoch));
      await Promise.all(updates.map(async (update) => await raceAbort(update.armed.promise, completionSignal!.signal)));
      const pending = {
        payload,
        epoch: nextEpoch,
        acknowledged: deferred<void>(),
        committed: { value: false },
      } as const;
      this.pendingSessionRekey = pending;
      this.preparingSendEpoch = undefined;
      await this.sendControl(InnerTypeV2.SessionKeyUpdate, payload);
      await raceAbort(pending.acknowledged.promise, completionSignal.signal);
      await Promise.all(updates.map(async (update) => await raceAbort(update.done.promise, completionSignal!.signal)));
      if (this.pendingSessionRekey === pending) this.pendingSessionRekey = undefined;
      this.cleanupEpochRoots();
    } catch (error) {
      if (committed) this.fail(asError(error));
      throw error;
    } finally {
      prepareSignal.cancel();
      prepareDeadline.cancel();
      completionSignal?.cancel();
      completionDeadline?.cancel();
      this.openFrozen = false;
      this.openGate.resolve();
      if (respondersFrozen) this.unfreezeInboundResponders(false);
      this.preparingSendEpoch = undefined;
      this.cleanupEpochRoots();
    }
  }

  private async receiveSessionRekey(payload: Uint8Array): Promise<void> {
    const completionDeadline = createSessionDeadline(this.config, "rekey_completion");
    let respondersFrozen = false;
    try {
      await this.freezeInboundResponders(true, completionDeadline.signal);
      respondersFrozen = true;
      await this.receiveSessionRekeyBeforeDeadline(payload, completionDeadline.signal);
    } finally {
      if (respondersFrozen) this.unfreezeInboundResponders(true);
      completionDeadline.cancel();
    }
  }

  private async enterInboundResponder(): Promise<void> {
    while (this.localResponderFrozen || this.peerResponderFrozen) {
      this.assertOpen();
      await this.responderChanged.promise;
    }
    this.assertOpen();
    this.activeInboundResponders++;
    this.notifyResponderChanged();
  }

  private leaveInboundResponder(): void {
    if (this.activeInboundResponders === 0) return;
    this.activeInboundResponders--;
    this.notifyResponderChanged();
  }

  private async freezeInboundResponders(peer: boolean, signal: AbortSignal): Promise<void> {
    if (peer) this.peerResponderFrozen = true;
    else this.localResponderFrozen = true;
    this.notifyResponderChanged();
    while (this.activeInboundResponders !== 0) {
      await raceAbort(this.responderChanged.promise, signal);
      this.assertOpen();
    }
  }

  private unfreezeInboundResponders(peer: boolean): void {
    if (peer) this.peerResponderFrozen = false;
    else this.localResponderFrozen = false;
    this.notifyResponderChanged();
  }

  private notifyResponderChanged(): void {
    this.responderChanged.resolve();
    this.responderChanged = deferred<void>();
  }

  private async receiveSessionRekeyBeforeDeadline(
    payload: Uint8Array,
    signal: AbortSignal,
  ): Promise<void> {
    throwIfAborted(signal);
    const transition = readU64(payload);
    const nextEpoch = readU32(payload, 8);
    const watermark = readU64At(payload, 12);
    if (payload.length !== 20 || transition !== this.receiveTransition + 1n || nextEpoch !== this.receiveEpoch + 1) {
      throw protocolError("invalid SESSION_KEY_UPDATE");
    }
    if (watermark !== this.peerLedger.frontier) throw protocolError("SESSION_KEY_UPDATE watermark mismatch");
    this.pendingReceiveEpoch = nextEpoch;
    const current = this.rootForReceive(this.receiveEpoch);
    if (!this.receiveRoots.has(nextEpoch)) {
      this.receiveRoots.set(nextEpoch, deriveEpochRoots(deriveNextEpoch(
        current.rekeyRoot,
        this.h3,
        this.receiveDirection,
        nextEpoch,
      )));
    }
    const streams = [...this.streams.values()];
    await Promise.all(streams.map(async (stream) => await stream.waitReceiveRekey(transition, nextEpoch, signal)));
    await raceAbort(this.sendControl(InnerTypeV2.SessionKeyUpdateACK, payload), signal);
    throwIfAborted(signal);
    this.receiveEpoch = nextEpoch;
    this.receiveTransition = transition;
    this.pendingReceiveEpoch = undefined;
    for (const stream of streams) stream.publishReceiveRekey(transition, nextEpoch);
    this.cleanupEpochRoots();
  }

  private receiveSessionRekeyACK(payload: Uint8Array): void {
    const pending = this.pendingSessionRekey;
    if (pending === undefined) {
      if (this.lastSessionRekeyACK !== undefined && bytesEqual(payload, this.lastSessionRekeyACK)) return;
      throw protocolError("unexpected SESSION_KEY_UPDATE_ACK");
    }
    if (!bytesEqual(payload, pending.payload)) throw protocolError("unexpected SESSION_KEY_UPDATE_ACK");
    if (pending.committed.value) return;
    pending.committed.value = true;
    this.sendEpoch = pending.epoch;
    this.controlSendEpoch = pending.epoch;
    this.controlSendSequence = 0n;
    this.lastSessionRekeyACK = payload.slice();
    pending.acknowledged.resolve();
    this.cleanupEpochRoots();
  }

  private async waitOpenGate(signal?: AbortSignal): Promise<void> {
    while (this.openFrozen) await raceAbort(this.openGate.promise, signal);
  }

  resolveOutboundOpen(id: bigint): void {
    this.outboundLedger.validOpen(id);
    this.notifyOutboundFrontierChanged();
  }

  private async waitOutboundFrontier(watermark: bigint, signal: AbortSignal): Promise<void> {
    while (this.outboundLedger.frontier !== watermark) {
      if (this.outboundLedger.frontier > watermark) throw protocolError("outbound frontier exceeded watermark");
      await raceAbort(this.outboundFrontierChanged.promise, signal);
    }
  }

  private async commitOutboundReset(id: bigint): Promise<void> {
    await this.sendControl(InnerTypeV2.StreamReset, idReason(id, 6));
    this.outboundLedger.localResetCommitted(id);
    this.notifyOutboundFrontierChanged();
  }

  private commitLocalReset(id: bigint): void {
    if (this.isLocalLogicalID(id)) {
      this.outboundLedger.localResetCommitted(id);
      this.notifyOutboundFrontierChanged();
      return;
    }
    this.peerLedger.localResetCommitted(id);
  }

  private notifyOutboundFrontierChanged(): void {
    this.outboundFrontierChanged.resolve();
    this.outboundFrontierChanged = deferred<void>();
  }

  private isLocalLogicalID(id: bigint): boolean {
    return id > 0n && (this.role === 1 ? (id & 1n) === 1n : (id & 1n) === 0n);
  }

  private localOpenHighWatermark(): bigint {
    const first = this.role === 1 ? 1n : 2n;
    return this.nextLogicalID === first ? 0n : this.nextLogicalID - 2n;
  }

  private validGoAwayBoundary(lastAccepted: bigint): boolean {
    if (lastAccepted === 0n) return true;
    return this.isLocalLogicalID(lastAccepted) && lastAccepted <= this.localOpenHighWatermark();
  }

  private async sendGoAway(reason: number): Promise<void> {
    if (!Number.isInteger(reason) || reason < 1 || reason > 0xffff) throw protocolError("invalid GOAWAY reason");
    if (this.sentGoAway) {
      if (this.sentGoAwayReason !== reason) throw protocolError("conflicting local GOAWAY reason");
      return;
    }
    const lastAccepted = this.peerLedger.frontier;
    this.sentGoAway = true;
    this.sentGoAwayLastAccepted = lastAccepted;
    this.sentGoAwayReason = reason;
    await this.sendControl(InnerTypeV2.GoAway, idReason(lastAccepted, reason));
  }

  private async receiveGoAway(payload: Uint8Array): Promise<void> {
    const { id: lastAccepted, reason } = parseIDReason(payload);
    if (reason === 0 || !this.validGoAwayBoundary(lastAccepted)) throw protocolError("invalid GOAWAY boundary");
    if (this.receivedGoAway) {
      if (this.receivedGoAwayLastAccepted !== lastAccepted || this.receivedGoAwayReason !== reason) {
        throw protocolError("conflicting GOAWAY");
      }
      return;
    }
    this.receivedGoAway = true;
    this.receivedGoAwayLastAccepted = lastAccepted;
    this.receivedGoAwayReason = reason;
    const excluded = [...this.streams.values()].filter((stream) =>
      this.isLocalLogicalID(stream.id) && stream.id > lastAccepted);
    await Promise.allSettled(excluded.map(async (stream) => {
      await this.localReset(stream, new SessionV2Error("going_away", "logical stream exceeds peer GOAWAY boundary"));
    }));
  }

  private localOpeningAllowedAfterGoAway(id: bigint): boolean {
    return !this.receivedGoAway || id <= this.receivedGoAwayLastAccepted;
  }

  private acceptsPeerStreamAfterGoAway(id: bigint): boolean {
    return !this.sentGoAway || id <= this.sentGoAwayLastAccepted;
  }

  private cleanupEpochRoots(): void {
    const sendInUse = new Set<number>([this.sendEpoch, this.controlSendEpoch]);
    const receiveInUse = new Set<number>([this.receiveEpoch, this.controlReceiveEpoch]);
    if (this.preparingSendEpoch !== undefined) sendInUse.add(this.preparingSendEpoch);
    if (this.pendingReceiveEpoch !== undefined) receiveInUse.add(this.pendingReceiveEpoch);
    if (this.pendingSessionRekey !== undefined) sendInUse.add(this.pendingSessionRekey.epoch);
    for (const stream of this.streams.values()) {
      for (const epoch of stream.sendEpochsInUse()) sendInUse.add(epoch);
      for (const epoch of stream.receiveEpochsInUse()) receiveInUse.add(epoch);
    }
    this.cleanupRootMap(this.sendRoots, sendInUse);
    this.cleanupRootMap(this.receiveRoots, receiveInUse);
  }

  streamEpochStateChanged(): void {
    this.cleanupEpochRoots();
  }

  private cleanupRootMap(roots: Map<number, EpochRootsV2>, inUse: ReadonlySet<number>): void {
    for (const [epoch, value] of roots) {
      if (inUse.has(epoch)) continue;
      wipeEpochRoots(value);
      roots.delete(epoch);
    }
  }

  private wipeAllRoots(): void {
    for (const roots of this.sendRoots.values()) wipeEpochRoots(roots);
    for (const roots of this.receiveRoots.values()) wipeEpochRoots(roots);
    this.sendRoots.clear();
    this.receiveRoots.clear();
  }

  private startIdleWatchdog(): void {
    this.idleWatchdogStarted = true;
    this.markAuthenticatedActivity();
  }

  private markAuthenticatedActivity(): void {
    if (!this.idleWatchdogStarted || this.terminalError !== undefined) return;
    const timeoutMs = sessionIdleTimeoutMs(this.config);
    if (timeoutMs === 0) return;
    if (this.idleTimer !== undefined) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      this.idleTimer = undefined;
      this.fail(new SessionV2Error("timeout", "Flowersec v2 session idle timeout exceeded"));
    }, timeoutMs);
  }

  private fail(error: Error, abortCarrier = true): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error;
    this.terminationState.resolve({ error });
    if (this.idleTimer !== undefined) {
      clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
    }
    this.incoming.fail(error);
    this.outboundPermits.fail(error);
    this.inboundPermits.fail(error);
    this.notifyResponderChanged();
    for (const ping of this.pings.values()) ping.reject(error);
    this.pings.clear();
    this.rpc.close();
    for (const stream of [...this.streams.values()]) stream.peerReset(error);
    this.wipeAllRoots();
    this.h3.fill(0);
    if (abortCarrier) this.carrier.abort({ code: 6, reason: "session terminated" });
  }

  private assertOpen(): void {
    if (this.terminalError !== undefined) throw this.terminalError;
  }
}

class EncryptedStreamV2 implements ByteStreamV2 {
  readonly reader: ExactReader;
  readonly opened = deferred<void>();
  readonly data = new ByteQueue(MAX_BUFFERED_STREAM_BYTES);
  terminalError: Error | undefined;
  sendSequence = 0n;
  receiveSequence = 0n;
  priorACK: Readonly<{ epoch: number; sequence: bigint }> | undefined;
  private sendTail: Promise<void> = Promise.resolve();
  private localFIN = false;
  private remoteFIN = false;
  private pumpStarted = false;
  private permitReleased = false;
  private pendingSendRekey: Readonly<{
    transition: bigint;
    epoch: number;
    armed: Deferred<void>;
    done: Deferred<void>;
  }> | undefined;
  private lastSendRekeyACK: Readonly<{ transition: bigint; epoch: number }> | undefined;
  private receiveRekey: Readonly<{
    transition: bigint;
    epoch: number;
    acknowledged: Deferred<void>;
  }> | undefined;

  constructor(
    readonly session: SessionV2,
    readonly carrier: CarrierStreamV2,
    readonly id: bigint,
    readonly kind: string,
    public sendEpoch: number,
    public receiveEpoch: number,
    private readonly permitRelease: () => void,
    reader?: ExactReader,
  ) {
    this.reader = reader ?? new ExactReader(carrier);
  }

  async read(options: OperationOptionsV2 = {}): Promise<Uint8Array | null> {
    if (this.terminalError !== undefined) throw this.terminalError;
    return await this.data.read(options.signal);
  }

  async write(payload: Uint8Array, options: OperationOptionsV2 = {}): Promise<number> {
    if (!(payload instanceof Uint8Array)) throw new TypeError("stream write requires Uint8Array");
    if (payload.length === 0) return 0;
    throwIfAborted(options.signal);
    await this.opened.promise;
    await this.waitSendRekey(options.signal);
    if (this.localFIN) throw new SessionV2Error("closed", "write after FIN");
    if (this.terminalError !== undefined) throw this.terminalError;
    const copy = payload.slice();
    await this.enqueueSend(async () => {
      for (let offset = 0; offset < copy.length; offset += MAX_DATA_BYTES) {
        throwIfAborted(options.signal);
        await this.session.sendStreamRecord(
          this,
          InnerTypeV2.Data,
          copy.subarray(offset, Math.min(copy.length, offset + MAX_DATA_BYTES)),
        );
      }
    });
    return copy.length;
  }

  async closeWrite(): Promise<void> {
    await this.opened.promise;
    await this.waitSendRekey();
    if (this.localFIN || this.terminalError !== undefined) return;
    await this.enqueueSend(async () => {
      if (this.localFIN) return;
      this.localFIN = true;
      await this.session.sendStreamRecord(this, InnerTypeV2.FIN, new Uint8Array());
      await this.carrier.closeWrite();
      this.releaseIfClean();
    });
  }

  async reset(): Promise<void> {
    await this.session.localReset(this, new SessionV2Error("closed", "logical stream reset"));
  }

  async close(): Promise<void> {
    await this.reset();
  }

  send(type: InnerTypeV2, payload: Uint8Array, signal?: AbortSignal): Promise<void> {
    return this.enqueueSend(async () => await this.session.sendStreamRecord(this, type, payload, signal));
  }

  canRekeySend(): boolean {
    return this.terminalError === undefined && this.opened.settled && !this.localFIN;
  }

  startSendRekey(transition: bigint, epoch: number): Readonly<{
    armed: Deferred<void>;
    done: Deferred<void>;
  }> {
    if (this.pendingSendRekey !== undefined) throw protocolError("overlapping stream rekey");
    const pending = { transition, epoch, armed: deferred<void>(), done: deferred<void>() } as const;
    this.pendingSendRekey = pending;
    void this.enqueueSend(async () => {
      await this.session.sendStreamRecord(this, InnerTypeV2.StreamKeyUpdate, concat(u64(transition), u32(epoch)));
      pending.armed.resolve();
    }).catch((error) => {
      pending.armed.reject(error);
      pending.done.reject(error);
      void this.session.localReset(this, asError(error));
    });
    return pending;
  }

  async waitReceiveRekey(transition: bigint, epoch: number, signal?: AbortSignal): Promise<void> {
    throwIfAborted(signal);
    if (this.terminalError !== undefined || this.remoteFIN) return;
    while (true) {
      const pending = this.receiveRekey;
      if (pending !== undefined) {
        if (pending.transition !== transition || pending.epoch !== epoch) throw protocolError("stream rekey mismatch");
        await raceAbort(pending.acknowledged.promise, signal);
        return;
      }
      await raceAbort(new Promise<void>((resolve) => setTimeout(resolve, 0)), signal);
      if (this.terminalError !== undefined || this.remoteFIN) return;
    }
  }

  publishReceiveRekey(transition: bigint, epoch: number): void {
    if (this.receiveRekey?.transition === transition && this.receiveRekey.epoch === epoch) {
      this.receiveRekey = undefined;
    }
  }

  startPump(): void {
    if (this.pumpStarted) return;
    this.pumpStarted = true;
    void this.pump();
  }

  markOpen(): void {
    this.opened.resolve();
  }

  markTerminal(error: Error): boolean {
    if (this.terminalError !== undefined) return false;
    this.terminalError = error;
    this.opened.reject(error);
    this.data.fail(error);
    return true;
  }

  peerReset(error: Error): void {
    if (!this.markTerminal(error)) return;
    this.carrier.abort(error);
    this.session.releaseStream(this);
  }

  abort(error: Error = new SessionV2Error("closed", "logical stream aborted")): void {
    this.peerReset(error);
  }

  releasePermit(): void {
    if (this.permitReleased) return;
    this.permitReleased = true;
    this.permitRelease();
  }

  private async pump(): Promise<void> {
    try {
      while (this.terminalError === undefined) {
        const record = await this.session.readStreamRecord(this);
        if (!this.opened.settled) {
          if (record.type === InnerTypeV2.OpenACK) {
            const got = decodeOpenACKV2(record.payload);
            if (!bytesEqual(got, this.openedHash())) throw protocolError("OPEN ACK hash mismatch");
            this.session.resolveOutboundOpen(this.id);
            this.markOpen();
            continue;
          }
          if (record.type === InnerTypeV2.OpenReject) {
            const reject = decodeOpenRejectV2(record.payload);
            if (!bytesEqual(reject.openHash, this.openedHash())) throw protocolError("OPEN REJECT hash mismatch");
            this.session.resolveOutboundOpen(this.id);
            const error = new SessionV2Error("open_rejected", `logical stream rejected (${reject.reason})`);
            this.markTerminal(error);
            await this.carrier.closeWrite().catch(() => undefined);
            this.session.releaseStream(this);
            return;
          }
          throw protocolError("expected OPEN ACK or REJECT");
        }
        switch (record.type) {
          case InnerTypeV2.Data:
            if (this.remoteFIN) throw protocolError("DATA after FIN");
            this.data.push(record.payload);
            break;
          case InnerTypeV2.FIN:
            if (this.remoteFIN) throw protocolError("duplicate FIN");
            this.remoteFIN = true;
            this.data.close();
            this.releaseIfClean();
            break;
          case InnerTypeV2.StreamKeyUpdate:
            await this.receiveStreamKeyUpdate(record.payload, record.header);
            break;
          case InnerTypeV2.StreamKeyUpdateACK:
            this.receiveStreamKeyUpdateACK(record.payload);
            break;
          default:
            throw protocolError(`unexpected stream type ${record.type}`);
        }
      }
    } catch (error) {
      const normalized = asError(error);
      if (this.remoteFIN && /closed|EOF/i.test(normalized.message)) {
        this.releaseIfClean();
        return;
      }
      await this.session.localReset(this, normalized);
    }
  }

  private openedHash(): Uint8Array {
    const value = (this as unknown as { openHash?: Uint8Array }).openHash;
    if (value === undefined) throw protocolError("missing OPEN hash");
    return value;
  }

  setOpenHash(value: Uint8Array): void {
    (this as unknown as { openHash?: Uint8Array }).openHash = value.slice();
  }

  private enqueueSend(operation: () => Promise<void>): Promise<void> {
    const task = this.sendTail.then(async () => {
      if (this.terminalError !== undefined) throw this.terminalError;
      await operation();
    });
    this.sendTail = task.catch(() => undefined);
    return task;
  }

  private async waitSendRekey(signal?: AbortSignal): Promise<void> {
    while (this.pendingSendRekey !== undefined) {
      await raceAbort(this.pendingSendRekey.done.promise, signal);
    }
  }

  private async receiveStreamKeyUpdate(payload: Uint8Array, header: RecordHeaderV2): Promise<void> {
    if (payload.length !== 12 || this.receiveRekey !== undefined) throw protocolError("invalid STREAM_KEY_UPDATE");
    const transition = readU64(payload);
    const nextEpoch = readU32(payload, 8);
    if (transition === 0n || nextEpoch !== this.receiveEpoch + 1) throw protocolError("invalid stream rekey transition");
    const current = this.session.rootForReceive(this.receiveEpoch);
    if (!this.session.hasReceiveRoots(nextEpoch)) {
      this.session.installReceiveRoots(nextEpoch, deriveEpochRoots(deriveNextEpoch(
        current.rekeyRoot,
        this.session.transcriptHash(),
        this.session.receiveDirectionValue(),
        nextEpoch,
      )));
    }
    if (this.pendingSendRekey?.transition === transition && this.pendingSendRekey.epoch === nextEpoch) {
      this.priorACK = { epoch: header.epoch, sequence: this.receiveSequence };
    }
    this.receiveEpoch = nextEpoch;
    this.receiveSequence = 0n;
    const pending = { transition, epoch: nextEpoch, acknowledged: deferred<void>() } as const;
    this.receiveRekey = pending;
    await this.send(InnerTypeV2.StreamKeyUpdateACK, encodeStreamKeyUpdateACKV2({
      logicalStreamID: this.id,
      transition,
      epoch: nextEpoch,
    }));
    pending.acknowledged.resolve();
  }

  private receiveStreamKeyUpdateACK(payload: Uint8Array): void {
    const decoded = decodeStreamKeyUpdateACKV2(payload);
    if (decoded.logicalStreamID !== this.id) throw protocolError("invalid STREAM_KEY_UPDATE_ACK");
    const { transition, epoch } = decoded;
    const pending = this.pendingSendRekey;
    if (pending === undefined) {
      if (this.lastSendRekeyACK?.transition === transition && this.lastSendRekeyACK.epoch === epoch) return;
      throw protocolError("unexpected STREAM_KEY_UPDATE_ACK");
    }
    if (pending.transition !== transition || pending.epoch !== epoch) throw protocolError("unexpected STREAM_KEY_UPDATE_ACK");
    this.sendEpoch = epoch;
    this.sendSequence = 0n;
    this.pendingSendRekey = undefined;
    this.lastSendRekeyACK = { transition, epoch };
    pending.done.resolve();
    this.session.streamEpochStateChanged();
  }

  sendEpochsInUse(): readonly number[] {
    return this.pendingSendRekey === undefined ? [this.sendEpoch] : [this.sendEpoch, this.pendingSendRekey.epoch];
  }

  receiveEpochsInUse(): readonly number[] {
    const epochs = new Set<number>([this.receiveEpoch]);
    if (this.priorACK !== undefined) epochs.add(this.priorACK.epoch);
    if (this.receiveRekey !== undefined) epochs.add(this.receiveRekey.epoch);
    return [...epochs];
  }

  private releaseIfClean(): void {
    if (!this.localFIN || !this.remoteFIN || this.terminalError !== undefined) return;
    this.session.releaseStream(this);
  }
}

async function clientHandshake(
  control: CarrierStreamV2,
  reader: ExactReader,
  config: SessionConfigV2,
  signal?: AbortSignal,
): Promise<HandshakeMaterial> {
  const key = generateEphemeralKeyV2(config.suite);
  const fsc2 = encodeControlPrefaceV2();
  const initRaw = encodeClientInitV2({
    profile: "flowersec/2",
    channelID: config.channelID,
    sessionContractHash: config.sessionContractHash,
    clientRole: 1,
    suite: config.suite,
    clientEphemeralPublic: key.publicKey,
    nonceC: randomBytes(32),
    selectedFeatures: 0,
    maxInboundStreams: config.maxInboundStreams,
    clientAdmissionBinding: config.localAdmissionBinding,
    clientEndpointInstanceID: config.localEndpointInstanceID,
  });
  await writeAll(control, fsc2, signal);
  await writeAll(control, initRaw, signal);
  const serverRaw = await readHandshakeFrame(reader, signal);
  const server = decodeServerFinishedV2(serverRaw, config.suite);
  validateServerFinishedV2(server, expectations(config, false));
  const shared = computeSharedSecretV2(config.suite, key.privateKey, server.core.serverEphemeralPublic);
  const handshakePRK = deriveHandshakePRKV2(config.psk, shared);
  const h0 = computeHandshakeH0V2(fsc2, initRaw);
  const h1 = computeHandshakeH1V2(h0, encodeServerFinishedCoreV2(server.core, config.suite));
  if (!bytesEqual(server.serverConfirm, computeServerConfirmV2(handshakePRK, h1))) {
    throw protocolError("server confirm mismatch");
  }
  const clientCore = encodeClientFinishedCoreV2(server.core.handshakeID);
  const h2 = computeHandshakeH2V2(h1, serverRaw, clientCore);
  const clientRaw = encodeClientFinishedV2({
    handshakeID: server.core.handshakeID,
    clientConfirm: computeClientConfirmV2(handshakePRK, h2),
  });
  await writeAll(control, clientRaw, signal);
  const h3 = computeHandshakeH3V2(h2, clientRaw);
  return { h3, sessionPRK: deriveSessionPRKV2(h3, handshakePRK) };
}

async function serverHandshake(
  control: CarrierStreamV2,
  reader: ExactReader,
  config: SessionConfigV2,
  signal?: AbortSignal,
): Promise<HandshakeMaterial> {
  const fsc2 = await reader.readExactly(16, signal);
  parseControlPrefaceV2(fsc2);
  const clientRaw = await readHandshakeFrame(reader, signal);
  const client = decodeClientInitV2(clientRaw);
  validateClientInitV2(client, expectations(config, true));
  const key = generateEphemeralKeyV2(config.suite);
  const shared = computeSharedSecretV2(config.suite, key.privateKey, client.clientEphemeralPublic);
  const handshakePRK = deriveHandshakePRKV2(config.psk, shared);
  const core = {
    suite: config.suite,
    handshakeID: randomBytes(16),
    serverEphemeralPublic: key.publicKey,
    nonceS: randomBytes(32),
    sessionContractHash: config.sessionContractHash,
    selectedFeatures: 0,
    maxInboundStreams: config.maxInboundStreams,
    serverAdmissionBinding: config.localAdmissionBinding,
    serverEndpointInstanceID: config.localEndpointInstanceID,
  } as const;
  const h0 = computeHandshakeH0V2(fsc2, clientRaw);
  const h1 = computeHandshakeH1V2(h0, encodeServerFinishedCoreV2(core, config.suite));
  const serverRaw = encodeServerFinishedV2({
    core,
    serverConfirm: computeServerConfirmV2(handshakePRK, h1),
  }, config.suite);
  await writeAll(control, serverRaw, signal);
  const clientFinishedRaw = await readHandshakeFrame(reader, signal);
  const clientFinished = decodeClientFinishedV2(clientFinishedRaw);
  if (!bytesEqual(clientFinished.handshakeID, core.handshakeID)) throw protocolError("handshake ID mismatch");
  const clientCore = encodeClientFinishedCoreV2(clientFinished.handshakeID);
  const h2 = computeHandshakeH2V2(h1, serverRaw, clientCore);
  if (!bytesEqual(clientFinished.clientConfirm, computeClientConfirmV2(handshakePRK, h2))) {
    throw protocolError("client confirm mismatch");
  }
  const h3 = computeHandshakeH3V2(h2, clientFinishedRaw);
  return { h3, sessionPRK: deriveSessionPRKV2(h3, handshakePRK) };
}

function expectations(config: SessionConfigV2, peerIsClient: boolean): HandshakeExpectationsV2 {
  return {
    path: config.path,
    channelID: peerIsClient ? config.channelID : "",
    sessionContractHash: config.sessionContractHash,
    suite: config.suite,
    maxInboundStreams: config.maxInboundStreams,
    admissionBinding: config.peerAdmissionBinding,
    expectedEndpointInstanceID: config.expectedPeerEndpointInstanceID,
  };
}

async function readHandshakeFrame(reader: ExactReader, signal?: AbortSignal): Promise<Uint8Array> {
  const header = await reader.readExactly(12, signal);
  const length = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(8, false);
  if (length < 1 || length > 8_192) throw protocolError("invalid handshake payload length");
  const raw = concat(header, await reader.readExactly(length, signal));
  decodeHandshakeFrameV2(raw);
  return raw;
}

class ExactReader {
  private chunks: Uint8Array[] = [];
  private offset = 0;
  private bytes = 0;

  constructor(private readonly stream: CarrierStreamV2) {}

  async readExactly(length: number, signal?: AbortSignal): Promise<Uint8Array> {
    while (this.bytes < length) {
      const chunk = await this.stream.read(signal === undefined ? {} : { signal });
      if (chunk === null) throw new SessionV2Error("closed", "unexpected carrier EOF");
      if (chunk.length === 0) continue;
      this.chunks.push(chunk);
      this.bytes += chunk.length;
    }
    const out = new Uint8Array(length);
    let written = 0;
    while (written < length) {
      const chunk = this.chunks[0]!;
      const take = Math.min(length - written, chunk.length - this.offset);
      out.set(chunk.subarray(this.offset, this.offset + take), written);
      written += take;
      this.offset += take;
      this.bytes -= take;
      if (this.offset === chunk.length) {
        this.chunks.shift();
        this.offset = 0;
      }
    }
    return out;
  }
}

class ByteQueue {
  private readonly chunks: Uint8Array[] = [];
  private head = 0;
  private bytes = 0;
  private closed = false;
  private error: Error | undefined;
  private readonly waiters = new Set<Deferred<void>>();

  constructor(private readonly limit: number) {}

  push(chunk: Uint8Array): void {
    if (this.closed || this.error !== undefined) throw protocolError("DATA after terminal stream state");
    if (this.bytes + chunk.length > this.limit) throw new SessionV2Error("resource_exhausted", "stream receive buffer exceeded");
    this.chunks.push(chunk.slice());
    this.bytes += chunk.length;
    this.wake();
  }

  close(): void {
    this.closed = true;
    this.wake();
  }

  fail(error: Error): void {
    if (this.error !== undefined) return;
    this.error = error;
    this.chunks.length = 0;
    this.head = 0;
    this.bytes = 0;
    this.wake(error);
  }

  async read(signal?: AbortSignal): Promise<Uint8Array | null> {
    while (true) {
      if (this.error !== undefined) throw this.error;
      if (this.head < this.chunks.length) {
        const chunk = this.chunks[this.head++]!;
        this.bytes -= chunk.length;
        if (this.head > 1_024 && this.head * 2 > this.chunks.length) {
          this.chunks.splice(0, this.head);
          this.head = 0;
        }
        return chunk;
      }
      if (this.closed) return null;
      const waiter = deferred<void>();
      this.waiters.add(waiter);
      try { await raceAbort(waiter.promise, signal); }
      finally { this.waiters.delete(waiter); }
    }
  }

  private wake(error?: Error): void {
    for (const waiter of [...this.waiters]) error === undefined ? waiter.resolve() : waiter.reject(error);
    this.waiters.clear();
  }
}

class AsyncSemaphore {
  private available: number;
  private readonly waiters = new Set<SemaphoreWaiter>();
  private error: Error | undefined;

  constructor(count: number) { this.available = count; }

  async acquire(signal?: AbortSignal): Promise<() => void> {
    if (this.error !== undefined) throw this.error;
    if (this.available > 0) {
      this.available--;
      return this.releaser();
    }
    return await new Promise<() => void>((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        this.waiters.delete(waiter);
        signal?.removeEventListener("abort", abort);
      };
      const waiter: SemaphoreWaiter = {
        deliver: (release) => {
          if (settled) {
            release();
            return false;
          }
          settled = true;
          cleanup();
          resolve(release);
          return true;
        },
        fail: (error) => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(error);
        },
      };
      const abort = () => waiter.fail(abortReason(signal!));
      this.waiters.add(waiter);
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted === true) abort();
    });
  }

  tryAcquire(): (() => void) | undefined {
    if (this.error !== undefined || this.available === 0) return undefined;
    this.available--;
    return this.releaser();
  }

  fail(error: Error): void {
    this.error = error;
    for (const waiter of [...this.waiters]) waiter.fail(error);
  }

  private releaser(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const waiter = this.waiters.values().next().value as SemaphoreWaiter | undefined;
      if (waiter === undefined) this.available++;
      else waiter.deliver(this.releaser());
    };
  }
}

class AsyncQueue<T> {
  private readonly values: T[] = [];
  private readonly waiters = new Set<AsyncQueueWaiter<T>>();
  private error: Error | undefined;

  push(value: T): void {
    if (this.error !== undefined) return;
    const waiter = this.waiters.values().next().value as AsyncQueueWaiter<T> | undefined;
    if (waiter === undefined || !waiter.deliver(value)) this.values.push(value);
  }

  async shift(signal?: AbortSignal): Promise<T> {
    if (this.error !== undefined) throw this.error;
    const value = this.values.shift();
    if (value !== undefined) return value;
    return await new Promise<T>((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        this.waiters.delete(waiter);
        signal?.removeEventListener("abort", abort);
      };
      const waiter: AsyncQueueWaiter<T> = {
        deliver: (next) => {
          if (settled) return false;
          settled = true;
          cleanup();
          resolve(next);
          return true;
        },
        fail: (error) => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(error);
        },
      };
      const abort = () => waiter.fail(abortReason(signal!));
      this.waiters.add(waiter);
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted === true) abort();
    });
  }

  fail(error: Error): void {
    this.error = error;
    this.values.length = 0;
    for (const waiter of [...this.waiters]) waiter.fail(error);
  }
}

type SemaphoreWaiter = Readonly<{
  deliver(release: () => void): boolean;
  fail(error: Error): void;
}>;

type AsyncQueueWaiter<T> = Readonly<{
  deliver(value: T): boolean;
  fail(error: Error): void;
}>;

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
  readonly settled: boolean;
}>;

function deferred<T>(): Deferred<T> {
  let resolvePromise!: (value: T | PromiseLike<T>) => void;
  let rejectPromise!: (reason?: unknown) => void;
  let settled = false;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return {
    promise,
    resolve: (value) => { if (!settled) { settled = true; resolvePromise(value); } },
    reject: (reason) => { if (!settled) { settled = true; rejectPromise(reason); } },
    get settled() { return settled; },
  };
}

function validateConfig(carrier: CarrierSessionV2, config: SessionConfigV2): void {
  if (carrier.path !== config.path || (config.role !== "client" && config.role !== "server")) {
    throw new SessionV2Error("handshake", "invalid session carrier/config binding");
  }
  if (!Number.isInteger(config.maxInboundStreams) || config.maxInboundStreams < 1 || config.maxInboundStreams > 128) {
    throw new SessionV2Error("handshake", "invalid maxInboundStreams");
  }
  if (carrier.inboundBidirectionalStreamCapacity !== config.maxInboundStreams + 2) {
    throw new SessionV2Error("handshake", "carrier inbound bidirectional stream capacity mismatch");
  }
  sessionIdleTimeoutMs(config);
  sessionCloseTimeoutMs(config);
  for (const [name, value] of [
    ["session contract hash", config.sessionContractHash],
    ["PSK", config.psk],
    ["local admission binding", config.localAdmissionBinding],
    ["peer admission binding", config.peerAdmissionBinding],
  ] as const) {
    if (value.length !== 32) throw new SessionV2Error("handshake", `${name} must be 32 bytes`);
  }
  if (config.path === "direct") {
    if (config.localEndpointInstanceID !== "" || config.expectedPeerEndpointInstanceID !== "") {
      throw new SessionV2Error("handshake", "direct session endpoint IDs must be empty");
    }
  } else if (config.localEndpointInstanceID === "" || config.expectedPeerEndpointInstanceID === "") {
    throw new SessionV2Error("handshake", "tunnel session endpoint IDs are required");
  }
}

function encodeMetadata(value: JsonObjectV2): Uint8Array {
  return encoder.encode(canonicalJSON(value));
}

function decodeMetadata(raw: Uint8Array): JsonObjectV2 {
  return JSON.parse(decoder.decode(raw)) as JsonObjectV2;
}

function canonicalJSON(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  if (typeof value !== "object" || value === null) throw new TypeError("metadata must be JSON");
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(object[key])}`).join(",")}}`;
}

async function writeAll(stream: CarrierStreamV2, value: Uint8Array, signal?: AbortSignal): Promise<void> {
  let offset = 0;
  while (offset < value.length) {
    throwIfAborted(signal);
    const written = await stream.write(value.subarray(offset), signal === undefined ? {} : { signal });
    if (written < 1 || written > value.length - offset) throw protocolError("short carrier write");
    offset += written;
  }
}

async function settleWithin(promise: Promise<unknown>, timeoutMs: number): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMs);
    void promise.then(
      () => { clearTimeout(timer); resolve(true); },
      () => { clearTimeout(timer); resolve(true); },
    );
  });
}

function sessionIdleTimeoutMs(config: SessionConfigV2): number {
  const timeoutMs = config.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0) {
    throw new RangeError("idleTimeoutMs must be a non-negative integer");
  }
  return timeoutMs;
}

function sessionCloseTimeoutMs(config: SessionConfigV2): number {
  const timeoutMs = config.closeTimeoutMs ?? DEFAULT_CLOSE_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new RangeError("closeTimeoutMs must be an integer from 1 to 60000");
  }
  return timeoutMs;
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function idReason(id: bigint, reason: number): Uint8Array {
  return concat(u64(id), Uint8Array.of((reason >>> 8) & 0xff, reason & 0xff));
}

function parseIDReason(payload: Uint8Array): Readonly<{ id: bigint; reason: number }> {
  if (payload.length !== 10) throw protocolError("invalid ID/reason payload");
  return { id: readU64(payload), reason: readU16(payload, 8) };
}

function u64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

function u32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function readU64(value: Uint8Array): bigint {
  if (value.length < 8) throw protocolError("truncated uint64");
  return new DataView(value.buffer, value.byteOffset, value.byteLength).getBigUint64(0, false);
}

function readU64At(value: Uint8Array, offset: number): bigint {
  if (value.length < offset + 8) throw protocolError("truncated uint64");
  return new DataView(value.buffer, value.byteOffset, value.byteLength).getBigUint64(offset, false);
}

function readU32(value: Uint8Array, offset: number): number {
  if (value.length < offset + 4) throw protocolError("truncated uint32");
  return new DataView(value.buffer, value.byteOffset, value.byteLength).getUint32(offset, false);
}

function readU16(value: Uint8Array, offset: number): number {
  if (value.length < offset + 2) throw protocolError("truncated uint16");
  return new DataView(value.buffer, value.byteOffset, value.byteLength).getUint16(offset, false);
}

function concat(...values: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) { out.set(value, offset); offset += value.length; }
  return out;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function wipeEpochRoots(roots: EpochRootsV2): void {
  roots.epochSecret.fill(0);
  roots.controlRoot.fill(0);
  roots.streamRoot.fill(0);
  roots.setupRoot.fill(0);
  roots.rekeyRoot.fill(0);
}

async function raceAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return await promise;
  throwIfAborted(signal);
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(abortReason(signal));
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      (value) => { signal.removeEventListener("abort", abort); resolve(value); },
      (error) => { signal.removeEventListener("abort", abort); reject(error); },
    );
  });
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw abortReason(signal);
}

function abortedError(): SessionV2Error {
  return new SessionV2Error("aborted", "operation aborted");
}

function abortReason(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : abortedError();
}

function createSessionDeadline(config: SessionConfigV2, phase: SessionDeadlinePhaseV2): SessionDeadlineHandleV2 {
  const deadlines = config.deadlines;
  const timeoutMs = phase === "establish"
    ? deadlines?.establishTimeoutMs ?? 30_000
    : phase === "rekey_prepare"
      ? deadlines?.rekeyPrepareTimeoutMs ?? 10_000
      : deadlines?.rekeyCompletionTimeoutMs ?? 30_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new RangeError(`${phase} timeout must be positive`);
  return (deadlines?.factory ?? defaultDeadlineFactory)(timeoutMs, phase);
}

function defaultDeadlineFactory(timeoutMs: number, phase: SessionDeadlinePhaseV2): SessionDeadlineHandleV2 {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new SessionV2Error("timeout", `${phase} deadline exceeded`));
  }, timeoutMs);
  return {
    signal: controller.signal,
    cancel: () => clearTimeout(timer),
  };
}

function combineSignals(...signals: Array<AbortSignal | undefined>): SessionDeadlineHandleV2 {
  const controller = new AbortController();
  const cleanups: Array<() => void> = [];
  const abortFrom = (signal: AbortSignal) => {
    if (!controller.signal.aborted) controller.abort(abortReason(signal));
  };
  for (const signal of signals) {
    if (signal === undefined) continue;
    const abort = () => abortFrom(signal);
    signal.addEventListener("abort", abort, { once: true });
    cleanups.push(() => signal.removeEventListener("abort", abort));
    if (signal.aborted) abortFrom(signal);
  }
  return {
    signal: controller.signal,
    cancel: () => { for (const cleanup of cleanups.splice(0)) cleanup(); },
  };
}

function signalOptions(signal: AbortSignal | undefined): OperationOptionsV2 {
  return signal === undefined ? {} : { signal };
}

function protocolError(message: string): SessionV2Error {
  return new SessionV2Error("protocol", message);
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
