import { describe, expect, it } from "vitest";
import { promiseHooks } from "node:v8";
import { V4ReaderCursor } from "./public.js";
import { TrustedClock, trustedClockCharge } from "./runtime/clock.js";
import { ClockRate } from "./runtime/timeArithmetic.js";
import { TrustedDeadline } from "./runtime/deadline.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { CryptoUsageLedger, cryptoUsageCharge } from "./runtime/cryptoUsage.js";
import type { RecordCipher, RecordPacket} from "./runtime/recordCrypto.js";
import { RecordEpoch, recordCipherCharge, recordEpochCharge } from "./runtime/recordCrypto.js";
import { EnvelopeDecoder, envelopeDecoderCharge } from "./runtime/envelope.js";
import {
  ReceiveDeliveryGate, ReliableReceiveDirection, receiveCursorCharge,
  receiveDecoderCharge, receiveDeliveryCharge, receiveDirectionCharge,
} from "./runtime/receiveDirection.js";
import { wire } from "./runtime/wireRegistry.js";
import { encode, uint, type Value } from "./testSupport/cbor.js";

const text = new TextEncoder();
const string = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const profiles = ["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"];
async function settle() { for (let i = 0; i < 12; i++) await Promise.resolve(); }

// The fixture supplies a deterministic trusted clock and admitted record keys.
// Actual AEAD, ResourceRoot, strict wire decoding and the receive owner run here;
// this is not evidence for transport admission, provider I/O or maintenance.
function fixture(profile = profiles[0]!) {
  let tick = 0n, nextOwner = 1n;
  const limit = new ResourceVector([64n * 1024n * 1024n, 0n, 0n, 10000n, 100n, 100n, 100n, 100n, 100n, 100n, 100n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 8, reservations: 40, references: 80,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const tenant = "1".repeat(32), environment = "2".repeat(32);
  const scopes = [root.account("tenant", tenant, limit), root.account("environment", environment, limit)];
  const reserve = (kind: string, charge: ResourceVector) => root.reserve({
    owner: { tenant, environment, kind, backing: (nextOwner++).toString(16).padStart(32, "0") }, charge, accounts: scopes,
  });
  const clock = new TrustedClock({ rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 100000n, maxRoundTripMS: 100n },
    () => ({ milliseconds: tick, incarnation: "3".repeat(32) }), 128n, reserve("clock", trustedClockCharge(128n)));
  clock.installTrusted(clock.monotonic(), { lowerMS: 1000n, upperMS: 1000n });
  const deadline = new TrustedDeadline(clock, 10000n);
  const usageConfig = { clock, profile, keys: 8, maintenance: { calls: 1n, blocks: 1n, bytes: 1n }, runtimeBytes: 128n };
  const senderLedger = new CryptoUsageLedger({ ...usageConfig, sendDirection: 0 }, reserve("send_ledger", cryptoUsageCharge({ ...usageConfig, sendDirection: 0 })));
  const receiverLedger = new CryptoUsageLedger({ ...usageConfig, sendDirection: 1 }, reserve("receive_ledger", cryptoUsageCharge({ ...usageConfig, sendDirection: 1 })));
  const epochConfig = { clock, born: clock.sample(), authorizationDeadline: deadline, epoch: 0, runtimeBytes: 128n };
  const senderEpoch = new RecordEpoch(epochConfig, new Uint8Array(32).fill(7), new Uint8Array(32).fill(9), senderLedger, reserve("send_epoch", recordEpochCharge(128n)));
  const receiverEpoch = new RecordEpoch(epochConfig, new Uint8Array(32).fill(7), new Uint8Array(32).fill(9), receiverLedger, reserve("receive_epoch", recordEpochCharge(128n)));
  const cipherConfig = { maxFrame: 512, runtimeBytes: 128n };
  const authorization = { check: () => deadline.check() };
  const sender = senderEpoch.derive(1n, 0, cipherConfig, authorization, reserve("send_key", recordCipherCharge(cipherConfig)));
  const receiver = receiverEpoch.derive(1n, 0, cipherConfig, authorization, reserve("receive_key", recordCipherCharge(cipherConfig)));
  const envelopeConfig = { maxFrame: 512, mode: "message" as const, runtimeBytes: 128n };
  const envelope = new EnvelopeDecoder(envelopeConfig, reserve("envelope", envelopeDecoderCharge(envelopeConfig)));
  const gate = new ReceiveDeliveryGate(deadline, 128n, reserve("delivery", receiveDeliveryCharge(128n)));
  const config = { maxDataBytes: 64, queueBytes: 32, maxCursorBytes: 64, receiveLimit: 32n,
    runtimeBytes: 256n, cursorRuntimeBytes: 256n, decoderRuntimeBytes: 256n };
  const directionReservation = reserve("receive_queue", receiveDirectionCharge(config));
  const decoderReservation = reserve("receive_decoder", receiveDecoderCharge(config));
  const cursorReservation = reserve("receive_cursor", receiveCursorCharge(config));
  const direction = new ReliableReceiveDirection(config, receiver, gate,
    { root, direction: directionReservation, decoder: decoderReservation, cursor: cursorReservation });
  const streamDataType = wire.frame_types.STREAM_DATA;
  if (streamDataType === undefined) throw new Error("STREAM_DATA is missing from the wire registry");
  let sequence = 0n;
  const packet = (data: string, offset: bigint, fin = false, overrides: Partial<{ scope: bigint; direction: bigint; sequence: bigint; epoch: bigint }> = {}): RecordPacket => {
    const fields: Value[] = [uint(overrides.scope ?? 1n), uint(overrides.direction ?? 0n), uint(overrides.epoch ?? 0n),
      uint(overrides.sequence ?? sequence++), uint(offset), { kind: "bool", value: fin }, { kind: "bytes", value: text.encode(data) }];
    const plaintext = encode({ kind: "map", value: fields.map((value, i) => [uint(BigInt(i)), value]) });
    const sealed = sender.seal(streamDataType, plaintext);
    const bytes = new Uint8Array(520), count = sealed.copyBytes(bytes); sealed.release();
    const frame = envelope.message(bytes.subarray(0, count));
    try { return receiver.open(frame); } finally { frame.release(); }
  };
  return { root, gate, direction, config, sender, receiver, packet, deadline,
    setTick: (value: bigint) => { tick = value; },
    close: () => {
      direction.close(); gate.close(); sender.close(); receiver.close(); envelope.close();
      senderEpoch.close(); receiverEpoch.close(); senderLedger.close(); receiverLedger.close(); clock.close();
      expect(root.snapshot().reservations).toBe(0);
    },
    makeForeignReceiver: () => receiverEpoch.derive(3n, 0, cipherConfig, authorization, reserve("other_key", recordCipherCharge(cipherConfig))),
  };
}

describe("bounded v4 authenticated receive direction", () => {
  it("does not recycle a raw read owner inside its public resolver", async () => {
    const f = fixture();
    let output: Promise<unknown> | undefined;
    let observed = false;
    const stop = promiseHooks.createHook({ settled(promise) {
      if (promise !== output) return;
      observed = true;
      f.direction.close();
      expect(f.direction.cleanupStatus().status).toBe("pending");
    } });
    try {
      f.direction.accept(f.packet("abc", 0n));
      output = f.direction.read(3n);
      expect(f.direction.progress().released_offset).toBe(0n);
      const result = await output;
      expect(result).toMatchObject({ progress: { filled: 3n }, wait_status: "ready" });
      expect(observed).toBe(true);
      expect(f.direction.cleanupStatus().status).toBe("complete");
    } finally { stop(); f.close(); }
  });

  for (const profile of profiles) {
    it(`moves authenticated bytes through cursor and raw read with ${profile}`, async () => {
      const f = fixture(profile);
      try {
        f.direction.accept(f.packet("ab\ntail", 0n, true));
        expect(f.direction.progress()).toMatchObject({ ack_offset: 7n, released_offset: 0n, queued_bytes: 7n });
        const cursor = new V4ReaderCursor(f.direction, { delimiter: text.encode("\n"), maxBytes: 6n });
        const line = await cursor.readLine();
        expect(string(line.data)).toBe("ab\n");
        expect(line.progress).toEqual({ offset: 3n, filled: 3n, target: 6n });
        expect(f.direction.progress()).toMatchObject({ ack_offset: 7n, released_offset: 3n, queued_bytes: 4n });
        const tail = await f.direction.read(10n);
        expect(string(tail.data)).toBe("tail");
        expect(tail).toMatchObject({ stream_status: "eof", progress: { offset: 7n, filled: 4n } });
        expect(tail.progress.target).toBeUndefined();
        expect(f.direction.progress().released_offset).toBe(7n);
        line.data.fill(0); expect(string(tail.data)).toBe("tail");
      } finally { f.close(); }
    });
  }

  it("enforces one actual direction across raw read and every cursor", async () => {
    const f = fixture();
    try {
      const cursor = new V4ReaderCursor(f.direction, { exact: 4n });
      const controller = new AbortController();
      const wait = cursor.readExactly({ signal: controller.signal });
      await settle();
      await expect(f.direction.read(1n)).rejects.toThrow("read_in_progress");
      expect(() => new V4ReaderCursor(f.direction, { exact: 0n })).toThrow("read_in_progress");
      f.direction.accept(f.packet("ab", 0n));
      await settle(); controller.abort();
      expect(await wait).toMatchObject({ wait_status: "wait_canceled", progress: { offset: 2n, filled: 0n } });
      expect(cursor.progress().transferred_bytes).toBe(2n);
      f.direction.accept(f.packet("cdsuffix", 2n));
      const result = await cursor.readExactly();
      expect(string(result.data)).toBe("abcd");
      expect(f.direction.progress()).toMatchObject({ ack_offset: 10n, released_offset: 4n, queued_bytes: 6n });
      expect(string((await f.direction.read(6n)).data)).toBe("suffix");
    } finally { f.close(); }
  });

  it("ordinary wait cancellation leaves subsequently authenticated input for its next owner", async () => {
    const f = fixture();
    try {
      const controller = new AbortController();
      const read = f.direction.read(3n, { signal: controller.signal });
      controller.abort();
      expect(await read).toMatchObject({ wait_status: "wait_canceled", progress: { offset: 0n, filled: 0n } });
      f.direction.accept(f.packet("abc", 0n));
      expect(f.direction.progress().released_offset).toBe(0n);
      expect(string((await f.direction.read(3n)).data)).toBe("abc");
    } finally { f.close(); }
  });

  it("retains private prefix charges after a canceled wait and releases them on Close", async () => {
    const f = fixture();
    try {
      const charged = f.root.snapshot().charged.values()[0];
      const cursor = new V4ReaderCursor(f.direction, { exact: 8n });
      const controller = new AbortController();
      const wait = cursor.readExactly({ signal: controller.signal });
      f.direction.accept(f.packet("abc", 0n));
      await settle(); controller.abort(); await wait;
      expect(f.root.snapshot().charged.values()[0]).toBe(charged);
      f.direction.close();
      expect(f.direction.cleanupStatus().status).toBe("pending");
      cursor.close(); await settle();
      expect(f.direction.cleanupStatus().status).toBe("complete");
      expect(f.root.snapshot().charged.values()[0]! < charged!).toBe(true);
    } finally { f.close(); }
  });

  it("normal I/O close preserves an authorized completed cursor candidate", async () => {
    const f = fixture();
    try {
      const cursor = new V4ReaderCursor(f.direction, { exact: 3n });
      const controller = new AbortController();
      const wait = cursor.readExactly({ signal: controller.signal });
      await settle(); controller.abort(); await wait;
      f.direction.accept(f.packet("abc", 0n));
      await settle();
      f.direction.close();
      const result = await cursor.readExactly();
      expect(string(result.data)).toBe("abc");
      expect(result.progress.offset).toBe(3n);
      expect(f.direction.cleanupStatus().status).toBe("complete");
    } finally { f.close(); }
  });

  it("revocation wakes outstanding reads and cannot release an unclaimed prefix to the application", async () => {
    const f = fixture();
    const cursor = new V4ReaderCursor(f.direction, { exact: 8n });
    try {
      const read = cursor.readExactly();
      const failed = expect(read).rejects.toThrow("authorization_denied");
      f.direction.accept(f.packet("abc", 0n)); await settle();
      f.gate.close("authorization_denied");
      await failed;
      expect(cursor.progress()).toMatchObject({ transferred_bytes: 3n, delivered: false });
      expect(f.gate.cleanupStatus().status).toBe("pending");
      cursor.close(); await settle();
      expect(f.gate.cleanupStatus().status).toBe("complete");
    } finally { cursor.close(); f.close(); }
  });

  it("checks the original trusted deadline again at candidate delivery", async () => {
    const f = fixture();
    const cursor = new V4ReaderCursor(f.direction, { exact: 3n });
    try {
      const controller = new AbortController();
      const wait = cursor.readExactly({ signal: controller.signal });
      await settle(); controller.abort(); await wait;
      f.direction.accept(f.packet("abc", 0n)); await settle();
      f.setTick(9000n);
      await expect(cursor.readExactly()).rejects.toThrow("authorization_denied");
      expect(cursor.progress().delivered).toBe(false);
    } finally { cursor.close(); f.close(); }
  });

  it("rejects plaintext header contradictions before ACK or delivery can advance", () => {
    const f = fixture();
    try {
      expect(() => f.direction.accept(f.packet("bad", 0n, false, { direction: 1n }))).toThrow("receive_data");
      expect(f.direction.progress()).toMatchObject({ ack_offset: 0n, released_offset: 0n, queued_bytes: 0n });
      expect(f.direction.state()).toMatchObject({ stream_status: "error", error: { code: "stream_data_invalid" } });
    } finally { f.close(); }
  });

  it("does not treat a released prefix as permission to exceed the published credit", async () => {
    const f = fixture();
    try {
      f.direction.accept(f.packet("a".repeat(32), 0n));
      expect((await f.direction.read(32n)).data.length).toBe(32);
      expect(f.direction.progress()).toMatchObject({ released_offset: 32n, receive_limit: 32n });
      expect(() => f.direction.accept(f.packet("x", 32n))).toThrow("receive_credit");
      expect(f.direction.progress().ack_offset).toBe(32n);
    } finally { f.close(); }
  });

  it("rejects cursor capacity before acquiring a reader or consuming queue input", async () => {
    const f = fixture();
    try {
      f.direction.accept(f.packet("a", 0n, true));
      expect(() => new V4ReaderCursor(f.direction, { exact: 65n })).toThrow("invalid_argument");
      expect(f.direction.progress().released_offset).toBe(0n);
      expect(string((await f.direction.read(1n)).data)).toBe("a");
    } finally { f.close(); }
  });

  it("binds packet capabilities to the exact receive cipher", () => {
    const f = fixture();
    const foreign: RecordCipher = f.makeForeignReceiver();
    try {
      const packet = f.packet("abc", 0n);
      expect(() => foreign.inspectIncoming(packet)).toThrow("record_released");
      f.direction.accept(packet);
      expect(f.direction.progress().ack_offset).toBe(3n);
    } finally { foreign.close(); f.close(); }
  });
});
