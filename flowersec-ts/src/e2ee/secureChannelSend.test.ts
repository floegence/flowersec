import { describe, expect, test } from "vitest";
import { decryptRecord } from "./record.js";
import { SecureChannel } from "./secureChannel.js";
import { RECORD_FLAG_APP, RECORD_FLAG_REKEY } from "./constants.js";
import { deriveRekeyKey } from "./kdf.js";

function makeTransport() {
  const frames: Uint8Array[] = [];
  let rejectRead: ((e: unknown) => void) | null = null;

  const transport = {
    async readBinary(): Promise<Uint8Array> {
      return await new Promise<Uint8Array>((_, reject) => {
        rejectRead = reject;
      });
    },
    async writeBinary(frame: Uint8Array): Promise<void> {
      frames.push(frame);
    },
    close(): void {
      if (rejectRead != null) rejectRead(new Error("closed"));
    }
  };

  return { transport, frames, close: () => transport.close() };
}

describe("SecureChannel send queue", () => {
  test("bounds queued and in-flight outbound plaintext bytes", async () => {
    const key = new Uint8Array(32).fill(1);
    const noncePrefix = new Uint8Array(4).fill(2);
    let releaseWrite!: () => void;
    const blocked = new Promise<void>((resolve) => { releaseWrite = resolve; });
    let firstStarted!: () => void;
    const started = new Promise<void>((resolve) => { firstStarted = resolve; });
    let writeCalls = 0;
    const transport = {
      async readBinary(): Promise<Uint8Array> { return await new Promise(() => {}); },
      async writeBinary(): Promise<void> {
        writeCalls++;
        if (writeCalls === 1) {
          firstStarted();
          await blocked;
        }
      },
      close(): void {},
    };
    const sc = new SecureChannel({
      transport,
      maxRecordBytes: 1 << 20,
      maxOutboundBufferedBytes: 4,
      sendKey: key,
      recvKey: key,
      sendNoncePrefix: noncePrefix,
      recvNoncePrefix: noncePrefix,
      rekeyBase: new Uint8Array(32).fill(3),
      transcriptHash: new Uint8Array(32).fill(4),
      sendDir: 1,
      recvDir: 2,
    });

    const first = sc.write(new Uint8Array([1, 2, 3]));
    await started;
    await expect(sc.write(new Uint8Array([4, 5]))).rejects.toThrow("outbound buffer exceeded");

    releaseWrite();
    await first;
    await expect(sc.write(new Uint8Array([6, 7, 8, 9]))).resolves.toBeUndefined();
    sc.close();
  });

  test("validates the outbound byte limit", () => {
    const key = new Uint8Array(32).fill(1);
    const noncePrefix = new Uint8Array(4).fill(2);
    const { transport } = makeTransport();
    expect(() => new SecureChannel({
      transport,
      maxRecordBytes: 1 << 20,
      maxOutboundBufferedBytes: -1,
      sendKey: key,
      recvKey: key,
      sendNoncePrefix: noncePrefix,
      recvNoncePrefix: noncePrefix,
      rekeyBase: new Uint8Array(32).fill(3),
      transcriptHash: new Uint8Array(32).fill(4),
      sendDir: 1,
      recvDir: 2,
    })).toThrow("maxOutboundBufferedBytes");
  });

  test("defaults the outbound byte limit to 4 MiB", async () => {
    const key = new Uint8Array(32).fill(1);
    const noncePrefix = new Uint8Array(4).fill(2);
    const { transport } = makeTransport();
    const sc = new SecureChannel({
      transport,
      maxRecordBytes: 1 << 20,
      sendKey: key,
      recvKey: key,
      sendNoncePrefix: noncePrefix,
      recvNoncePrefix: noncePrefix,
      rekeyBase: new Uint8Array(32).fill(3),
      transcriptHash: new Uint8Array(32).fill(4),
      sendDir: 1,
      recvDir: 2,
    });

    await expect(sc.write(new Uint8Array(4 * (1 << 20) + 1))).rejects.toThrow("outbound buffer exceeded");
    sc.close();
  });

  test("defaults outbound application records to 64 KiB plaintext chunks", async () => {
    const key = new Uint8Array(32).fill(1);
    const noncePrefix = new Uint8Array(4).fill(2);
    const { transport, frames, close } = makeTransport();
    const sc = new SecureChannel({
      transport,
      maxRecordBytes: 1 << 20,
      sendKey: key,
      recvKey: key,
      sendNoncePrefix: noncePrefix,
      recvNoncePrefix: noncePrefix,
      rekeyBase: new Uint8Array(32).fill(3),
      transcriptHash: new Uint8Array(32).fill(4),
      sendDir: 1,
      recvDir: 2,
    });
    await sc.write(new Uint8Array(64 * 1024 + 1));
    expect(frames).toHaveLength(2);
    expect(decryptRecord(key, noncePrefix, frames[0]!, 1n, 1 << 20)).toMatchObject({ flags: RECORD_FLAG_APP, plaintext: { length: 64 * 1024 } });
    expect(decryptRecord(key, noncePrefix, frames[1]!, 2n, 1 << 20)).toMatchObject({ flags: RECORD_FLAG_APP, plaintext: { length: 1 } });
    sc.close();
    close();
  });

  test("rekey is ordered before subsequent app writes", async () => {
    const key = new Uint8Array(32).fill(1);
    const noncePrefix = new Uint8Array(4).fill(2);
    const rekeyBase = new Uint8Array(32).fill(3);
    const transcriptHash = new Uint8Array(32).fill(4);
    const maxRecordBytes = 1 << 20;

    const { transport, frames, close } = makeTransport();

    const sc = new SecureChannel({
      transport,
      maxRecordBytes,
      maxBufferedBytes: 0,
      sendKey: key,
      recvKey: key,
      sendNoncePrefix: noncePrefix,
      recvNoncePrefix: noncePrefix,
      rekeyBase,
      transcriptHash,
      sendDir: 1,
      recvDir: 2
    });

    const payload = new Uint8Array([9, 9, 9]);
    await Promise.all([sc.rekeyNow(), sc.write(payload)]);

    expect(frames.length).toBe(2);

    const first = decryptRecord(key, noncePrefix, frames[0]!, 1n, maxRecordBytes);
    expect(first.flags).toBe(RECORD_FLAG_REKEY);

    const nextKey = deriveRekeyKey(rekeyBase, transcriptHash, 1n, 1);
    const second = decryptRecord(nextKey, noncePrefix, frames[1]!, 2n, maxRecordBytes);
    expect(Array.from(second.plaintext)).toEqual(Array.from(payload));
    expect(() => decryptRecord(key, noncePrefix, frames[1]!, 2n, maxRecordBytes)).toThrow();

    sc.close();
    close();
  });

  test("keeps every record of one application write contiguous", async () => {
    const key = new Uint8Array(32).fill(1);
    const noncePrefix = new Uint8Array(4).fill(2);
    const frames: Uint8Array[] = [];
    let releaseFirst!: () => void;
    const firstBlocked = new Promise<void>((resolve) => { releaseFirst = resolve; });
    let firstStarted!: () => void;
    const started = new Promise<void>((resolve) => { firstStarted = resolve; });
    let writes = 0;
    const transport = {
      async readBinary(): Promise<Uint8Array> { return await new Promise(() => {}); },
      async writeBinary(frame: Uint8Array): Promise<void> {
        writes += 1;
        if (writes === 1) {
          firstStarted();
          await firstBlocked;
        }
        frames.push(frame);
      },
      close(): void {},
    };
    const sc = new SecureChannel({
      transport,
      maxRecordBytes: 1 << 20,
      outboundRecordChunkBytes: 4,
      sendKey: key,
      recvKey: key,
      sendNoncePrefix: noncePrefix,
      recvNoncePrefix: noncePrefix,
      rekeyBase: new Uint8Array(32).fill(3),
      transcriptHash: new Uint8Array(32).fill(4),
      sendDir: 1,
      recvDir: 2,
    });

    const first = sc.write(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    await started;
    const second = sc.write(new Uint8Array([9, 10, 11, 12]));
    releaseFirst();
    await Promise.all([first, second]);

    expect(frames.map((frame, index) => Array.from(decryptRecord(key, noncePrefix, frame, BigInt(index + 1), 1 << 20).plaintext))).toEqual([
      [1, 2, 3, 4],
      [5, 6, 7, 8],
      [9, 10, 11, 12],
    ]);
    sc.close();
  });
});
