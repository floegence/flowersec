import { describe, expect, test } from "vitest";
import { decryptRecord, encryptRecord } from "./record.js";
import { SecureChannel } from "./secureChannel.js";
import { RECORD_FLAG_APP, RECORD_FLAG_PING, RECORD_FLAG_REKEY } from "./constants.js";
import { deriveRekeyKey } from "./kdf.js";

type BinaryTransport = {
  readBinary(): Promise<Uint8Array>;
  writeBinary(frame: Uint8Array): Promise<void>;
  close(): void;
};

function makeQueueTransport(): {
  transport: BinaryTransport;
  push: (frame: Uint8Array) => void;
  writes: Uint8Array[];
  close: () => void;
} {
  const reads: Uint8Array[] = [];
  const waiters: Array<{ resolve: (frame: Uint8Array) => void; reject: (e: unknown) => void }> = [];
  const writes: Uint8Array[] = [];
  let closed = false;
  let closedError: unknown = null;

  const transport: BinaryTransport = {
    async readBinary() {
      if (closedError != null) throw closedError;
      if (reads.length > 0) return reads.shift()!;
      return await new Promise<Uint8Array>((resolve, reject) => {
        if (closedError != null || closed) {
          reject(closedError ?? new Error("closed"));
          return;
        }
        waiters.push({ resolve, reject });
      });
    },
    async writeBinary(frame: Uint8Array) {
      writes.push(frame);
    },
    close() {
      closed = true;
      closedError = new Error("closed");
      while (waiters.length > 0) {
        const w = waiters.shift();
        w?.reject(closedError);
      }
    }
  };

  return {
    transport,
    writes,
    push: (frame) => {
      const w = waiters.shift();
      if (w != null) w.resolve(frame);
      else reads.push(frame);
    },
    close: () => transport.close()
  };
}

describe("SecureChannel", () => {
  test("sendPing and rekeyNow emit expected flags", async () => {
    const key = new Uint8Array(32).fill(7);
    const noncePrefix = new Uint8Array(4).fill(9);
    const rekeyBase = new Uint8Array(32).fill(3);
    const transcriptHash = new Uint8Array(32).fill(5);
    const { transport, writes, close } = makeQueueTransport();

    const sc = new SecureChannel({
      transport,
      maxRecordBytes: 1 << 20,
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

    await sc.sendPing();
    await sc.rekeyNow();

    expect(writes.length).toBe(2);
    const ping = decryptRecord(key, noncePrefix, writes[0]!, 1n, 1 << 20);
    expect(ping.flags).toBe(RECORD_FLAG_PING);
    const rekey = decryptRecord(key, noncePrefix, writes[1]!, 2n, 1 << 20);
    expect(rekey.flags).toBe(RECORD_FLAG_REKEY);

    sc.close();
    close();
  });

  test("recv rekey updates receive key", async () => {
    const key = new Uint8Array(32).fill(1);
    const noncePrefix = new Uint8Array(4).fill(2);
    const rekeyBase = new Uint8Array(32).fill(3);
    const transcriptHash = new Uint8Array(32).fill(4);
    const maxRecordBytes = 1 << 20;

    const { transport, push, close } = makeQueueTransport();
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

    const rekeyFrame = encryptRecord(key, noncePrefix, RECORD_FLAG_REKEY, 1n, new Uint8Array(), maxRecordBytes);
    const nextKey = deriveRekeyKey(rekeyBase, transcriptHash, 1n, 2);
    const appFrame = encryptRecord(nextKey, noncePrefix, RECORD_FLAG_APP, 2n, new Uint8Array([9, 9]), maxRecordBytes);

    const readPromise = sc.read();
    push(rekeyFrame);
    push(appFrame);

    await expect(readPromise).resolves.toEqual(new Uint8Array([9, 9]));

    sc.close();
    close();
  });

  test("unknown record flag rejects reads", async () => {
    const key = new Uint8Array(32).fill(1);
    const noncePrefix = new Uint8Array(4).fill(2);
    const rekeyBase = new Uint8Array(32).fill(3);
    const transcriptHash = new Uint8Array(32).fill(4);
    const maxRecordBytes = 1 << 20;

    const { transport, push, close } = makeQueueTransport();
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

    const valid = encryptRecord(key, noncePrefix, RECORD_FLAG_APP, 1n, new Uint8Array([1]), maxRecordBytes);
    const bad = valid.slice();
    bad[5] = 9;
    const readPromise = sc.read();
    push(bad);

    await expect(readPromise).rejects.toThrow(/bad record flag|unknown record flag/);

    sc.close();
    close();
  });

  test("write errors fail senders", async () => {
    const err = new Error("write failed");
    let readReject: ((e: unknown) => void) | null = null;
    const transport: BinaryTransport = {
      async readBinary() {
        return await new Promise<Uint8Array>((_resolve, reject) => {
          readReject = reject;
        });
      },
      async writeBinary() {
        throw err;
      },
      close() {
        readReject?.(new Error("closed"));
      }
    };
    const sc = new SecureChannel({
      transport,
      maxRecordBytes: 1 << 20,
      maxBufferedBytes: 0,
      sendKey: new Uint8Array(32),
      recvKey: new Uint8Array(32),
      sendNoncePrefix: new Uint8Array(4),
      recvNoncePrefix: new Uint8Array(4),
      rekeyBase: new Uint8Array(32),
      transcriptHash: new Uint8Array(32),
      sendDir: 1,
      recvDir: 2
    });

    await expect(sc.write(new Uint8Array([1, 2]))).rejects.toThrow(/write failed/);
  });

  test("close rejects pending reads", async () => {
    const { transport, close } = makeQueueTransport();
    const sc = new SecureChannel({
      transport,
      maxRecordBytes: 1 << 20,
      maxBufferedBytes: 0,
      sendKey: new Uint8Array(32),
      recvKey: new Uint8Array(32),
      sendNoncePrefix: new Uint8Array(4),
      recvNoncePrefix: new Uint8Array(4),
      rekeyBase: new Uint8Array(32),
      transcriptHash: new Uint8Array(32),
      sendDir: 1,
      recvDir: 2
    });

    const readPromise = sc.read();
    sc.close();
    close();

    await expect(readPromise).rejects.toThrow(/closed/);
  });

  test("close rejects new writes", async () => {
    const { transport, close } = makeQueueTransport();
    const sc = new SecureChannel({
      transport,
      maxRecordBytes: 1 << 20,
      maxBufferedBytes: 0,
      sendKey: new Uint8Array(32),
      recvKey: new Uint8Array(32),
      sendNoncePrefix: new Uint8Array(4),
      recvNoncePrefix: new Uint8Array(4),
      rekeyBase: new Uint8Array(32),
      transcriptHash: new Uint8Array(32),
      sendDir: 1,
      recvDir: 2
    });

    sc.close();
    close();
    await expect(sc.write(new Uint8Array([1]))).rejects.toThrow(/closed/);
  });

  test("sendLoop preserves order under failures", async () => {
    const writes: Uint8Array[] = [];
    let fail = false;
    let readReject: ((e: unknown) => void) | null = null;
    const transport: BinaryTransport = {
      async readBinary() {
        return await new Promise<Uint8Array>((_resolve, reject) => {
          readReject = reject;
        });
      },
      async writeBinary(frame) {
        writes.push(frame);
        if (fail) throw new Error("boom");
      },
      close() {
        readReject?.(new Error("closed"));
      }
    };
    const sc = new SecureChannel({
      transport,
      maxRecordBytes: 1 << 20,
      maxBufferedBytes: 0,
      sendKey: new Uint8Array(32).fill(1),
      recvKey: new Uint8Array(32).fill(1),
      sendNoncePrefix: new Uint8Array(4),
      recvNoncePrefix: new Uint8Array(4),
      rekeyBase: new Uint8Array(32),
      transcriptHash: new Uint8Array(32),
      sendDir: 1,
      recvDir: 2
    });

    await sc.write(new Uint8Array([1]));
    fail = true;
    await expect(sc.write(new Uint8Array([2]))).rejects.toThrow(/boom/);

    expect(writes.length).toBe(2);
  });
});
