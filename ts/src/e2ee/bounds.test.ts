import { describe, expect, test } from "vitest";
import { encryptRecord, decryptRecord } from "./record.js";
import { SecureChannel } from "./secureChannel.js";
import { RECORD_FLAG_APP } from "./constants.js";

type BinaryTransport = {
  readBinary(): Promise<Uint8Array>;
  writeBinary(frame: Uint8Array): Promise<void>;
  close(): void;
};

describe("e2ee bounds", () => {
  test("SecureChannel fails fast when recv buffer exceeds maxBufferedBytes", async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const noncePrefix = crypto.getRandomValues(new Uint8Array(4));
    const maxRecordBytes = 1 << 20;

    const frame = encryptRecord(key, noncePrefix, RECORD_FLAG_APP, 1n, new Uint8Array(10), maxRecordBytes);

    let closed = false;
    const transport: BinaryTransport = {
      async readBinary() {
        return frame;
      },
      async writeBinary() {},
      close() {
        closed = true;
      }
    };

    const sc = new SecureChannel({
      transport,
      maxRecordBytes,
      maxBufferedBytes: 5,
      sendKey: key,
      recvKey: key,
      sendNoncePrefix: noncePrefix,
      recvNoncePrefix: noncePrefix,
      rekeyBase: crypto.getRandomValues(new Uint8Array(32)),
      transcriptHash: crypto.getRandomValues(new Uint8Array(32)),
      sendDir: 1,
      recvDir: 2
    });

    await expect(sc.read()).rejects.toThrow(/recv buffer exceeded/);
    expect(closed).toBe(true);
  });

  test("decryptRecord error does not include the full frame payload", () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const wrongKey = crypto.getRandomValues(new Uint8Array(32));
    const noncePrefix = crypto.getRandomValues(new Uint8Array(4));
    const maxRecordBytes = 1 << 20;

    const frame = encryptRecord(key, noncePrefix, RECORD_FLAG_APP, 1n, new Uint8Array([1, 2, 3]), maxRecordBytes);
    try {
      decryptRecord(wrongKey, noncePrefix, frame, 1n, maxRecordBytes);
      throw new Error("expected decryptRecord to throw");
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      expect(msg).toMatch(/len=\d+/);
      expect(msg).not.toMatch(/frame=/);
    }
  });
});
