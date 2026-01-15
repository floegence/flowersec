import { describe, expect, test } from "vitest";
import { decryptRecord } from "./record.js";
import { SecureChannel } from "./secureChannel.js";
import { RECORD_FLAG_REKEY } from "./constants.js";
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
});
