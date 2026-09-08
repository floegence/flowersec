import { Duplex } from "node:stream";
import type { ByteStream } from "../public/contract.js";

/** A bounded Node stream that owns one application ByteStream, including half-close. */
export function createByteStreamDuplex(stream: ByteStream, signal?: AbortSignal): Duplex {
  const operations = new AbortController();
  let reading = false;
  let ended = false;
  let duplex: Duplex;
  const abort = (): void => { duplex.destroy(new Error("Application stream canceled")); };
  duplex = new Duplex({
    allowHalfOpen: true,
    readableHighWaterMark: 64 * 1024,
    writableHighWaterMark: 64 * 1024,
    read() {
      if (reading || ended) return;
      reading = true;
      void (async () => {
        try {
          while (!duplex.destroyed) {
            const chunk = await stream.read({ signal: operations.signal });
            if (chunk === null) {
              ended = true;
              duplex.push(null);
              return;
            }
            if (chunk.byteLength && !duplex.push(chunk)) return;
          }
        } catch {
          duplex.destroy(new Error("Application stream read failed"));
        } finally {
          reading = false;
        }
      })();
    },
    write(chunk: Buffer, _encoding, callback) {
      void (async () => {
        try {
          for (let offset = 0; offset < chunk.byteLength;) {
            const part = chunk.subarray(offset, Math.min(offset + 64 * 1024, chunk.byteLength));
            const count = await stream.write(part, { signal: operations.signal });
            if (!Number.isSafeInteger(count) || count <= 0 || count > part.byteLength) {
              throw new Error("Invalid application stream write result");
            }
            offset += count;
          }
          callback();
        } catch {
          callback(new Error("Application stream write failed"));
        }
      })();
    },
    final(callback) {
      void stream.closeWrite().then(() => callback(), () => callback(new Error("Application stream half-close failed")));
    },
    destroy(error, callback) {
      signal?.removeEventListener("abort", abort);
      operations.abort();
      void (error ? stream.reset() : stream.close()).then(
        () => callback(error),
        () => callback(error ?? new Error("Application stream close failed")),
      );
    },
  });
  signal?.addEventListener("abort", abort, { once: true });
  if (signal?.aborted) queueMicrotask(abort);
  return duplex;
}
