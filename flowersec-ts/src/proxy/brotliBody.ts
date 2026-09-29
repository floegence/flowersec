// The worker receives this function as source, so it must be self-contained.
// The fixed decoder is used for br on every host; there is no format fallback.
export interface BrotliDecoder {
  dec(input: Uint8Array, outputSize: number): {
    readonly code: number;
    readonly input_offset: number;
    readonly buf: Uint8Array<ArrayBuffer>;
    free(): void;
  };
  free(): void;
}

export function decodeBrotliBody(
  input: ReadableStream<Uint8Array<ArrayBuffer>>,
  limit: number,
  createDecoder: () => BrotliDecoder,
): ReadableStream<Uint8Array<ArrayBuffer>> {
  const decoder = createDecoder();
  const reader = input.getReader();
  let chunk = new Uint8Array(0);
  let offset = 0;
  let total = 0;
  let code = 2;
  let closed = false;
  const dispose = () => {
    if (closed) return;
    closed = true;
    decoder.free();
    chunk = new Uint8Array(0);
  };
  return new ReadableStream<Uint8Array<ArrayBuffer>>({
    async pull(controller) {
      try {
        for (;;) {
          if (closed) return;
          if (offset === chunk.length && code !== 3) {
            const next = await reader.read();
            if (closed) return;
            if (next.done) {
              if (code !== 1) throw new TypeError("truncated brotli body");
              dispose();
              reader.releaseLock();
              controller.close();
              return;
            }
            chunk = next.value;
            offset = 0;
          }
          if (chunk.length === offset && code !== 3) continue;
          if (code === 1) throw new TypeError("trailing brotli body");
          // Bound each output allocation before calling the decoder. One byte
          // beyond the remaining cap detects expansion without publishing it.
          const result = decoder.dec(chunk.subarray(offset), Math.min(65_536, limit - total + 1));
          let output: Uint8Array<ArrayBuffer>;
          try {
            const consumed = result.input_offset;
            code = result.code;
            output = result.buf;
            if (!Number.isInteger(consumed) || consumed < 0 || consumed > chunk.length - offset || ![1, 2, 3].includes(code)) {
              throw new TypeError("invalid brotli decoder result");
            }
            offset += consumed;
            if (code === 1 && offset !== chunk.length) throw new TypeError("trailing brotli body");
            if (code === 2 && offset !== chunk.length) throw new TypeError("incomplete brotli input consumption");
            if (code === 3 && consumed === 0 && output.length === 0) throw new TypeError("brotli decoder made no progress");
          } finally {
            result.free();
          }
          total += output.length;
          if (total > limit) throw new RangeError("proxy decoded body exceeds limit");
          if (output.length !== 0) {
            controller.enqueue(output);
            return;
          }
        }
      } catch (error) {
        dispose();
        controller.error(error);
        await reader.cancel(error).catch(() => undefined);
        reader.releaseLock();
      }
    },
    async cancel(reason) {
      dispose();
      await reader.cancel(reason).catch(() => undefined);
      reader.releaseLock();
    },
  });
}
