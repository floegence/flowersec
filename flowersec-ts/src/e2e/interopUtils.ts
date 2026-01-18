export type LineReader = {
  nextLine: (timeoutMs: number) => Promise<string>;
};

export function createLineReader(stream: NodeJS.ReadableStream | null): LineReader {
  let buf = "";
  stream?.setEncoding("utf8");
  stream?.on("data", (d: string) => {
    buf += d;
  });
  return {
    nextLine: async (timeoutMs: number) => {
      const start = Date.now();
      while (Date.now() - start < timeoutMs) {
        const idx = buf.indexOf("\n");
        if (idx >= 0) {
          const line = buf.slice(0, idx);
          buf = buf.slice(idx + 1);
          return line;
        }
        await delay(10);
      }
      throw new Error("timeout waiting for harness output");
    }
  };
}

export function createTextBuffer(stream: NodeJS.ReadableStream | null): () => string {
  let buf = "";
  stream?.setEncoding("utf8");
  stream?.on("data", (d: string) => {
    buf += d;
  });
  return () => buf;
}

export async function readJsonLine<T>(reader: LineReader, timeoutMs: number): Promise<T> {
  const line = await reader.nextLine(timeoutMs);
  return JSON.parse(line) as T;
}

export async function withTimeout<T>(label: string, timeoutMs: number, task: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`timeout waiting for ${label}`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([task, timeout]);
  } finally {
    if (timer != null) clearTimeout(timer);
  }
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
