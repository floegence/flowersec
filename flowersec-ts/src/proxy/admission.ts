import { SessionError } from "../public/contract.js";

export type StreamPermit = (() => void) & { resizeBody(bytes: number): void; workspace(bytes: number): () => void; retain(): () => void };

export class StreamAdmission {
  private active = 0;
  private bodyBytes = 0;
  private workspaceBytes = 0;
  private queuedBytes = 0;
  private closed = false;
  private readonly queue: Array<Readonly<{
    bytes: number;
    signal?: AbortSignal;
    cleanup(): void;
    resolve(release: StreamPermit): void;
    reject(error: Error): void;
  }>> = [];

  constructor(
    private readonly concurrent: number,
    private readonly queued: number,
    private readonly queuedBodyBytes: number,
  ) {}

  acquire(bytes: number, signal?: AbortSignal, noQueue = false): Promise<StreamPermit> {
    if (this.closed) return Promise.reject(new SessionError("closed"));
    if (signal?.aborted === true) return Promise.reject(new SessionError("canceled"));
    if (this.active < this.concurrent && this.queue.length === 0) {
      this.active++;
      return Promise.resolve(this.releaseFunction());
    }
    if (noQueue || this.queue.length >= this.queued || this.queuedBytes + bytes > this.queuedBodyBytes) {
      return Promise.reject(new SessionError("resource_exhausted"));
    }
    return new Promise((resolve, reject) => {
      let cleaned = false;
      const cleanup = () => {
        if (cleaned) return;
        cleaned = true;
        signal?.removeEventListener("abort", onAbort);
      };
      const entry = {
        bytes,
        ...(signal === undefined ? {} : { signal }),
        cleanup,
        resolve: (release: StreamPermit) => { cleanup(); resolve(release); },
        reject: (error: Error) => { cleanup(); reject(error); },
      };
      const onAbort = () => {
        const index = this.queue.indexOf(entry);
        if (index < 0) return;
        this.queue.splice(index, 1);
        this.queuedBytes -= bytes;
        entry.reject(new SessionError("canceled"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      this.queue.push(entry);
      this.queuedBytes += bytes;
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const entry of this.queue.splice(0)) entry.reject(new SessionError("closed"));
    this.queuedBytes = 0;
  }

  private releaseFunction(): StreamPermit {
    let bodyBytes = 0;
    let released = false;
    let references = 1;
    const drop = () => {
      if (--references !== 0) return;
      this.bodyBytes -= bodyBytes;
      bodyBytes = 0;
      this.active--;
      this.drain();
    };
    const release = () => { if (!released) { released = true; drop(); } };
    return Object.assign(release, {
      retain: () => {
        if (released) throw new SessionError("closed");
        references++;
        let returned = false;
        return () => { if (!returned) { returned = true; drop(); } };
      },
      resizeBody: (bytes: number) => {
        if (released) throw new SessionError("closed");
        if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes - bodyBytes > this.queuedBodyBytes - this.bodyBytes) throw new SessionError("resource_exhausted");
        this.bodyBytes += bytes - bodyBytes;
        bodyBytes = bytes;
      },
      workspace: (bytes: number) => {
        if (released) throw new SessionError("closed");
        if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > this.queuedBodyBytes - this.workspaceBytes) throw new SessionError("resource_exhausted");
        this.workspaceBytes += bytes;
        let returned = false;
        return () => { if (!returned) { returned = true; this.workspaceBytes -= bytes; } };
      },
    });
  }

  private drain(): void {
    while (!this.closed && this.active < this.concurrent && this.queue.length > 0) {
      const entry = this.queue.shift()!;
      this.queuedBytes -= entry.bytes;
      if (entry.signal?.aborted === true) {
        entry.reject(new SessionError("canceled"));
        continue;
      }
      this.active++;
      entry.resolve(this.releaseFunction());
    }
  }
}
