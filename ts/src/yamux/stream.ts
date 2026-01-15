import { concatBytes } from "../utils/bin.js";
import { encodeHeader } from "./header.js";
import {
  DEFAULT_MAX_STREAM_WINDOW,
  FLAG_ACK,
  FLAG_FIN,
  FLAG_RST,
  FLAG_SYN,
  TYPE_DATA,
  TYPE_WINDOW_UPDATE
} from "./constants.js";
import type { YamuxSession } from "./session.js";

type StreamState =
  | "init"
  | "synSent"
  | "synReceived"
  | "established"
  | "localClose"
  | "remoteClose"
  | "closed"
  | "reset";

// YamuxStream manages per-stream flow control and state transitions.
export class YamuxStream {
  // Stream identifier within the session.
  readonly id: number;
  // Current stream state in the yamux state machine.
  private state: StreamState;
  // Parent session used for frame IO and window coordination.
  private readonly session: YamuxSession;

  // Remaining receive window advertised to the peer.
  private recvWindow = DEFAULT_MAX_STREAM_WINDOW;
  // Remaining send window credit granted by the peer.
  private sendWindow = DEFAULT_MAX_STREAM_WINDOW;

  // Buffered inbound data chunks.
  private readonly recvQueue: Uint8Array[] = [];
  // Total buffered bytes in recvQueue.
  private recvQueueBytes = 0;
  // Readers waiting for incoming data or EOF/reset.
  private readWaiters: Array<() => void> = [];
  // Terminal error (reset/overflow) for the stream.
  private error: unknown = null;

  constructor(session: YamuxSession, id: number, state: StreamState) {
    this.session = session;
    this.id = id;
    this.state = state;
  }

  // open sends the initial window update to establish the stream.
  async open(): Promise<void> {
    await this.sendWindowUpdate();
  }

  // onData handles inbound DATA frames and updates receive window.
  onData(data: Uint8Array, flags: number): void {
    this.processFlags(flags);
    if (data.length === 0) return;
    if (data.length > this.recvWindow) {
      this.reset(new Error("recv window exceeded"));
      return;
    }
    this.recvWindow -= data.length;
    this.recvQueue.push(data);
    this.recvQueueBytes += data.length;
    const ws = this.readWaiters;
    this.readWaiters = [];
    for (const w of ws) w();
  }

  // onWindowUpdate applies flow-control credits from peer.
  onWindowUpdate(delta: number, flags: number): void {
    this.processFlags(flags);
    this.sendWindow += delta >>> 0;
    this.session.notifySendWindow(this.id);
  }

  // read resolves with the next data chunk or throws on EOF/reset.
  async read(): Promise<Uint8Array> {
    while (true) {
      if (this.error != null) throw this.error;
      const b = this.recvQueue.shift();
      if (b != null) {
        this.recvQueueBytes -= b.length;
        await this.sendWindowUpdate();
        return b;
      }
      if (this.state === "closed" || this.state === "remoteClose") throw new Error("eof");
      await new Promise<void>((resolve) => this.readWaiters.push(resolve));
    }
  }

  // write sends DATA frames, respecting the send window.
  async write(data: Uint8Array): Promise<void> {
    if (this.state === "reset") throw new Error("stream reset");
    if (this.state === "closed" || this.state === "localClose") throw new Error("stream closed");

    let off = 0;
    while (off < data.length) {
      const chunk = data.subarray(off);
      const allowed = await this.waitForSendWindow(chunk.length);
      const sendChunk = chunk.subarray(0, allowed);
      const flags = this.sendFlags();
      this.sendWindow -= sendChunk.length;
      const hdr = encodeHeader({
        type: TYPE_DATA,
        flags,
        streamId: this.id,
        length: sendChunk.length
      });
      await this.session.writeRaw(concatBytes([hdr, sendChunk]));
      off += sendChunk.length;
    }
  }

  // close sends FIN and transitions to local close.
  async close(): Promise<void> {
    if (this.state === "closed") return;
    if (this.state === "reset") return;
    this.state = "localClose";
    const flags = this.sendFlags() | FLAG_FIN;
    const hdr = encodeHeader({
      type: TYPE_WINDOW_UPDATE,
      flags,
      streamId: this.id,
      length: 0
    });
    await this.session.writeRaw(hdr);
  }

  // reset tears down the stream and notifies the peer.
  reset(err: Error): void {
    if (this.state === "reset") return;
    this.state = "reset";
    this.error = err;
    const ws = this.readWaiters;
    this.readWaiters = [];
    for (const w of ws) w();
    void this.session.sendRst(this.id);
  }

  // processFlags updates the state machine for ACK/FIN/RST.
  private processFlags(flags: number): void {
    if ((flags & FLAG_ACK) !== 0) {
      if (this.state === "synSent") this.state = "established";
      this.session.onStreamEstablished(this.id);
    }
    if ((flags & FLAG_FIN) !== 0) {
      if (this.state === "localClose") {
        this.state = "closed";
      } else if (this.state === "established" || this.state === "synSent" || this.state === "synReceived") {
        this.state = "remoteClose";
      }
      const ws = this.readWaiters;
      this.readWaiters = [];
      for (const w of ws) w();
    }
    if ((flags & FLAG_RST) !== 0) {
      this.reset(new Error("rst"));
    }
  }

  // sendFlags returns any SYN/ACK flags needed for the current state.
  private sendFlags(): number {
    if (this.state === "init") {
      this.state = "synSent";
      return FLAG_SYN;
    }
    if (this.state === "synReceived") {
      this.state = "established";
      return FLAG_ACK;
    }
    return 0;
  }

  // sendWindowUpdate advertises the current receive window to the peer.
  private async sendWindowUpdate(): Promise<void> {
    const max = DEFAULT_MAX_STREAM_WINDOW;
    const bufLen = this.recvQueueBytes >>> 0;
    const delta = (max - bufLen) - this.recvWindow;
    const flags = this.sendFlags();
    if (delta < max / 2 && flags === 0) return;
    this.recvWindow += delta;
    const hdr = encodeHeader({
      type: TYPE_WINDOW_UPDATE,
      flags,
      streamId: this.id,
      length: delta >>> 0
    });
    await this.session.writeRaw(hdr);
  }

  // waitForSendWindow blocks until credits are available.
  private async waitForSendWindow(want: number): Promise<number> {
    if (want <= 0) return 0;
    while (this.sendWindow <= 0) {
      await this.session.waitForSendWindow(this.id);
    }
    return Math.min(want, this.sendWindow);
  }
}
