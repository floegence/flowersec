import { describe, expect, test, vi } from "vitest";

import {
  adaptWebTransportCarrierSessionV2,
  type WebTransportBidirectionalLikeV2,
  type WebTransportSessionLikeV2,
} from "./webTransportAdapter.js";

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);

describe("runtime-neutral WebTransport carrier adapter", () => {
  test("maps stream FIN, DATAGRAM, and close without runtime-specific session logic", async () => {
    const outgoing = streamFixture([bytes("reply")]);
    const incoming = streamFixture([bytes("request")]);
    const incomingStreams = readableOf<WebTransportBidirectionalLikeV2>(incoming.stream);
    const datagramWrites: Uint8Array[] = [];
    let closeTransport!: () => void;
    const closed = new Promise<void>((resolve) => { closeTransport = resolve; });
    const close = vi.fn(() => closeTransport());
    const native: WebTransportSessionLikeV2 = {
      closed,
      incomingBidirectionalStreams: incomingStreams,
      createBidirectionalStream: async () => outgoing.stream,
      datagrams: {
        maxDatagramSize: 1_200,
        readable: readableOf(bytes("datagram-in")),
        writable: new WritableStream<Uint8Array>({ write: (value) => { datagramWrites.push(value.slice()); } }),
      },
      close,
    };
    const carrier = adaptWebTransportCarrierSessionV2(native, {
      path: "direct",
      inboundBidirectionalStreamCapacity: 10,
    });

    const opened = await carrier.openStream();
    expect(await opened.write(bytes("request"))).toBe(7);
    await opened.closeWrite();
    expect(outgoing.writes.map((value) => new TextDecoder().decode(value))).toEqual(["request"]);
    expect(new TextDecoder().decode((await opened.read())!)).toBe("reply");

    const accepted = await carrier.acceptStream();
    expect(new TextDecoder().decode((await accepted.read())!)).toBe("request");
    expect(await carrier.unreliableDatagrams!.send(bytes("datagram-out"))).toBe("accepted");
    expect(new TextDecoder().decode((await carrier.unreliableDatagrams!.receive()))).toBe("datagram-in");
    expect(datagramWrites).toHaveLength(1);

    await carrier.close();
    expect(close).toHaveBeenCalledTimes(1);
    await carrier.close();
    expect(close).toHaveBeenCalledTimes(1);
  });

  test("maps reset and abort idempotently", async () => {
    const fixture = streamFixture([]);
    const native: WebTransportSessionLikeV2 = {
      closed: new Promise(() => undefined),
      incomingBidirectionalStreams: readablePending<WebTransportBidirectionalLikeV2>(),
      createBidirectionalStream: async () => fixture.stream,
      datagrams: {
        maxDatagramSize: 1_200,
        readable: readablePending<Uint8Array>(),
        writable: new WritableStream<Uint8Array>(),
      },
      close: vi.fn(),
    };
    const carrier = adaptWebTransportCarrierSessionV2(native, {
      path: "tunnel",
      inboundBidirectionalStreamCapacity: 3,
    });
    const stream = await carrier.openStream();
    await stream.reset();
    await stream.reset();
    carrier.abort({ code: 6, reason: "test abort" });
    carrier.abort({ code: 6, reason: "test abort" });
    await expect(carrier.openStream()).rejects.toMatchObject({ code: "aborted" });
  });
});

function streamFixture(reads: readonly Uint8Array[]): Readonly<{
  stream: WebTransportBidirectionalLikeV2;
  writes: Uint8Array[];
}> {
  const writes: Uint8Array[] = [];
  return {
    writes,
    stream: {
      readable: readableOf(...reads),
      writable: new WritableStream<Uint8Array>({ write: (value) => { writes.push(value.slice()); } }),
    },
  };
}

function readableOf<T>(...values: readonly T[]): ReadableStream<T> {
  return new ReadableStream<T>({
    start(controller) {
      for (const value of values) controller.enqueue(value);
    },
  });
}

function readablePending<T>(): ReadableStream<T> {
  return new ReadableStream<T>();
}
