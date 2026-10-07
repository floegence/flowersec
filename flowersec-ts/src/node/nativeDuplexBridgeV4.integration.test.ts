import { createServer, type AddressInfo, type Socket } from "node:net";
import { expect, it } from "vitest";
import { DuplexBridge, connectDuplexTCP, createHandlerPlan } from "./index.js";
import type { DuplexBridgeResult } from "./index.js";
import { createCurrentNodeSession } from "../v4/testSupport/currentNodeSession.js";

it.each([16,undefined])("public TCP bridge half-closes the request and retains reverse authenticated drainage with chunk %s",async readChunkBytes => {
  let socket: Socket | undefined;
  let received = Buffer.alloc(0);
  const listener = createServer({allowHalfOpen:true},peer => {
    socket = peer; peer.on("error",() => undefined);
    peer.on("data",chunk => { received = Buffer.concat([received, typeof chunk === "string" ? Buffer.from(chunk) : chunk]); });
    peer.once("end",() => { peer.end(Buffer.from("response after TCP request EOF")); });
  });
  await new Promise<void>((resolve,reject) => { listener.once("error",reject); listener.listen(0,"127.0.0.1",() => { listener.removeListener("error",reject); resolve(); }); });
  const port = (listener.address() as AddressInfo).port;
  let originalResult: DuplexBridgeResult | undefined;
  let handlerResult: Promise<DuplexBridgeResult> | undefined;
  const fixture = await createCurrentNodeSession(environment => createHandlerPlan(environment,{applicationBytes:16384n,streams:[{
    kind:"bridge.native",authorize:() => true,
    options:{applicationBytes:16384n,maxConcurrentStreams:1,maxAuthorizing:1,applicationTimeoutMS:10000n},
    handler:async (stream,context) => {
      const chunk = readChunkBytes === undefined ? {} : {readChunkBytes};
      const native = await connectDuplexTCP(environment,{host:"127.0.0.1",port,...chunk,signal:context.signal,timeoutMS:5000});
      const bridge = new DuplexBridge(stream,native,{...chunk,timeoutMS:5000,cleanupTimeoutMS:1000,signal:context.signal});
      bridge.start(); bridge.start();
      const waitAbort = new AbortController(); waitAbort.abort();
      await expect(bridge.wait({signal:waitAbort.signal})).rejects.toThrow("wait_canceled");
      handlerResult = bridge.wait({signal:context.signal});
      const result = await handlerResult; originalResult = result;
      expect(result.outcome).toBe("normal");
      expect(result.a_to_b.send_result).toEqual({endpoint_kind:"native_duplex",native_send_finished:true});
      expect(result.b_to_a.send_result).toEqual({endpoint_kind:"flowersec_stream",send_drained:true});
      expect(await bridge.wait()).toBe(result); result.release();
    },
  }]}));
  try {
    const signal = AbortSignal.timeout(10000);
    const stream = await fixture.session.openStream("bridge.native",{signal});
    const request = Buffer.from("bounded multi-chunk request");
    let offset = 0;
    while (offset < request.byteLength) {
      const chunk = request.subarray(offset,Math.min(offset + 16,request.byteLength));
      const progress = await stream.write(chunk,{signal});
      expect(progress.accepted_bytes).toBeGreaterThan(0n);
      expect(progress.accepted_bytes).toBeLessThanOrEqual(BigInt(chunk.byteLength));
      expect(progress.terminal_reason).toBe("complete");
      offset += Number(progress.accepted_bytes);
    }
    await stream.closeWrite({signal});
    const reply: Uint8Array[] = [];
    while (true) { const read = await stream.read(16n,{signal}); reply.push(new Uint8Array(read.data)); if (read.stream_status === "eof") break; }
    expect(Buffer.concat(reply)).toEqual(Buffer.from("response after TCP request EOF"));
    await stream.finish({signal});
    expect(received).toEqual(request);
    expect(handlerResult).toBeDefined();
    const result = await handlerResult!;
    expect(result.outcome).toBe("normal");
    expect(result.a_to_b.send_result).toEqual({endpoint_kind:"native_duplex",native_send_finished:true});
    expect(result.b_to_a.send_result).toEqual({endpoint_kind:"flowersec_stream",send_drained:true});
    expect(result.a_to_b.progress.destination_accepted_bytes).toBe(BigInt(request.byteLength));
    expect(result.b_to_a.progress.destination_accepted_bytes).toBe(BigInt(Buffer.byteLength("response after TCP request EOF")));
    // Close resets the handle, so wait for both original finish owners first.
    await stream.close({signal});
  } finally {
    await fixture.close(); socket?.destroy(); await new Promise<void>(resolve => listener.close(() => resolve())); originalResult?.release();
  }
},15000);


it("forwards a short native prefix before TCP EOF or a full bridge chunk",async () => {
  let handlerResult: Promise<DuplexBridgeResult> | undefined;
  let socket: Socket | undefined;
  let received = Buffer.alloc(0);
  const listener = createServer({allowHalfOpen:true},peer => {
    socket = peer; peer.on("error",() => undefined);
    // The native peer waits for the caller's response before its FIN.
    peer.write(Buffer.from("ready"));
    peer.on("data",bytes => { received = Buffer.concat([received, typeof bytes === "string" ? Buffer.from(bytes) : bytes]); });
    peer.once("end",() => peer.end());
  });
  await new Promise<void>((resolve,reject) => { listener.once("error",reject); listener.listen(0,"127.0.0.1",() => { listener.removeListener("error",reject); resolve(); }); });
  const port = (listener.address() as AddressInfo).port;
  const fixture = await createCurrentNodeSession(environment => createHandlerPlan(environment,{applicationBytes:16384n,streams:[{
    kind:"bridge.short-prefix",authorize:() => true,
    options:{applicationBytes:16384n,maxConcurrentStreams:1,maxAuthorizing:1,applicationTimeoutMS:10000n},
    handler:async (stream,context) => {
      const native = await connectDuplexTCP(environment,{host:"127.0.0.1",port,readChunkBytes:16,signal:context.signal,timeoutMS:5000});
      const bridge = new DuplexBridge(stream,native,{readChunkBytes:16,timeoutMS:5000,cleanupTimeoutMS:1000,signal:context.signal});
      bridge.start(); handlerResult = bridge.wait({signal:context.signal});
      const result = await handlerResult;
      expect(result.outcome).toBe("normal"); result.release();
    },
  }]}));
  try {
    const signal = AbortSignal.timeout(10000);
    const stream = await fixture.session.openStream("bridge.short-prefix",{signal});
    const greeting: Uint8Array[] = []; let filled = 0;
    while (filled < 5) {
      const part = await stream.read(BigInt(5-filled),{signal});
      expect(part.data.byteLength).toBeGreaterThan(0); greeting.push(new Uint8Array(part.data)); filled += part.data.byteLength;
    }
    expect(Buffer.concat(greeting).toString()).toBe("ready");
    const progress = await stream.write(Buffer.from("go"),{signal});
    expect(progress.accepted_bytes).toBe(2n); await stream.closeWrite({signal});
    while (true) { const read = await stream.read(16n,{signal}); if (read.stream_status === "eof") break; }
    await stream.finish({signal});
    expect(received.toString()).toBe("go");
    expect(handlerResult).toBeDefined();
    const result = await handlerResult!;
    expect(result.outcome).toBe("normal");
    expect(result.b_to_a.progress.source_read_bytes).toBe(5n);
    expect(result.a_to_b.progress.destination_accepted_bytes).toBe(2n);
    await stream.close({signal});
  } finally { await fixture.close(); socket?.destroy(); await new Promise<void>(resolve => listener.close(() => resolve())); }
},15000);
