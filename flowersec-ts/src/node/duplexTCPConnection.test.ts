import { createServer, Socket, type AddressInfo } from "node:net";
import { describe, expect, it, vi } from "vitest";
import { ClockRate, ResourceRoot, ResourceVector, createTransportEnvironment, connectDuplexTCP } from "./index.js";

function environment() {
  const limit = new ResourceVector([64n << 20n, 16n << 20n, 1n << 20n, 4096n, 4096n, 128n, 128n, 32n, 32n, 32n, 32n]);
  const root = new ResourceRoot({ profileRevision:"1".repeat(64),limit,accounts:16,reservations:128,references:256,
    rootRuntimeBytes:128n,accountRuntimeBytes:128n,reservationRuntimeBytes:128n,referenceRuntimeBytes:128n });
  const beginning = performance.now();
  const owner = createTransportEnvironment({ root,limit,tenantLimit:limit,tenantID:"1".repeat(32),environmentID:"2".repeat(32),
    runtimeBytes:1024n,namespaces:1,sources:1,acquisitions:1,materials:1,sessions:1,dependencies:4,acquireMS:1000n,cleanupMS:100,
    clock:{profile:{rate:new ClockRate(0n,1n,0n),maxWidthMS:100n,maxAgeMS:60000n,maxRoundTripMS:100n},
      tick:() => ({milliseconds:BigInt(Math.floor(performance.now()-beginning)),incarnation:"3".repeat(32)}),
      initial:() => ({lowerMS:1000n,upperMS:1000n})},random:bytes => { crypto.getRandomValues(bytes); } });
  return {root,owner,async close(){ await owner.close(); await owner.waitCleanup(); root.close(); }};
}

async function server() {
  const sockets = new Set<Socket>();
  const listener = createServer({allowHalfOpen:true},socket => { sockets.add(socket); socket.on("error",() => undefined); socket.once("close",() => sockets.delete(socket)); });
  await new Promise<void>((resolve,reject) => { listener.once("error",reject); listener.listen(0,"127.0.0.1",() => { listener.removeListener("error",reject); resolve(); }); });
  return { port:(listener.address() as AddressInfo).port,async close(){ for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => listener.close(() => resolve())); } };
}

describe("sealed native TCP factory ownership",() => {
  it.each([1,16,65536,undefined])("bounds both native buffers to the configured chunk %s",async readChunkBytes => {
    const env = environment(), peer = await server();
    const connect = vi.spyOn(Socket.prototype,"connect");
    try {
      const endpoint = await connectDuplexTCP(env.owner,{host:"127.0.0.1",port:peer.port,timeoutMS:1000,
        ...(readChunkBytes === undefined ? {} : {readChunkBytes})});
      const socket = connect.mock.contexts.at(-1) as Socket;
      expect(socket).toBeInstanceOf(Socket);
      expect(socket.readableHighWaterMark).toBe(readChunkBytes ?? 16384);
      expect(socket.writableHighWaterMark).toBe(readChunkBytes ?? 16384);
      expect(socket.allowHalfOpen).toBe(true);
      endpoint.close();
      await env.owner.close(); await env.owner.waitCleanup();
      expect(endpoint.cleanupStatus().status).toBe("complete");
    } finally { connect.mockRestore(); await peer.close(); await env.close(); }
    expect(env.root.snapshot().cleanupComplete).toBe(true);
  });

  it("creates one opaque endpoint and Environment close joins its real socket",async () => {
    const env = environment(), peer = await server();
    try {
      const endpoint = await connectDuplexTCP(env.owner,{host:"127.0.0.1",port:peer.port,readChunkBytes:16,timeoutMS:1000});
      expect(Object.keys(endpoint)).toEqual([]); expect(Object.isFrozen(endpoint)).toBe(true);
      expect(endpoint.cleanupStatus().status).toBe("pending");
      await env.owner.close(); await env.owner.waitCleanup();
      expect(endpoint.cleanupStatus().status).toBe("complete");
    } finally { await peer.close(); await env.close(); }
    expect(env.root.snapshot().cleanupComplete).toBe(true);
  });

  it("rejects DNS and canceled creation before consuming a dependency",async () => {
    const env = environment();
    const before = env.root.snapshot();
    try {
      await expect(connectDuplexTCP(env.owner,{host:"localhost",port:1234})).rejects.toThrow("configuration_capacity");
      const controller = new AbortController(); controller.abort();
      await expect(connectDuplexTCP(env.owner,{host:"127.0.0.1",port:1234,signal:controller.signal})).rejects.toThrow("owner_unavailable");
      expect(env.root.snapshot().charged.values()).toEqual(before.charged.values());
      expect(env.root.snapshot().reservations).toBe(before.reservations);
    } finally { await env.close(); }
  });
});
