import { connect as connectTLS, type ConnectionOptions } from "node:tls";
import { createServer as createNetServer, type Socket } from "node:net";
import { WebSocket, type ClientOptions } from "ws";
import { describe, expect, test } from "vitest";
import { MethodDefinition, ServiceDefinition, bytesMessageCodec, connect, createConnectionController, createHandlerPlan,
  type HandlerPlan, type AuthorizeApplicationResult, type AcceptedSession, type Session, type Stream, type ConnectionController } from "./index.js";
import { createCurrentPeerServer, type CurrentPeerServerOptions } from "../interop/currentServer.js";
import { createCurrentP256TLSFixture, currentPinnedWSSLeg } from "../interop/currentTLSPin.js";
import { startInvalidProofPeer } from "../interop/invalidProofPeer.js";
import { captureHandlerPlan } from "../v4/handlerPlan.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { array, bytes, encode, fill, map, text, u } from "../v4/testSupport/credentials.js";
import { configureCurrentPeerWSS, createCurrentPeerClient, peerJSONBytes, peerJSONValue, peerRequirements, peerServices, registerCurrentPoolMaterialSequence, type CurrentPeerClient } from "../interop/currentPeer.js";

const complete = Object.freeze({ status: "complete" as const, core_cleanup: "complete" as const, pending_callbacks: 0n });
const ingress = { positions: 2, handshakeMS: 1000n, drainMS: 1000n, cleanupMS: 200n };
const plan = (environment: Parameters<typeof createHandlerPlan>[0]) => createHandlerPlan(environment, { applicationBytes: 16384n, services: { ...peerServices, profile: "services" }, streams: [] });
const server = (options: CurrentPeerServerOptions = {}) => createCurrentPeerServer(plan, "https://app.example", { applicationProfile: "services", ...options });
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(yes => { resolve = yes; });
  return { promise, resolve };
}
async function bounded<T>(promise: Promise<T>, milliseconds = 5000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([promise, new Promise<never>((_resolve,reject) => { timer = setTimeout(() => reject(new Error("current runtime observation timed out")),milliseconds); })]); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}
async function waitFor(check: () => boolean): Promise<void> {
  let observing = true;
  try { await bounded((async () => { while (observing && !check()) await new Promise<void>(resolve => setTimeout(resolve, 20)); })()); }
  finally { observing = false; }
}
function localApplication(namespace: string, unaryType: number, notificationType: number) {
  const codec = bytesMessageCodec({ schemaDigest: new Uint8Array(32), revision: "1", maxMessageBytes: 4096 });
  const unary = new MethodDefinition({ typeID: unaryType, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
    requestMaxBytes: 4096, minResponseLimitBytes: 0, maxResponseBytes: 4096, restartFlush: false });
  const notification = new MethodDefinition({ typeID: notificationType, shape: "notify", notifySemantics: "observation", request: codec,
    requestMaxBytes: 4096, responseRevision: "1", restartFlush: false });
  const definition = new ServiceDefinition({ namespace, methods: { unary, notification } });
  const contract = (typeID: number, notify: boolean) => encode(map({
    0: text(namespace), 1: u(typeID), 2: u(notify ? 2 : 0), [notify ? 5 : 3]: u(0), 6: text("1"), 7: text("1"), 8: u(notify ? 0 : 1),
    9: u(0), 10: u(notify ? 0 : 4096), 11: u(30000), ...(notify ? {} : { 12: u(30000) }),
    21: { kind: "bool", value: false }, 23: u(4096), 27: array(),
  }));
  return { unary, notification, definition, unaryContract: contract(unaryType, false), notificationContract: contract(notificationType, true),
    services: { ...peerServices, definitions: [definition], maxMethods: 2, notificationMethods: [],
      queryPermissions: [unary, notification].map(method => ({ namespace, method, permission: "allowed" as const })) } };
}
function silent(peer: Awaited<ReturnType<typeof server>>, path = "/flowersec/v4/direct", protocol = "flowersec.direct.v4", origin = peer.origin) {
  const port = peer.acceptor.addresses()[0]!.port;
  const options: ClientOptions & ConnectionOptions = { ca: peer.trustPEM, origin, perMessageDeflate: false, family: 4,
    minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"] };
  const socket = new WebSocket(`wss://localhost:${port}${path}`, [protocol], options);
  const opened = new Promise<void>((resolve,reject) => { socket.once("open",resolve); socket.once("error",reject); });
  const closed = new Promise<void>(resolve => { socket.once("close",resolve); });
  void opened.catch(() => undefined);
  socket.on("error",() => undefined);
  return { socket, opened, closed };
}

describe("current original WSS admission and shutdown", () => {
  test("accepts a current production WSS Session with reverse RPC, opaque invocation and original stream payload", async () => {
    const codec = bytesMessageCodec({ schemaDigest:new Uint8Array(32), revision:"1", maxMessageBytes:4096 });
    const method = new MethodDefinition({ typeID:9100, shape:"unary", unarySemantics:"transient", request:codec, response:codec,
      requestMaxBytes:4096, minResponseLimitBytes:0, maxResponseBytes:4096, restartFlush:false });
    const definition = new ServiceDefinition({ namespace:"flowersec.direct", methods:{ handled:method } });
    const contract = encode(map({ 0:text(definition.namespace),1:u(method.typeID),2:u(0),3:u(0),6:text("1"),7:text("1"),8:u(1),9:u(0),10:u(4096),11:u(30000),12:u(30000),21:{kind:"bool",value:false},23:u(4096),27:array() }));
    const services = { ...peerServices, definitions:[definition], maxMethods:1, notificationMethods:[],
      queryPermissions:[{ namespace:definition.namespace, method, permission:"allowed" as const }] };
    const payload = deferred<Uint8Array>();
    let expectedIdentity: string | undefined;
    const peer = await createCurrentPeerServer(environment=>createHandlerPlan(environment,{ applicationBytes:16384n,services:{...services,profile:"services"},
      streams:[{kind:"node-v4-direct",authorize:()=>true,options:{applicationBytes:16384n,maxConcurrentStreams:2,maxAuthorizing:2,applicationTimeoutMS:10000n},handler:async(stream,context)=>{
        const collected=new Uint8Array(16);let length=0;
        for(;;){const read=await stream.read(16n,{signal:context.signal});if(read.wait_status!=="ready" || read.stream_status==="error" || read.stream_status==="aborted" || read.data.length>collected.length-length)throw new Error("direct WSS input failed");collected.set(read.data,length);length+=read.data.length;if(read.stream_status==="eof")break;if(read.data.length===0)throw new Error("empty WSS input");}
        await stream.closeWrite({signal:context.signal});payload.resolve(collected.slice(0,length));
        const finished=await stream.finish({signal:context.signal});if(!finished.send_drained)throw new Error("direct WSS FIN did not drain");
      }}]}),"https://app.example",{applicationProfile:"services",onAuthenticated:context=>{
        expect(Object.keys(context.invocation)).toEqual([]);expect(JSON.stringify(context.invocation)).toBe("{}");expect(Object.isFrozen(context.invocation)).toBe(true);
        expect(context.authentication.peerIdentityDigest).toBe(expectedIdentity);
      }});
    expectedIdentity=peer.clientIdentity;
    const fixture=await createCurrentPeerClient(peer.artifactJSON,{trustPEM:peer.trustPEM});
    let clientPlan:HandlerPlan|undefined,client:Session|undefined,accepted:AcceptedSession|undefined;
    const signal=AbortSignal.timeout(10000);
    try{
      clientPlan=createHandlerPlan(fixture.environment,{applicationBytes:16384n,services:{...services,profile:"services",unaryHandlers:[{namespace:definition.namespace,method,contract,
        handler:async(_context,request:Uint8Array)=>peerJSONBytes({handled:peerJSONValue(request)}),options:{workClass:"short",maxConcurrentCalls:2,applicationBytes:16384n,authorization:"authenticated"}}]},streams:[]});
      const owner=configureCurrentPeerWSS(fixture,peer.origin,peer.trustPEM,clientPlan),accepting=peer.acceptor.accept({signal});void accepting.catch(()=>undefined);
      client=await connect(fixture.environment,fixture.registerSource(owner),peerRequirements,{signal});accepted=await accepting;
      const binding=await accepted.session.bindService(definition,{signal,target:{authority:fixture.policy.authorities[0]!,tenant:fixture.policy.tenant,audience:fixture.policy.audience,
        localSubject:fixture.policy.serverSubject,peers:[{subject:fixture.policy.clientSubject,identityDigest:peer.clientIdentity}]},maximumOfferWindowMS:10000n});
      try{const response=await binding.call(method,peerJSONBytes({mode:"one-shot"}),{signal,responseLimitBytes:4096,timeoutMS:10000n});if(response.kind!=="value" || response.encoding!=="typed"){const detail=response.kind==="application_error"?`application_error:${response.header.kind}:${String(response.header.uint(10))}`:response.kind==="sdk_error"?`sdk_error:${response.header.kind}:${response.code}`:response.kind==="metadata"?`metadata:${response.progress.state}:${response.progress.failure??"none"}`:`${response.kind}:${response.encoding}`;throw new Error(`reverse WSS RPC result missing (${detail})`);}try{expect(peerJSONValue(response.value)).toEqual({handled:{mode:"one-shot"}});}finally{response.release();}}finally{binding.close();}
      const stream=await client.openStream("node-v4-direct",{signal});
      try{const progress=await stream.write(new Uint8Array([3,0,0]),{signal});expect(progress.accepted_bytes).toBe(3n);expect(progress.terminal_reason).toBe("complete");await stream.closeWrite({signal});await expect(bounded(payload.promise)).resolves.toEqual(new Uint8Array([3,0,0]));expect((await stream.read(16n,{signal})).stream_status).toBe("eof");}finally{await stream.close({signal});}
      expect(fixture.spentCount()).toBe(1);await Promise.all([client.close(),accepted.close()]);expect((await client.waitCleanup()).status).toBe("complete");expect((await accepted.waitCleanup()).status).toBe("complete");
    }finally{await client?.close();await accepted?.close();clientPlan?.close();await fixture.close();await peer.close();contract.fill(0);}
  },15000);

  test("serves immutable accepted-server RPC, notification, and stream declarations after the original plan is sealed", async () => {
    const app = localApplication("flowersec.accepted", 9103, 9104), notification = deferred<void>(), payload = deferred<string>();
    let supplied: HandlerPlan | undefined, notifications = 0;
    const peer = await createCurrentPeerServer(environment => {
      supplied = createHandlerPlan(environment, { applicationBytes: 16384n, services: { ...app.services, profile: "services",
        unaryHandlers: [{ namespace: app.definition.namespace, method: app.unary, contract: app.unaryContract,
          handler: async (_context, request: Uint8Array) => peerJSONBytes({ server: peerJSONValue(request) }),
          options: { workClass: "short", maxConcurrentCalls: 2, applicationBytes: 16384n, authorization: "authenticated" } }],
        notificationHandlers: [{ namespace: app.definition.namespace, method: app.notification, contract: app.notificationContract,
          handler: (_context, request: Uint8Array) => { expect(peerJSONValue(request)).toEqual({ event: "accepted" }); notifications++; notification.resolve(); },
          options: { workClass: "short", applicationBytes: 16384n, authorization: "authenticated", applicationTimeoutMS: 10000n } }],
      }, streams: [{ kind: "accepted-current-handler", authorize: () => true,
        options: { applicationBytes: 16384n, maxConcurrentStreams: 2, maxAuthorizing: 2, applicationTimeoutMS: 10000n },
        handler: async (stream, context) => {
          const output = new Uint8Array(64); let length = 0;
          for (;;) {
            const result = await stream.read(64n, { signal: context.signal });
            if (result.wait_status !== "ready" || result.stream_status === "error" || result.stream_status === "aborted" || result.data.length > output.length - length) throw new Error("accepted handler input failed");
            output.set(result.data, length); length += result.data.length;
            if (result.stream_status === "eof") break;
            if (result.data.length === 0) throw new Error("accepted handler input made no progress");
          }
          await stream.closeWrite({ signal: context.signal }); payload.resolve(new TextDecoder("utf-8", { fatal: true }).decode(output.subarray(0, length)));
          if (!(await stream.finish({ signal: context.signal })).send_drained) throw new Error("accepted handler FIN did not drain");
        } }], });
      return supplied;
    }, "https://app.example", { applicationProfile: "services" });
    let fixture: CurrentPeerClient | undefined, clientPlan: HandlerPlan | undefined, client: Session | undefined, accepted: AcceptedSession | undefined, outgoing: Stream | undefined;
    const cancellation = new AbortController(), signal = AbortSignal.any([cancellation.signal, AbortSignal.timeout(10000)]);
    let accepting: Promise<AcceptedSession> | undefined;
    try {
      fixture = await createCurrentPeerClient(peer.artifactJSON, { trustPEM: peer.trustPEM });
      clientPlan = createHandlerPlan(fixture.environment, { applicationBytes: 16384n, services: { ...app.services, profile: "services" }, streams: [] });
      const owner = configureCurrentPeerWSS(fixture, peer.origin, peer.trustPEM, clientPlan);
      accepting = peer.acceptor.accept({ signal }); void accepting.catch(() => undefined);
      client = await connect(fixture.environment, fixture.registerSource(owner), peerRequirements, { signal }); accepted = await accepting;
      expect(Object.isFrozen(supplied)).toBe(true); supplied!.close();
      expect(() => captureHandlerPlan(supplied!, originalEnvironment(peer.environment))).toThrow("owner_unavailable");
      const serving = accepted.serve({ signal }); void serving.catch(() => undefined);
      const service = await client.bindService(app.definition, { target: { authority: fixture.policy.authorities[0]!, tenant: fixture.policy.tenant, audience: fixture.policy.audience,
        localSubject: fixture.policy.clientSubject, peers: [{ subject: fixture.policy.serverSubject, identityDigest: fixture.serverIdentity }] }, maximumOfferWindowMS: 10000n, timeoutMS: 5000n, signal });
      try {
        const response = await service.call(app.unary, peerJSONBytes({ mode: "server" }), { responseLimitBytes: 4096, signal });
        if (response.kind !== "value" || response.encoding !== "typed") throw new Error("accepted-server RPC returned no typed value");
        try { expect(peerJSONValue(response.value)).toEqual({ server: { mode: "server" } }); } finally { response.release(); }
        await service.notify(app.notification, peerJSONBytes({ event: "accepted" }), { signal });
        await bounded(notification.promise); expect(notifications).toBe(1);
      } finally { service.close(); }
      outgoing = await client.openStream("accepted-current-handler", { signal });
      const originalPayload = new TextEncoder().encode("handled-by-current-session");
      expect((await outgoing.write(originalPayload, { signal })).accepted_bytes).toBe(BigInt(originalPayload.length));
      await outgoing.closeWrite({ signal }); await expect(bounded(payload.promise)).resolves.toBe("handled-by-current-session");
      expect((await outgoing.read(64n, { signal })).stream_status).toBe("eof");
      await outgoing.close({ signal }); outgoing = undefined;
      expect(fixture.spentCount()).toBe(1); await client.close(); await bounded(serving);
      await accepted.close(); expect((await accepted.waitCleanup()).status).toBe("complete");
    } finally {
      cancellation.abort(); await outgoing?.close(); await client?.close(); const late = accepted ?? await accepting?.catch(() => undefined); await late?.close();
      clientPlan?.close(); await fixture?.close(); await peer.close(); app.unaryContract.fill(0); app.notificationContract.fill(0);
    }
  }, 20000);

  test("reuses one immutable client HandlerPlan with fresh routers and original pool issuance across controller generations", async () => {
    const app = localApplication("flowersec.controller", 9101, 9102), observed = [deferred<void>(), deferred<void>()];
    let acquisitions = 0, rpcCalls = 0, notifications = 0;
    const peer = await createCurrentPeerServer(environment => createHandlerPlan(environment, { applicationBytes: 16384n,
      services: { ...app.services, profile: "services" }, streams: [] }), "https://app.example", { applicationProfile: "services", materialCount: 2 });
    let fixture: CurrentPeerClient | undefined, clientPlan: HandlerPlan | undefined, controller: ConnectionController | undefined;
    const accepted: AcceptedSession[] = [], accepting: Promise<AcceptedSession>[] = [];
    const cancellation = new AbortController(), signal = AbortSignal.any([cancellation.signal, AbortSignal.timeout(15000)]);
    try {
      fixture = await createCurrentPeerClient(peer.artifactJSON, { trustPEM: peer.trustPEM });
      clientPlan = createHandlerPlan(fixture.environment, { applicationBytes: 16384n, services: { ...app.services, profile: "services",
        unaryHandlers: [{ namespace: app.definition.namespace, method: app.unary, contract: app.unaryContract,
          handler: async (_context, request: Uint8Array) => peerJSONBytes({ invocation: ++rpcCalls, request: peerJSONValue(request) }),
          options: { workClass: "short", maxConcurrentCalls: 2, applicationBytes: 16384n, authorization: "authenticated" } }],
        notificationHandlers: [{ namespace: app.definition.namespace, method: app.notification, contract: app.notificationContract,
          handler: (_context, request: Uint8Array) => {
            expect(peerJSONValue(request)).toEqual({ phase: notifications === 0 ? "first" : "second" });
            notifications++; observed[notifications - 1]?.resolve();
          }, options: { workClass: "short", applicationBytes: 16384n, authorization: "authenticated", applicationTimeoutMS: 10000n } }],
      }, streams: [] });
      const owner = configureCurrentPeerWSS(fixture, peer.origin, peer.trustPEM, clientPlan);
      const source = registerCurrentPoolMaterialSequence(fixture, owner, peer.artifactJSONs, () => { acquisitions++; });
      controller = createConnectionController(fixture.environment, { source, requirements: peerRequirements, attemptTimeoutMS: 5000n, drainTimeoutMS: 1000n });
      const firstAccept = peer.acceptor.accept({ signal }); accepting.push(firstAccept); void firstAccept.catch(() => undefined);
      controller.start(); const first = await controller.waitForSession({ signal }); accepted.push(await firstAccept);
      const firstGeneration = controller.status().generation;
      const clientFixture = fixture;
      const exchange = async (index: number, phase: "first" | "second") => {
        const service = await accepted[index]!.session.bindService(app.definition, { target: { authority: clientFixture.policy.authorities[0]!, tenant: clientFixture.policy.tenant, audience: clientFixture.policy.audience,
        localSubject: clientFixture.policy.serverSubject, peers: [{ subject: clientFixture.policy.clientSubject, identityDigest: clientFixture.clientIdentity }] }, maximumOfferWindowMS: 10000n, timeoutMS: 5000n, signal });
        try {
          const response = await service.call(app.unary, peerJSONBytes({ phase }), { responseLimitBytes: 4096, timeoutMS: 10000n, signal });
          if (response.kind !== "value" || response.encoding !== "typed") throw new Error("controller reverse RPC returned no typed value");
          try { expect(peerJSONValue(response.value)).toEqual({ invocation: index + 1, request: { phase } }); } finally { response.release(); }
          await service.notify(app.notification, peerJSONBytes({ phase }), { timeoutMS: 10000n, signal }); await bounded(observed[index]!.promise);
        } finally { service.close(); }
      };
      await exchange(0, "first");
      const secondAccept = peer.acceptor.accept({ signal }); accepting.push(secondAccept); void secondAccept.catch(() => undefined);
      await first.close(); await waitFor(() => controller!.status().generation > firstGeneration);
      const second = await controller.waitForSession({ signal }); expect(second).not.toBe(first); accepted.push(await secondAccept);
      await exchange(1, "second"); expect(Object.isFrozen(clientPlan)).toBe(true);
      expect({ acquisitions, spends: fixture.spentCount(), rpcCalls, notifications }).toEqual({ acquisitions: 2, spends: 2, rpcCalls: 2, notifications: 2 });
      await controller.close(); expect((await controller.waitCleanup()).status).toBe("complete");
      await Promise.all(accepted.map(session => session.close()));
    } finally {
      cancellation.abort(); await controller?.close();
      const actual = await Promise.all(accepting.map(operation => operation.catch(() => undefined)));
      await Promise.all(actual.map(session => session?.close())); clientPlan?.close(); await fixture?.close(); await peer.close();
      app.unaryContract.fill(0); app.notificationContract.fill(0);
    }
  }, 25000);

  test("reacquires original signed material after a real refused WSS endpoint and spends only the successful lease", async () => {
    const reservation = createNetServer(); let refusedPort = 0;
    try {
      await new Promise<void>((resolve, reject) => { reservation.once("error", reject); reservation.listen(0, "127.0.0.1", resolve); });
      const address = reservation.address(); if (address === null || typeof address === "string") throw new Error("refused endpoint fixture did not bind"); refusedPort = address.port;
    } finally { await new Promise<void>(resolve => reservation.close(() => resolve())); }
    const peer = await server({ materialCount: 2, routeLeg: (address, index) => map({
      0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(1), 6: text("localhost"), 7: u(index === 0 ? refusedPort : address.port),
      8: text("/flowersec/v4/direct"), 9: text("http/1.1"), 10: text("flowersec.direct.v4"), 11: map({ 0: u(0), 1: { kind: "bool", value: true } }),
      12: map({ 0: array(text("https://app.example")), 1: { kind: "bool", value: false } }),
    }) });
    let fixture: CurrentPeerClient | undefined, controller: ConnectionController | undefined, accepted: AcceptedSession | undefined;
    const cancellation = new AbortController(), signal = AbortSignal.any([cancellation.signal, AbortSignal.timeout(10000)]);
    let accepting: Promise<AcceptedSession> | undefined;
    try {
      expect(peer.acceptor.addresses()[0]!.port).not.toBe(refusedPort);
      fixture = await createCurrentPeerClient(peer.artifactJSON, { trustPEM: peer.trustPEM });
      const owner = configureCurrentPeerWSS(fixture, peer.origin, peer.trustPEM);
      const source = registerCurrentPoolMaterialSequence(fixture, owner, peer.artifactJSONs);
      controller = createConnectionController(fixture.environment, { source, requirements: peerRequirements, attemptTimeoutMS: 3000n, drainTimeoutMS: 1000n });
      accepting = peer.acceptor.accept({ signal }); void accepting.catch(() => undefined);
      controller.start(); await waitFor(() => controller!.status().current);
      const client = await controller.waitForSession({ signal }); accepted = await accepting;
      expect(controller.status().attempts).toBe(2n); expect(fixture.spentCount()).toBe(1);
      await client.probeLiveness({ signal }); await controller.close(); await accepted.close();
      expect((await controller.waitCleanup()).status).toBe("complete"); expect((await accepted.waitCleanup()).status).toBe("complete");
    } finally {
      cancellation.abort(); await controller?.close(); const actual = accepted ?? await accepting?.catch(() => undefined); await actual?.close();
      await fixture?.close(); await peer.close();
    }
  }, 20000);

  test("fails over within one original signed candidate set and spends once", async () => {
    const reservation = createNetServer(); let refusedPort = 0;
    try {
      await new Promise<void>((resolve, reject) => { reservation.once("error", reject); reservation.listen(0, "127.0.0.1", resolve); });
      const address = reservation.address(); if (address === null || typeof address === "string") throw new Error("refused endpoint fixture did not bind"); refusedPort = address.port;
    } finally { await new Promise<void>(resolve => reservation.close(() => resolve())); }
    const leg = (port: number, id: number) => map({ 0: u(0), 1: bytes(fill(21 + id, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(1), 6: text("localhost"), 7: u(port),
      8: text("/flowersec/v4/direct"), 9: text("http/1.1"), 10: text("flowersec.direct.v4"), 11: map({ 0: u(0), 1: { kind: "bool", value: true } }),
      12: map({ 0: array(text("https://app.example")), 1: { kind: "bool", value: false } }) });
    const peer = await server({ candidateLegs: address => [leg(refusedPort, 0), leg(address.port, 1)] });
    let fixture: CurrentPeerClient | undefined, controller: ConnectionController | undefined, accepted: AcceptedSession | undefined, accepting: Promise<AcceptedSession> | undefined;
    const cancellation = new AbortController(), signal = AbortSignal.any([cancellation.signal, AbortSignal.timeout(10000)]);
    try {
      fixture = await createCurrentPeerClient(peer.artifactJSON, { trustPEM: peer.trustPEM });
      const owner = configureCurrentPeerWSS(fixture, peer.origin, peer.trustPEM);
      const source = registerCurrentPoolMaterialSequence(fixture, owner, [peer.artifactJSON]);
      controller = createConnectionController(fixture.environment, { source, requirements: peerRequirements, attemptTimeoutMS: 3000n, drainTimeoutMS: 1000n });
      accepting = peer.acceptor.accept({ signal }); void accepting.catch(() => undefined);
      controller.start(); await waitFor(() => controller!.status().current);
      const client = await controller.waitForSession({ signal }); accepted = await accepting;
      expect(controller.status().attempts).toBe(1n); expect(fixture.spentCount()).toBe(1);
      await client.probeLiveness({ signal }); await controller.close(); await accepted.close();
      expect((await controller.waitCleanup()).status).toBe("complete"); expect((await accepted.waitCleanup()).status).toBe("complete");
    } finally {
      cancellation.abort(); await controller?.close(); const actual = accepted ?? await accepting?.catch(() => undefined); await actual?.close();
      await fixture?.close(); await peer.close();
    }
  }, 20000);

  test("keeps an established current WSS Session alive after its original signed pin window expires", async () => {
    const tls = await createCurrentP256TLSFixture(), payload = deferred<Uint8Array>();
    const cancellation = new AbortController(), signal = AbortSignal.any([cancellation.signal, AbortSignal.timeout(10000)]);
    let peer: Awaited<ReturnType<typeof createCurrentPeerServer>> | undefined, fixture: CurrentPeerClient | undefined;
    let client: Session | undefined, accepted: AcceptedSession | undefined, accepting: Promise<AcceptedSession> | undefined, outgoing: Stream | undefined;
    let pinExpiry = 0n;
    try {
      peer = await createCurrentPeerServer(environment => createHandlerPlan(environment, {
        applicationBytes: 16384n, services: { ...peerServices, profile: "services" },
        streams: [{ kind: "pin-expiry-does-not-close", authorize: () => true,
          options: { applicationBytes: 16384n, maxConcurrentStreams: 2, maxAuthorizing: 2, applicationTimeoutMS: 10000n },
          handler: async (stream, context) => {
            const output = new Uint8Array(4); let length = 0;
            for (;;) {
              const result = await stream.read(4n, { signal: context.signal });
              if (result.wait_status !== "ready" || result.stream_status === "error" || result.stream_status === "aborted" || result.data.length > output.length - length) throw new Error("pin-expiry stream input failed");
              output.set(result.data, length); length += result.data.length;
              if (result.stream_status === "eof") break;
              if (result.data.length === 0) throw new Error("pin-expiry stream input made no progress");
            }
            await stream.closeWrite({ signal: context.signal }); payload.resolve(output.slice(0, length));
            const finished = await stream.finish({ signal: context.signal });
            if (!finished.send_drained) throw new Error("pin-expiry stream FIN did not drain");
          } }],
      }), "https://app.example", { applicationProfile: "services", listenerTLS: tls,
        routeLeg: address => {
          pinExpiry = BigInt(Date.now()) + 3000n;
          return currentPinnedWSSLeg("localhost", address.port, "https://app.example", tls.certificateDER, pinExpiry);
        } });
      fixture = await createCurrentPeerClient(peer.artifactJSON, { trustPEM: peer.trustPEM });
      const owner = configureCurrentPeerWSS(fixture, peer.origin);
      accepting = peer.acceptor.accept({ signal }); void accepting.catch(() => undefined);
      client = await connect(fixture.environment, fixture.registerSource(owner), peerRequirements, { signal });
      accepted = await accepting;
      await new Promise<void>(resolve => setTimeout(resolve, Math.max(1, Number(pinExpiry) - Date.now() + 50)));
      expect(BigInt(Date.now())).toBeGreaterThan(pinExpiry);
      outgoing = await client.openStream("pin-expiry-does-not-close", { signal });
      const progress = await outgoing.write(new Uint8Array([3, 3, 0, 0]), { signal });
      expect(progress.accepted_bytes).toBe(4n); expect(progress.terminal_reason).toBe("complete");
      await outgoing.closeWrite({ signal });
      await expect(bounded(payload.promise)).resolves.toEqual(new Uint8Array([3, 3, 0, 0]));
      expect((await outgoing.read(4n, { signal })).stream_status).toBe("eof");
      await outgoing.close({ signal }); outgoing = undefined;
      expect(fixture.spentCount()).toBe(1);
      await Promise.all([client.close(), accepted.close()]);
      expect((await client.waitCleanup()).status).toBe("complete");
      expect((await accepted.waitCleanup()).status).toBe("complete");
    } finally {
      cancellation.abort(); await outgoing?.close(); await client?.close();
      const actualAccepted = accepted ?? await accepting?.catch(() => undefined); await actualAccepted?.close();
      await fixture?.close(); await peer?.close(); tls.certificateDER.fill(0); tls.close();
    }
  }, 20000);

  test("keeps original pin-window checks active until READY publication despite earlier pool spend", async () => {
    const tls = await createCurrentP256TLSFixture(), entered = deferred<void>(), pending = deferred<HandlerPlan>();
    let supplied: HandlerPlan | undefined, pinExpiry = 0n, fixture: CurrentPeerClient | undefined;
    let callbackSignal: AbortSignal | undefined;
    const cancellation = new AbortController(), signal = AbortSignal.any([cancellation.signal, AbortSignal.timeout(10000)]);
    let peer: Awaited<ReturnType<typeof createCurrentPeerServer>> | undefined, connecting: Promise<Session> | undefined;
    try {
      peer = await createCurrentPeerServer(environment => { supplied = plan(environment); return supplied; }, "https://app.example", {
        applicationProfile: "services", listenerTLS: tls,
        routeLeg: address => { pinExpiry = BigInt(Date.now()) + 3000n; return currentPinnedWSSLeg("localhost", address.port, "https://app.example", tls.certificateDER, pinExpiry); },
        resolveHandlers: async context => { callbackSignal = context.signal; entered.resolve(); return pending.promise; },
      });
      fixture = await createCurrentPeerClient(peer.artifactJSON, { trustPEM: peer.trustPEM });
      const owner = configureCurrentPeerWSS(fixture, peer.origin);
      connecting = connect(fixture.environment, fixture.registerSource(owner), peerRequirements, { signal }); void connecting.catch(() => undefined);
      await bounded(entered.promise); expect(fixture.spentCount()).toBe(1);
      await new Promise<void>(resolve => setTimeout(resolve, Math.max(1, Number(pinExpiry) - Date.now() + 250)));
      pending.resolve(supplied!); await expect(bounded(connecting)).rejects.toThrow();
      await bounded(peer.acceptor.close());
      expect(callbackSignal?.aborted).toBe(true); expect(fixture.spentCount()).toBe(1);
      expect((await peer.acceptor.waitCleanup()).status).toBe("complete");
    } finally {
      cancellation.abort(); if (supplied !== undefined) pending.resolve(supplied);
      const late = await connecting?.catch(() => undefined); await late?.close();
      await fixture?.close(); await peer?.close(); tls.certificateDER.fill(0); tls.close();
    }
  }, 20000);

  test("rejects a hash-matched WSS leaf with an invalid TLS proof before current admission or durable spend", async () => {
    const peer = await startInvalidProofPeer("websocket");
    let authority: Awaited<ReturnType<typeof createCurrentPeerServer>> | undefined, fixture: CurrentPeerClient | undefined;
    try {
      const endpoint = new URL(`wss://${peer.address}`);
      const leg = currentPinnedWSSLeg(endpoint.hostname, Number(endpoint.port), "https://app.example", peer.leafDER, BigInt(Date.now()) + 3600000n - 60000n);
      authority = await server({ routeLeg: leg });
      fixture = await createCurrentPeerClient(authority.artifactJSON, { trustPEM: authority.trustPEM });
      const owner = configureCurrentPeerWSS(fixture, authority.origin);
      await expect(connect(fixture.environment, fixture.registerSource(owner), peerRequirements, { signal: AbortSignal.timeout(3000) }))
        .rejects.toMatchObject({ code: "authentication_failed", connection: { spendState: "unspent", admissionState: "not_started", networkReady: "not_started" } });
      expect(fixture.spentCount()).toBe(0);
      await peer.wait();
    } finally {
      await fixture?.close(); await authority?.close(); await peer.stop(); peer.leafDER.fill(0);
    }
  }, 45000);

  test("refuses an absent Origin before dialing or spending a signed WSS installation", async () => {
    let authorizations = 0;
    const peer = await server({ authorizeRequest: () => { authorizations++; return { allowed: true }; } });
    let fixture: CurrentPeerClient | undefined;
    try {
      fixture = await createCurrentPeerClient(peer.artifactJSON, { trustPEM: peer.trustPEM });
      const owner = configureCurrentPeerWSS(fixture, "", peer.trustPEM);
      await expect(connect(fixture.environment, fixture.registerSource(owner), peerRequirements, { signal: AbortSignal.timeout(3000) })).rejects.toThrow();
      expect(authorizations).toBe(0); expect(fixture.spentCount()).toBe(0);
    } finally { await fixture?.close(); await peer.close(); }
  }, 10000);

  test.each([
    ["/flowersec/v2/direct", "flowersec.direct.v2"],
    ["/flowersec/v3/direct", "flowersec.direct.v3"],
    ["/flowersec/v4/direct", "flowersec.direct.v3"],
    ["/flowersec/v4/tunnel", "flowersec.tunnel.v4"],
  ])("rejects unsupported path %s and protocol %s before Session acceptance", async (path,protocol) => {
    const peer = await server();
    const connection = silent(peer,path,protocol);
    try {
      await expect(bounded(connection.opened)).rejects.toThrow();
      await bounded(connection.closed);
      expect(peer.acceptor.cleanupStatus().pending_callbacks).toBe(0n);
    } finally { connection.socket.terminate(); await peer.close(); }
  },10000);

  test("rejects a disallowed Origin before current admission", async () => {
    const peer = await server(); const connection = silent(peer,undefined,undefined,"https://other.example");
    try { await expect(bounded(connection.opened)).rejects.toThrow(); await bounded(connection.closed); }
    finally { connection.socket.terminate(); await peer.close(); }
  },10000);

  test("expires silent pre-admission WSS owners and releases their finite positions", async () => {
    const released = deferred<void>(); let releases = 0;
    const peer = await server({ ingress: { ...ingress, positions: 1 }, release: async () => {
      if (++releases === 1) await released.promise;
      return complete;
    } });
    const root = originalEnvironment(peer.environment).resources.root, baseline = root.snapshot();
    const first = silent(peer);
    let overflow: ReturnType<typeof silent> | undefined, replacement: ReturnType<typeof silent> | undefined;
    let phase = "first upgrade";
    try {
      await bounded(first.opened); await bounded(first.closed,3000);
      phase = "original release callback";
      await waitFor(() => releases === 1);
      expect(peer.acceptor.cleanupStatus().pending_callbacks).toBe(1n);
      // A remote socket close does not retire the server's original callback
      // and ingress owner. Its single position stays occupied until cleanup.
      overflow = silent(peer); await expect(bounded(overflow.opened)).rejects.toThrow(); await bounded(overflow.closed);
      released.resolve();
      phase = "original cleanup";
      await waitFor(() => peer.acceptor.cleanupStatus().pending_callbacks === 0n && root.snapshot().reservations === baseline.reservations &&
        root.snapshot().charged.values().every((value, index) => value === baseline.charged.values()[index]));
      phase = "replacement upgrade";
      replacement = silent(peer); await bounded(replacement.opened); await bounded(replacement.closed,3000);
      phase = "replacement cleanup";
      await waitFor(() => releases === 2 && peer.acceptor.cleanupStatus().pending_callbacks === 0n && root.snapshot().reservations === baseline.reservations &&
        root.snapshot().charged.values().every((value, index) => value === baseline.charged.values()[index]));
    } catch (error) { throw new Error(`silent WSS ${phase} failed: ${error instanceof Error ? error.message : String(error)}`, { cause: error }); }
    finally { released.resolve(); first.socket.terminate(); overflow?.socket.terminate(); replacement?.socket.terminate(); await peer.close(); }
  },10000);

  test("bounds authenticated handler resolution and cancels its original context", async () => {
    const entered = deferred<void>(), pending = deferred<HandlerPlan>();
    let callbackSignal: AbortSignal | undefined, supplied: HandlerPlan | undefined;
    const peer = await createCurrentPeerServer(environment => { supplied = plan(environment); return supplied; }, "https://app.example", {
      applicationProfile: "services", ingress,
      resolveHandlers: async context => { callbackSignal = context.signal; entered.resolve(); return pending.promise; },
    });
    const fixture = await createCurrentPeerClient(peer.artifactJSON,{ trustPEM: peer.trustPEM });
    const owner = configureCurrentPeerWSS(fixture,peer.origin,peer.trustPEM);
    const connecting = connect(fixture.environment,fixture.registerSource(owner),peerRequirements,{ signal: AbortSignal.timeout(5000) });
    void connecting.catch(() => undefined);
    try {
      await bounded(entered.promise);
      const canceled = new Promise<void>(resolve => { if (callbackSignal!.aborted) resolve(); else callbackSignal!.addEventListener("abort",() => resolve(),{ once:true }); });
      await bounded(canceled,3000); expect(callbackSignal?.aborted).toBe(true);
      expect(peer.acceptor.cleanupStatus().pending_callbacks).toBe(1n);
      pending.resolve(supplied!);
      await expect(bounded(connecting)).rejects.toThrow();
      const reusable = captureHandlerPlan(supplied!, originalEnvironment(peer.environment)); reusable.release();
    } finally { pending.resolve(supplied!); await connecting.catch(() => undefined); await fixture.close(); await peer.close(); }
  },10000);

  test("burns one real application lease returned after admission cancellation", async () => {
    const entered = deferred<void>(), pending = deferred<AuthorizeApplicationResult<HandlerPlan>>();
    let supplied: HandlerPlan | undefined, closed = 0, observed = 0;
    const peer = await createCurrentPeerServer(environment => { supplied = plan(environment); return supplied; }, "https://app.example", { applicationProfile:"services", ingress,
      authorizeApplication: async () => { entered.resolve(); return pending.promise; } });
    const fixture = await createCurrentPeerClient(peer.artifactJSON,{ trustPEM:peer.trustPEM });
    const owner = configureCurrentPeerWSS(fixture,peer.origin,peer.trustPEM), cancellation = new AbortController();
    const connecting = connect(fixture.environment,fixture.registerSource(owner),peerRequirements,{ signal:cancellation.signal });
    void connecting.catch(() => undefined);
    const result = () => ({ decision:"authorized" as const, handlers:supplied!, lease:{ close:()=>{closed++;}, waitCleanup:async()=>{observed++;return complete;} } });
    try {
      await bounded(entered.promise); cancellation.abort(); await expect(bounded(connecting)).rejects.toThrow();
      pending.resolve(result());
      await bounded(peer.acceptor.close());
      expect(closed).toBe(1); expect(observed).toBeGreaterThanOrEqual(1);
      expect((await peer.acceptor.waitCleanup()).status).toBe("complete");
    } finally { cancellation.abort(); pending.resolve(result()); await connecting.catch(() => undefined); await fixture.close(); await peer.close(); }
  },10000);

  test("force-closes a WSS peer that does not answer its close frame", async () => {
    const peer = await server({ ingress, acceptorCleanupMS:1000n }), connection = silent(peer);
    let transport: Socket | undefined;
    try {
      await bounded(connection.opened);
      transport = (connection.socket as WebSocket & { readonly _socket?: Socket })._socket;
      if (transport === undefined) throw new Error("actual WSS TCP owner is unavailable");
      transport.pause();
      await bounded(peer.acceptor.close(),2000);
      transport.resume();
      await bounded(connection.closed);
      expect((await peer.acceptor.waitCleanup()).status).toBe("complete");
    } finally { transport?.resume(); connection.socket.terminate(); await peer.close(); }
  },10000);

  test("force-closes an actual TLS owner before WebSocket upgrade during shutdown", async () => {
    const peer = await server({ ingress, acceptorCleanupMS:1000n });
    const socket = connectTLS({ host:"127.0.0.1", port:peer.acceptor.addresses()[0]!.port, servername:"localhost", ca:peer.trustPEM, minVersion:"TLSv1.3", maxVersion:"TLSv1.3", ALPNProtocols:["http/1.1"] });
    const established = new Promise<void>((resolve,reject)=>{socket.once("secureConnect",resolve);socket.once("error",reject);});
    const closed = new Promise<void>(resolve=>{socket.once("close",()=>resolve());});
    socket.on("error",()=>undefined);
    try { await bounded(established); await bounded(peer.acceptor.close(),2000); await bounded(closed); expect((await peer.acceptor.waitCleanup()).status).toBe("complete"); }
    finally {socket.destroy();await peer.close();}
  },10000);
});
