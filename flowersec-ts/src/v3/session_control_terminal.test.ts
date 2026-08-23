import { describe, expect, test, vi } from "vitest";

import { createMemoryCarrierPairV3, type CarrierSessionV3, type CarrierStreamV3 } from "./carrier.js";
import type { OperationOptionsV3 } from "./contract.js";
import { CipherSuiteV3, InnerTypeV3 } from "./protocol.js";
import { projectSessionV3 } from "./publicSession.js";
import { establishSessionV3, SessionV3Error, type SessionConfigV3, type SessionV3 } from "./session.js";
import { nodeSessionRuntimeV3 } from "./nodeSessionRuntime.js";

function config(role: "client" | "server"): SessionConfigV3 {
  return {
    role,
    path: "direct",
    channelID: "session-v3-control-terminal",
    sessionContractHash: new Uint8Array(32).fill(0x41),
    suite: CipherSuiteV3.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(0x42),
    maxInboundStreams: 1,
    localAdmissionBinding: new Uint8Array(32).fill(0x43),
    peerAdmissionBinding: new Uint8Array(32).fill(0x43),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    runtime: nodeSessionRuntimeV3,
    idleTimeoutMs: 0,
    closeTimeoutMs: 500,
  };
}

describe("SessionV3 control terminal serialization", () => {
  test("requires native EOF after encrypted FIN before publishing EOF or releasing capacity", async () => {
    const fault = new ApplicationFINFault("block");
    const [rawClient, rawServer] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(new ApplicationFINFaultCarrier(rawClient, "client", fault), config("client")),
      establishSessionV3(new ApplicationFINFaultCarrier(rawServer, "server", fault), config("server")),
    ]);
    const opening = client.openStream("native-eof-gate");
    const incoming = await server.acceptStream();
    const outgoing = await opening;

    await incoming.stream.closeWrite();
    await expect(outgoing.read()).resolves.toBeNull();
    let readSettled = false;
    const reading = incoming.stream.read().finally(() => { readSettled = true; });
    const closing = outgoing.closeWrite();
    await testDeadline(fault.clientCloseEntered.promise, "client native FIN block");
    await testDeadline(fault.serverEOFReadEntered.promise, "server native EOF read");
    await Promise.resolve();
    expect(readSettled).toBe(false);
    let replacementSettled = false;
    const replacementOpening = client.openStream("after-native-eof").finally(() => {
      replacementSettled = true;
    });
    await Promise.resolve();
    expect(replacementSettled).toBe(false);

    fault.releaseNativeFIN.resolve();
    await expect(testDeadline(closing, "native FIN release")).resolves.toBeUndefined();
    await expect(testDeadline(reading, "clean application EOF")).resolves.toBeNull();
    const replacementIncoming = await testDeadline(server.acceptStream(), "replacement accept");
    const replacement = await testDeadline(replacementOpening, "replacement open");
    await Promise.all([
      replacement.reset().catch(() => undefined),
      replacementIncoming.stream.reset().catch(() => undefined),
    ]);
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("rejects a trailing carrier byte after encrypted FIN", async () => {
    const fault = new ApplicationFINFault("trailing");
    const [rawClient, rawServer] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(new ApplicationFINFaultCarrier(rawClient, "client", fault), config("client")),
      establishSessionV3(rawServer, config("server")),
    ]);
    const opening = client.openStream("trailing-fin");
    const incoming = await server.acceptStream();
    const outgoing = await opening;

    await outgoing.closeWrite();
    await expect(incoming.stream.read()).rejects.toMatchObject({ code: "protocol" });
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("seals queued responses and appends GOAWAY, SESSION_CLOSE, and FIN after owned cleanup", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new TerminalOrderingCarrier(rawClient);
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    await client.openStream("terminal-reset");
    await server.acceptStream();
    const internals = sessionInternals(client);

    clientCarrier.blockNextControlWrite();
    const active = internals.sendControl(InnerTypeV3.Ping, new Uint8Array(8));
    await clientCarrier.blockedWriteEntered.promise;
    const cleanup = internals.sendControlCleanup(InnerTypeV3.StreamReset, idReason(1n, 6));
    const pong = internals.sendControlResponse(InnerTypeV3.Pong, new Uint8Array(8));
    const rekeyACK = internals.sendControlResponse(InnerTypeV3.SessionKeyUpdateACK, new Uint8Array(20));
    const closing = client.close();

    await expect(internals.sendControl(InnerTypeV3.Ping, new Uint8Array(8))).rejects.toThrow(/sealed|closed/);
    await expect(internals.sendControlCleanup(InnerTypeV3.StreamReset, idReason(3n, 6))).resolves.toBe(false);
    await expect(internals.sendControlResponse(InnerTypeV3.Pong, new Uint8Array(8))).resolves.toBe(false);
    clientCarrier.releaseBlockedWrite();

    await expect(active).resolves.toBeUndefined();
    await expect(cleanup).resolves.toBe(true);
    await expect(pong).resolves.toBe(false);
    await expect(rekeyACK).resolves.toBe(false);
    await expect(closing).resolves.toBeUndefined();
    expect(clientCarrier.controlEvents).toEqual(["write", "write", "write", "write", "fin"]);
    expect(clientCarrier.writesAfterFIN).toBe(0);
    expect(clientCarrier.aborts).toBe(0);
  });

  test("does not commit a receive rekey when its ACK is suppressed", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const sendControlResponse = internals.sendControlResponse.bind(client);
    internals.sendControlResponse = async (type) => {
      expect(type).toBe(InnerTypeV3.SessionKeyUpdateACK);
      return false;
    };

    await internals.receiveSessionRekeyBeforeDeadline(sessionRekeyPayload(), new AbortController().signal);

    expect(internals.receiveEpoch).toBe(0);
    expect(internals.receiveTransition).toBe(0n);
    expect(internals.pendingReceiveEpoch).toBeUndefined();
    expect([...internals.receiveRoots.keys()]).toEqual([0]);
    internals.sendControlResponse = sendControlResponse;
    await client.close();
    await server.waitTermination();
  });

  test("publishes receive epoch before the rekey ACK can be exposed", async () => {
    const [clientCarrier, rawServerCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const serverCarrier = new TerminalOrderingCarrier(rawServerCarrier);
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(server);
    serverCarrier.blockNextControlWrite();
    const rekeying = client.rekey();
    await serverCarrier.blockedWriteEntered.promise;
    expect(internals.receiveEpoch).toBe(1);
    expect(internals.receiveTransition).toBe(1n);
    serverCarrier.releaseBlockedWrite();
    await expect(rekeying).resolves.toBeUndefined();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("ignores a duplicate session rekey ACK while a later rekey is pending", async () => {
    const [clientCarrier, rawServerCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const serverCarrier = new TerminalOrderingCarrier(rawServerCarrier);
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const serverInternals = sessionInternals(server);
    let ackCalls = 0;
    let duplicateObservedWithPending = false;
    const receiveACK = internals.receiveSessionRekeyACK;
    internals.receiveSessionRekeyACK = (payload) => {
      ackCalls++;
      if (ackCalls === 2) duplicateObservedWithPending = internals.pendingSessionRekey !== undefined;
      receiveACK.call(client, payload);
    };

    await client.rekey();
    const accepted = internals.lastSessionRekeyACK;
    expect(accepted).toBeDefined();

    serverCarrier.trackControlWrites();
    serverCarrier.blockNextControlWrite();
    const oldACK = serverInternals.sendControlResponse(InnerTypeV3.SessionKeyUpdateACK, accepted!);
    await serverCarrier.blockedWriteEntered.promise;
    const second = client.rekey();
    await waitFor(() => internals.pendingSessionRekey !== undefined);
    const before = {
      sendEpoch: internals.sendEpoch,
      controlSendEpoch: internals.controlSendEpoch,
      controlSendSequence: internals.controlSendSequence,
    };
    serverCarrier.releaseBlockedWrite();
    serverCarrier.blockNextControlWrite();
    await oldACK;
    await waitFor(() => ackCalls >= 2);
    await serverCarrier.secondBlockedWriteEntered.promise;

    expect(duplicateObservedWithPending).toBe(true);
    expect(internals.sendEpoch).toBe(before.sendEpoch);
    expect(internals.controlSendEpoch).toBe(before.controlSendEpoch);
    expect(internals.controlSendSequence).toBe(before.controlSendSequence);
    expect(internals.pendingSessionRekey).toBeDefined();

    serverCarrier.releaseBlockedWrite();
    await expect(second).resolves.toBeUndefined();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("fails closed for a mismatched session rekey ACK without a pending transition", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const serverInternals = sessionInternals(server);
    await expect(serverInternals.sendControlResponse(
      InnerTypeV3.SessionKeyUpdateACK,
      new Uint8Array(20),
    )).resolves.toBe(true);
    const termination = await testDeadline(client.termination, "mismatched ACK termination");
    expect(termination.error).toMatchObject({ code: "protocol" });
    await server.close().catch(() => undefined);
  });

  test("does not consume a session rekey transition when prepare is cancelled", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const entered = deferred<void>();
    const release = deferred<void>();
    const controller = new AbortController();
    const originalWait = internals.waitOutboundFrontier;
    internals.waitOutboundFrontier = async (_watermark, signal) => {
      entered.resolve();
      await abortableWait(release.promise, signal);
    };
    try {
      const operation = client.rekey({ signal: controller.signal });
      await entered.promise;
      controller.abort(new Error("caller supplied cancellation reason"));
      await expect(operation).rejects.toMatchObject({ code: "aborted" });
      expect(internals.nextTransition).toBe(1n);
    } finally {
      release.resolve();
      internals.waitOutboundFrontier = originalWait;
      await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
    }
  });

  test("unfreezes inbound responders when rekey is cancelled during responder drain", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const controller = new AbortController();
    internals.activeInboundResponders = 1;

    const operation = client.rekey({ signal: controller.signal });
    await waitFor(() => internals.localResponderFrozen);
    controller.abort(new Error("caller supplied cancellation reason"));
    await expect(operation).rejects.toMatchObject({ code: "aborted" });
    expect(internals.localResponderFrozen).toBe(false);
    await expect(internals.enterInboundResponder()).resolves.toBeUndefined();
    internals.activeInboundResponders = 0;
    internals.notifyResponderChanged();

    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("uses the maximum session transition once and then fails before wire wrap", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const maximum = (1n << 64n) - 1n;
    const clientInternals = sessionInternals(client);
    const serverInternals = sessionInternals(server);
    clientInternals.nextTransition = maximum;
    serverInternals.receiveTransition = maximum - 1n;

    await expect(client.rekey()).resolves.toBeUndefined();
    expect(clientInternals.nextTransition).toBe(0n);
    await expect(client.rekey()).rejects.toMatchObject({ code: "resource_exhausted" });
    expect(clientInternals.nextTransition).toBe(0n);
    await waitFor(() => serverInternals.receivedGoAway);
    await expect(server.openStream("after-transition-exhaustion")).rejects.toMatchObject({ code: "going_away" });

    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("fails closed if an exhaustion GOAWAY cannot meet the preparation deadline", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new TerminalOrderingCarrier(rawClient);
    const clientConfig: SessionConfigV3 = {
      ...config("client"),
      deadlines: {
        establishTimeoutMs: 1_000,
        rekeyPrepareTimeoutMs: 25,
        rekeyCompletionTimeoutMs: 1_000,
      },
    };
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, clientConfig),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    sessionInternals(client).nextTransition = 0n;
    clientCarrier.blockNextControlWrite();
    const publicClient = projectSessionV3(client);

    const operation = publicClient.rekey();
    await clientCarrier.blockedWriteEntered.promise;
    await expect(testDeadline(operation, "exhaustion GOAWAY deadline")).rejects.toMatchObject({ code: "rekey_failed" });
    await expect(testDeadline(publicClient.waitTermination(), "exhaustion termination")).resolves.toMatchObject({
      error: { code: "timeout" },
    });
    expect(clientCarrier.aborts).toBe(1);

    clientCarrier.releaseBlockedWrite();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("fails closed on an exhaustion GOAWAY write error while preserving resource exhaustion", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new TerminalOrderingCarrier(rawClient);
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    internals.nextTransition = 0n;
    clientCarrier.failNextControlWrite();
    const publicClient = projectSessionV3(client);

    await expect(publicClient.rekey()).rejects.toMatchObject({ code: "resource_exhausted" });
    await expect(publicClient.waitTermination()).resolves.toMatchObject({
      error: { code: "operation_failed" },
    });
    expect(clientCarrier.controlEvents).toEqual(["write"]);
    expect(clientCarrier.aborts).toBe(1);

    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("projects epoch exhaustion through the production rekey lifecycle", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const clientInternals = sessionInternals(client);
    const serverInternals = sessionInternals(server);
    const maximum = 0xffffffff;
    clientInternals.sendRoots.set(maximum, clientInternals.sendRoots.get(0)!);
    serverInternals.receiveRoots.set(maximum, serverInternals.receiveRoots.get(0)!);
    clientInternals.sendEpoch = maximum;
    clientInternals.controlSendEpoch = maximum;
    serverInternals.receiveEpoch = maximum;
    serverInternals.controlReceiveEpoch = maximum;

    await expect(client.rekey()).rejects.toMatchObject({ code: "resource_exhausted" });
    await waitFor(() => serverInternals.receivedGoAway);
    await expect(server.openStream("after-epoch-exhaustion")).rejects.toMatchObject({ code: "going_away" });

    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("rejects post-maximum rekeys before waiting for inbound responders", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    internals.activeInboundResponders = 1;
    internals.receiveTransition = (1n << 64n) - 1n;
    await expect(testDeadline(
      internals.receiveSessionRekey(sessionRekeyPayload()),
      "post-maximum transition validation",
    )).rejects.toMatchObject({ code: "protocol" });
    expect(internals.peerResponderFrozen).toBe(false);

    internals.receiveTransition = 0n;
    internals.receiveEpoch = 0xffffffff;
    await expect(testDeadline(
      internals.receiveSessionRekey(sessionRekeyPayload()),
      "post-maximum epoch validation",
    )).rejects.toMatchObject({ code: "protocol" });
    expect(internals.peerResponderFrozen).toBe(false);
    internals.activeInboundResponders = 0;
    internals.notifyResponderChanged();

    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("caller cancellation after rekey commit does not terminate the session", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const serverInternals = sessionInternals(server);
    const entered = deferred<void>();
    const release = deferred<void>();
    const originalSendResponse = serverInternals.sendControlResponse.bind(server);
    serverInternals.sendControlResponse = async (type, payload) => {
      if (type === InnerTypeV3.SessionKeyUpdateACK) {
        entered.resolve();
        await release.promise;
      }
      return await originalSendResponse(type, payload);
    };
    const controller = new AbortController();
    const operation = client.rekey({ signal: controller.signal });
    await entered.promise;
    controller.abort(new Error("caller supplied cancellation reason"));
    await expect(operation).rejects.toMatchObject({ code: "aborted" });
    release.resolve();
    const internals = sessionInternals(client);
    await waitFor(() => internals.sendEpoch === 1 && internals.pendingSessionRekey === undefined);
    expect(client.terminalError).toBeUndefined();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("post-commit completion timeout projects rekey failure and terminal timeout", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new TerminalOrderingCarrier(rawClient);
    const clientConfig: SessionConfigV3 = {
      ...config("client"),
      deadlines: {
        establishTimeoutMs: 1_000,
        rekeyPrepareTimeoutMs: 1_000,
        rekeyCompletionTimeoutMs: 25,
      },
    };
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, clientConfig),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const publicClient = projectSessionV3(client);
    clientCarrier.blockNextControlWrite();

    const operation = publicClient.rekey();
    await clientCarrier.blockedWriteEntered.promise;
    await expect(testDeadline(operation, "post-commit completion timeout")).rejects.toMatchObject({
      code: "rekey_failed",
    });
    await expect(testDeadline(publicClient.waitTermination(), "post-commit timeout termination")).resolves.toMatchObject({
      error: { code: "timeout" },
    });
    expect(clientCarrier.aborts).toBe(1);

    clientCarrier.releaseBlockedWrite();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("ordinary preparation timeout projects rekey failure without closing the session", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientConfig: SessionConfigV3 = {
      ...config("client"),
      deadlines: {
        establishTimeoutMs: 1_000,
        rekeyPrepareTimeoutMs: 25,
        rekeyCompletionTimeoutMs: 1_000,
      },
    };
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, clientConfig),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const originalWait = internals.waitOutboundFrontier;
    internals.waitOutboundFrontier = async (_watermark, signal) => {
      await abortableWait(new Promise<void>(() => undefined), signal);
    };
    try {
      await expect(projectSessionV3(client).rekey()).rejects.toMatchObject({ code: "rekey_failed" });
      expect(client.terminalError).toBeUndefined();
      expect(internals.openFrozen).toBe(false);
    } finally {
      internals.waitOutboundFrontier = originalWait;
      await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
    }
  });

  test("post-commit writer failure returns rekey failure and terminates as operation failed", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new TerminalOrderingCarrier(rawClient);
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const publicClient = projectSessionV3(client);
    clientCarrier.failNextControlWrite();

    await expect(publicClient.rekey()).rejects.toMatchObject({ code: "rekey_failed" });
    await expect(publicClient.waitTermination()).resolves.toMatchObject({
      error: { code: "operation_failed" },
    });

    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("caller cancellation leaves a post-commit timeout owned by the session", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new TerminalOrderingCarrier(rawClient);
    const clientConfig: SessionConfigV3 = {
      ...config("client"),
      deadlines: {
        establishTimeoutMs: 1_000,
        rekeyPrepareTimeoutMs: 1_000,
        rekeyCompletionTimeoutMs: 100,
      },
    };
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, clientConfig),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const publicClient = projectSessionV3(client);
    const controller = new AbortController();
    clientCarrier.blockNextControlWrite();

    const operation = publicClient.rekey({ signal: controller.signal });
    await clientCarrier.blockedWriteEntered.promise;
    controller.abort(new Error("caller supplied cancellation reason"));
    await expect(testDeadline(operation, "post-commit caller cancellation")).rejects.toMatchObject({ code: "canceled" });
    await expect(testDeadline(publicClient.waitTermination(), "owned completion timeout")).resolves.toMatchObject({
      error: { code: "timeout" },
    });
    expect(clientCarrier.aborts).toBe(1);

    clientCarrier.releaseBlockedWrite();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("Close joins a committed rekey after its caller cancels", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new TerminalOrderingCarrier(rawClient);
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const publicClient = projectSessionV3(client);
    const controller = new AbortController();
    clientCarrier.blockNextControlWrite();

    const operation = publicClient.rekey({ signal: controller.signal });
    await clientCarrier.blockedWriteEntered.promise;
    controller.abort(new Error("caller supplied cancellation reason"));
    await expect(operation).rejects.toMatchObject({ code: "canceled" });
    await expect(testDeadline(publicClient.close(), "Close owned-rekey barrier")).resolves.toBeUndefined();

    const internals = sessionInternals(client);
    expect(internals.pendingSessionRekey).toBeUndefined();
    expect(internals.openFrozen).toBe(false);
    expect(internals.localResponderFrozen).toBe(false);
    clientCarrier.releaseBlockedWrite();
    await server.close().catch(() => undefined);
  });

  test("session failure rejects and clears a pending session rekey ACK immediately", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const serverInternals = sessionInternals(server);
    const entered = deferred<void>();
    const release = deferred<void>();
    const originalSendResponse = serverInternals.sendControlResponse.bind(server);
    serverInternals.sendControlResponse = async (type, payload) => {
      if (type === InnerTypeV3.SessionKeyUpdateACK) {
        entered.resolve();
        await release.promise;
      }
      return await originalSendResponse(type, payload);
    };
    const operation = client.rekey();
    await entered.promise;
    const clientInternals = sessionInternals(client);
    expect(clientInternals.pendingSessionRekey).toBeDefined();
    clientInternals.fail(new SessionV3Error("closed", "test failure"), false);
    await expect(operation).rejects.toMatchObject({ code: "closed" });
    expect(clientInternals.pendingSessionRekey).toBeUndefined();
    release.resolve();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("coalesces authenticated activity while preserving the signed idle deadline", async () => {
    const clock = { now: 0 };
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, {
        ...config("client"),
        runtime: { ...nodeSessionRuntimeV3, monotonicMilliseconds: () => clock.now },
      }),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    internals.config.idleTimeoutMs = 1_000;
    const callbacks: Array<() => void> = [];
    const schedule = ((callback: (...args: unknown[]) => void) => {
      callbacks.push(() => callback());
      return 1 as unknown as ReturnType<typeof setTimeout>;
    }) as typeof setTimeout;
    const performanceSpy = vi.spyOn(globalThis.performance, "now").mockImplementation(() => clock.now);
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout").mockImplementation(schedule);
    try {
      sessionInternals(server).markAuthenticatedActivity();
      expect(callbacks).toHaveLength(0);

      internals.markAuthenticatedActivity();
      expect(callbacks).toHaveLength(1);
      clock.now = 900;
      internals.markAuthenticatedActivity();
      expect(callbacks).toHaveLength(1);

      clock.now = 1_000;
      callbacks[0]!();
      expect(client.terminalError).toBeUndefined();
      expect(callbacks).toHaveLength(2);

      clock.now = 1_900;
      callbacks[1]!();
      expect(client.terminalError).toMatchObject({ code: "timeout" });
      await expect(client.waitTermination()).resolves.toMatchObject({ error: { code: "timeout" } });
    } finally {
      setTimeoutSpy.mockRestore();
      performanceSpy.mockRestore();
      await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
    }
  });

  test("transfers temporary inbound record material and wipes it at stream terminal", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const serverInternals = sessionInternals(server);
    const originalRead = serverInternals.readStreamRecord.bind(serverInternals);
    let temporary: StreamInternals | undefined;
    let transferred: RecordMaterialInternals | undefined;
    serverInternals.readStreamRecord = async (stream) => {
      const record = await originalRead(stream);
      if (!serverInternals.streams.has(stream.id) && stream.receiveMaterials.size !== 0) {
        temporary = stream;
        transferred = [...stream.receiveMaterials.values()][0];
      }
      return record;
    };

    const opening = client.openStream("record-material-transfer");
    const incoming = await server.acceptStream();
    const outgoing = await opening;
    const accepted = serverInternals.streams.get(incoming.id);
    expect(temporary).toBeDefined();
    expect(temporary!.receiveMaterials.size).toBe(0);
    expect(transferred).toBeDefined();
    expect(accepted?.receiveMaterials.get(0)).toBe(transferred);

    await outgoing.reset();
    await waitFor(() => materialIsZero(transferred!));
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("releases and wipes an OPEN_REJECT stream before hanging carrier cleanup", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new HangingApplicationCloseWriteCarrier(rawClient);
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const originalRelease = internals.releaseStream.bind(internals);
    let released: StreamInternals | undefined;
    let releasedMaterials: readonly RecordMaterialInternals[] = [];
    internals.releaseStream = (stream) => {
      released = stream;
      releasedMaterials = [...stream.sendMaterials.values(), ...stream.receiveMaterials.values()];
      originalRelease(stream);
    };

    const opening = internals.openLogicalStream("flowersec.rpc.v3", { metadata: { unexpected: true } }, true);
    await expect(opening).rejects.toMatchObject({ code: "open_rejected" });
    await clientCarrier.closeWriteEntered.promise;
    internals.fail(new SessionV3Error("closed", "test termination"), false);

    expect(released).toBeDefined();
    expect(internals.streams.size).toBe(0);
    expect(released!.sendMaterials.size).toBe(0);
    expect(released!.receiveMaterials.size).toBe(0);
    expect(releasedMaterials.length).toBeGreaterThan(0);
    expect(releasedMaterials.every(materialIsZero)).toBe(true);

    clientCarrier.releaseCloseWrite();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });
});

type RecordMaterialInternals = Readonly<{
  secret: Uint8Array;
  recordKey: Uint8Array;
  noncePrefix: Uint8Array;
}>;

type StreamInternals = {
  id: bigint;
  sendMaterials: Map<number, RecordMaterialInternals>;
  receiveMaterials: Map<number, RecordMaterialInternals>;
};

type SessionInternals = {
  config: { idleTimeoutMs?: number };
  markAuthenticatedActivity(): void;
  streams: Map<bigint, StreamInternals>;
  readStreamRecord(stream: StreamInternals): Promise<unknown>;
  openLogicalStream(kind: string, options: Readonly<{ metadata?: Readonly<Record<string, unknown>> }>, internal: boolean): Promise<unknown>;
  releaseStream(stream: StreamInternals): void;
  sendControl(type: InnerTypeV3, payload: Uint8Array): Promise<void>;
  sendControlResponse(type: InnerTypeV3, payload: Uint8Array, publish?: () => void): Promise<boolean>;
  sendControlCleanup(type: InnerTypeV3, payload: Uint8Array): Promise<boolean>;
  receiveSessionRekeyACK(payload: Uint8Array): void;
  receiveSessionRekey(payload: Uint8Array): Promise<void>;
  receiveSessionRekeyBeforeDeadline(payload: Uint8Array, signal: AbortSignal): Promise<void>;
  receiveEpoch: number;
  controlReceiveEpoch: number;
  receiveTransition: bigint;
  receivedGoAway: boolean;
  pendingReceiveEpoch: number | undefined;
  receiveRoots: Map<number, unknown>;
  nextTransition: bigint;
  sendEpoch: number;
  controlSendEpoch: number;
  controlSendSequence: bigint;
  sendRoots: Map<number, unknown>;
  pendingSessionRekey: {
    payload: Uint8Array;
    epoch: number;
    acknowledged: {
      promise: Promise<void>;
      resolve(value: void | PromiseLike<void>): void;
    };
    committed: { value: boolean };
  } | undefined;
  lastSessionRekeyACK: Uint8Array | undefined;
  waitOutboundFrontier(watermark: bigint, signal: AbortSignal): Promise<void>;
  activeInboundResponders: number;
  localResponderFrozen: boolean;
  peerResponderFrozen: boolean;
  enterInboundResponder(): Promise<void>;
  notifyResponderChanged(): void;
  fail(error: Error, abortCarrier?: boolean): void;
};

function sessionInternals(session: SessionV3): SessionInternals {
  return session as unknown as SessionInternals;
}

function materialIsZero(material: RecordMaterialInternals): boolean {
  return [material.secret, material.recordKey, material.noncePrefix]
    .every((value) => value.every((byte) => byte === 0));
}

async function abortableWait<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw signal.reason;
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      (value) => { signal.removeEventListener("abort", abort); resolve(value); },
      (error) => { signal.removeEventListener("abort", abort); reject(error); },
    );
  });
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for session rekey");
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
}

class TerminalOrderingCarrier implements CarrierSessionV3 {
  readonly kind: CarrierSessionV3["kind"];
  readonly path: CarrierSessionV3["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierSessionV3["unreliableDatagrams"];
  readonly blockedWriteEntered = deferred<void>();
  readonly secondBlockedWriteEntered = deferred<void>();
  readonly controlEvents: string[] = [];
  writesAfterFIN = 0;
  aborts = 0;
  private controlStreamBound = false;
  private tracking = false;
  private blockNext = false;
  private failNext = false;
  private fin = false;
  private blockedWriteRelease = deferred<void>();
  private blockedWriteCount = 0;

  constructor(private readonly inner: CarrierSessionV3) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
    this.unreliableDatagrams = inner.unreliableDatagrams;
  }

  blockNextControlWrite(): void {
    this.tracking = true;
    this.blockNext = true;
  }

  failNextControlWrite(): void {
    this.tracking = true;
    this.failNext = true;
  }

  trackControlWrites(): void { this.tracking = true; }

  releaseBlockedWrite(): void {
    this.blockedWriteRelease.resolve();
  }

  async openStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    const stream = await this.inner.openStream(options);
    const control = !this.controlStreamBound;
    this.controlStreamBound = true;
    return control ? this.wrapControl(stream) : stream;
  }

  async acceptStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    const stream = await this.inner.acceptStream(options);
    const control = !this.controlStreamBound;
    this.controlStreamBound = true;
    return control ? this.wrapControl(stream) : stream;
  }

  async waitTermination(): Promise<void> { await this.inner.waitTermination(); }
  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> { await this.inner.close(error); }
  abort(error?: Readonly<{ code: number; reason: string }>): void { this.aborts++; this.inner.abort(error); }

  private wrapControl(stream: CarrierStreamV3): CarrierStreamV3 {
    return {
      read: async (options) => await stream.read(options),
      write: async (data, options) => {
        if (this.tracking) {
          if (this.fin) this.writesAfterFIN++;
          this.controlEvents.push("write");
          if (this.failNext) {
            this.failNext = false;
            throw new Error("injected control writer failure");
          }
          if (this.blockNext) {
            this.blockNext = false;
            if (this.blockedWriteCount++ === 0) this.blockedWriteEntered.resolve();
            else this.secondBlockedWriteEntered.resolve();
            const release = this.blockedWriteRelease;
            await release.promise;
            this.blockedWriteRelease = deferred<void>();
          }
        }
        return await stream.write(data, options);
      },
      closeWrite: async () => {
        if (this.tracking) {
          this.fin = true;
          this.controlEvents.push("fin");
        }
        await stream.closeWrite();
      },
      stopSending: async () => await stream.stopSending(),
      reset: async () => await stream.reset(),
      abort: (error) => stream.abort(error),
    };
  }
}

class HangingApplicationCloseWriteCarrier implements CarrierSessionV3 {
  readonly kind: CarrierSessionV3["kind"];
  readonly path: CarrierSessionV3["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierSessionV3["unreliableDatagrams"];
  readonly closeWriteEntered = deferred<void>();
  private readonly closeWriteRelease = deferred<void>();
  private opens = 0;

  constructor(private readonly inner: CarrierSessionV3) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
    this.unreliableDatagrams = inner.unreliableDatagrams;
  }

  releaseCloseWrite(): void { this.closeWriteRelease.resolve(); }

  async openStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    const stream = await this.inner.openStream(options);
    return this.opens++ === 0 ? stream : this.wrap(stream);
  }

  async acceptStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    return await this.inner.acceptStream(options);
  }

  async waitTermination(): Promise<void> { await this.inner.waitTermination(); }
  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> { await this.inner.close(error); }
  abort(error?: Readonly<{ code: number; reason: string }>): void { this.closeWriteRelease.resolve(); this.inner.abort(error); }

  private wrap(stream: CarrierStreamV3): CarrierStreamV3 {
    return {
      read: async (options) => await stream.read(options),
      write: async (data, options) => await stream.write(data, options),
      closeWrite: async () => {
        this.closeWriteEntered.resolve();
        await this.closeWriteRelease.promise;
        await stream.closeWrite();
      },
      stopSending: async () => await stream.stopSending(),
      reset: async () => await stream.reset(),
      abort: (error) => stream.abort(error),
    };
  }
}

class ApplicationFINFault {
  readonly clientCloseEntered = deferred<void>();
  readonly serverEOFReadEntered = deferred<void>();
  readonly releaseNativeFIN = deferred<void>();
  blockingNativeFIN = false;

  constructor(readonly mode: "block" | "trailing") {}
}

class ApplicationFINFaultCarrier implements CarrierSessionV3 {
  readonly kind: CarrierSessionV3["kind"];
  readonly path: CarrierSessionV3["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierSessionV3["unreliableDatagrams"];
  private streams = 0;

  constructor(
    private readonly inner: CarrierSessionV3,
    private readonly side: "client" | "server",
    private readonly fault: ApplicationFINFault,
  ) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
    this.unreliableDatagrams = inner.unreliableDatagrams;
  }

  async openStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    return this.wrap(await this.inner.openStream(options));
  }

  async acceptStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    return this.wrap(await this.inner.acceptStream(options));
  }

  async waitTermination(): Promise<void> { await this.inner.waitTermination(); }
  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> { await this.inner.close(error); }
  abort(error?: Readonly<{ code: number; reason: string }>): void { this.inner.abort(error); }

  private wrap(stream: CarrierStreamV3): CarrierStreamV3 {
    const application = this.streams++ === 1;
    if (!application) return stream;
    return {
      read: async (options) => {
        if (this.side === "server" && this.fault.blockingNativeFIN) {
          this.fault.serverEOFReadEntered.resolve();
        }
        return await stream.read(options);
      },
      write: async (data, options) => await stream.write(data, options),
      closeWrite: async () => {
        if (this.side !== "client") {
          await stream.closeWrite();
          return;
        }
        if (this.fault.mode === "trailing") {
          await stream.write(new Uint8Array([0xa5]));
        } else {
          this.fault.blockingNativeFIN = true;
          this.fault.clientCloseEntered.resolve();
          await this.fault.releaseNativeFIN.promise;
        }
        await stream.closeWrite();
      },
      stopSending: async () => await stream.stopSending(),
      reset: async () => await stream.reset(),
      abort: (error) => stream.abort(error),
    };
  }
}

function idReason(id: bigint, reason: number): Uint8Array {
  const output = new Uint8Array(10);
  const view = new DataView(output.buffer);
  view.setBigUint64(0, id);
  view.setUint16(8, reason);
  return output;
}

function sessionRekeyPayload(transition = 1n, nextEpoch = 1): Uint8Array {
  const output = new Uint8Array(20);
  const view = new DataView(output.buffer);
  view.setBigUint64(0, transition);
  view.setUint32(8, nextEpoch);
  view.setBigUint64(12, 0n);
  return output;
}

function deferred<T = void>(): Readonly<{
  promise: Promise<T>;
  resolve(value: T | PromiseLike<T>): void;
}> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

async function testDeadline<T>(promise: Promise<T>, stage: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${stage} did not settle`)), 1_000);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
