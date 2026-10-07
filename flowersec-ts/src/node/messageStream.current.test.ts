import { expect, it } from "vitest";
import {
  MessageStreamDefinition, applicationMessageCodec, bytesMessageCodec, createHandlerPlan,
  createStreamMetadataEnvelope, utf8MessageCodec,
  type TypedMessageStream,
} from "./index.js";
import { createCurrentNodeSession } from "../v4/testSupport/currentNodeSession.js";

const signal = () => AbortSignal.timeout(10000);
const direction = (seed: number) => ({ schemaDigest: new Uint8Array(32).fill(seed), revision: "one", maxMessageBytes: 8192 });

it("dispatches registered typed WSS messages with original authorization, metadata, byte ownership and bidirectional FIN", async () => {
  const owner = await createCurrentNodeSession(environment => createHandlerPlan(environment, { applicationBytes: 1024n }));
  const definition = new MessageStreamDefinition({ kind: "example.typed.messages", revision: "one",
    openerToAcceptor: bytesMessageCodec(direction(81)), acceptorToOpener: utf8MessageCodec(direction(82)) });
  const metadata = createStreamMetadataEnvelope("example/document", 7, { cursor: new Uint8Array([0, 255, 3]) });
  let resolveCompleted!: () => void, rejectCompleted!: (error: unknown) => void;
  const completion = new Promise<void>((resolve, reject) => { resolveCompleted = resolve; rejectCompleted = reject; });
  const completed = { promise: completion, resolve: resolveCompleted, reject: rejectCompleted };
  let allowed = false, authorizations = 0, calls = 0;
  let incoming: TypedMessageStream<Uint8Array, string> | undefined;
  const registration = owner.accepted.session.registerMessageStream(definition, (context, received) => {
    expect(context.authentication.peerSubject).toBe("client");
    expect(received.encoded()).toEqual(metadata.encoded());
    authorizations++;
    return allowed;
  }, async (stream, context, received) => {
    incoming = stream; calls++;
    try {
      expect(received.encoded()).toEqual(metadata.encoded());
      expect(stream.metadata.encoded()).toEqual(metadata.encoded());
      const first = await stream.receive({ context, signal: context.signal });
      expect(first).toMatchObject({ done: false, value: new Uint8Array(), application_input_delivered: false });
      const second = await stream.receive({ context, signal: context.signal });
      expect(second).toMatchObject({ done: false, value: new Uint8Array(6000).fill(255), application_input_delivered: false });
      expect(await stream.receive({ context, signal: context.signal })).toEqual({ done: true });
      expect(await stream.send("typed reply", { context, signal: context.signal })).toMatchObject({ submission: "submitted" });
      await stream.closeWrite({ signal: context.signal });
      completed.resolve();
    } catch (error) { completed.reject(error); throw error; }
  }, { applicationBytes: 16384n, applicationTimeoutMS: 10000n, metadataNamespaces: [{ namespace: metadata.namespace, version: metadata.version }] });
  void completed.promise.catch(() => undefined);
  let outgoing: TypedMessageStream<string, Uint8Array> | undefined;
  try {
    await expect(owner.session.openMessageStream(definition, { metadata, signal: signal() })).rejects.toThrow();
    expect(authorizations).toBe(1); expect(calls).toBe(0);
    allowed = true;
    outgoing = await owner.session.openMessageStream(definition, { metadata, signal: signal() });
    expect(outgoing.metadata.encoded()).toEqual(metadata.encoded());
    await outgoing.send(new Uint8Array(), { signal: signal() });
    const bytes = new Uint8Array(6000).fill(255);
    await outgoing.send(bytes, { signal: signal() });
    expect(bytes).toEqual(new Uint8Array(6000).fill(255));
    await outgoing.closeWrite({ signal: signal() });
    await outgoing.closeWrite({ signal: signal() });
    await expect(outgoing.send(new Uint8Array([1]))).rejects.toMatchObject({ code: "closed" });
    expect(await outgoing.receive({ signal: signal() })).toMatchObject({ done: false, value: "typed reply" });
    expect(await outgoing.receive({ signal: signal() })).toEqual({ done: true });
    await completed.promise;
    await outgoing.finish({ signal: signal() });
    registration.close();
    expect(await registration.waitCleanup({ signal: signal() })).toMatchObject({ status: "complete" });
    expect(authorizations).toBe(2); expect(calls).toBe(1);
    expect(await outgoing.waitCleanup({ signal: signal() })).toMatchObject({ status: "complete" });
  } finally {
    registration.close();
    await Promise.all([outgoing?.close(), incoming?.close()]);
    await owner.close();
  }
});

it.each(["sync", "async"] as const)("keeps %s codec failure local to a message and allows explicit encoded delivery without invoking its decoder", async execution => {
  const owner = await createCurrentNodeSession(environment => createHandlerPlan(environment, { applicationBytes: 1024n }));
  let encoded = 0, decoded = 0;
  const encode = (value: string) => { encoded++; if (value === "encode-failure") throw new Error("application encode failed"); return new TextEncoder().encode(value); };
  const decode = (value: Uint8Array) => { decoded++; const text = new TextDecoder().decode(value); if (text === "decode-failure") throw new Error("application decode failed"); return text; };
  const codec = applicationMessageCodec<string>(direction(83), execution === "sync"
    ? { execution, applicationBytes: 16384n, encode: (_context, value) => encode(value), decode: (_context, value) => decode(value) }
    : { execution, applicationBytes: 16384n, encode: async (_context, value) => encode(value), decode: async (_context, value) => decode(value) });
  const definition = new MessageStreamDefinition({ kind: "example.typed.codec", revision: "one", openerToAcceptor: codec, acceptorToOpener: codec });
  let sender: TypedMessageStream<string, string> | undefined, receiver: TypedMessageStream<string, string> | undefined;
  try {
    [sender, receiver] = await Promise.all([
      owner.session.openMessageStream(definition, { signal: signal() }),
      owner.accepted.session.acceptMessageStream(definition, { signal: signal() }),
    ]);
    await expect(sender.send("encode-failure", { signal: signal() })).rejects.toMatchObject({ code: "encode_failed", progress: { submission: "not_submitted" } });
    await sender.send("decode-failure", { signal: signal() });
    await expect(receiver.receive({ signal: signal() })).rejects.toMatchObject({ code: "decode_failed", application_input_delivered: true });
    expect(encoded).toBe(2); expect(decoded).toBe(1);
    await sender.send("encoded payload", { signal: signal() });
    expect(await receiver.receiveEncoded({ signal: signal() })).toMatchObject({ done: false,
      value: new TextEncoder().encode("encoded payload"), application_input_delivered: false, codec_revision: "one", codec_schema_digest: direction(83).schemaDigest });
    expect(decoded).toBe(1);
    await sender.send("next typed payload", { signal: signal() });
    expect(await receiver.receive({ signal: signal() })).toMatchObject({ done: false, value: "next typed payload", application_input_delivered: true });
    expect(decoded).toBe(2);
    await sender.closeWrite({ signal: signal() });
    expect(await receiver.receive({ signal: signal() })).toEqual({ done: true });
    await receiver.closeWrite({ signal: signal() });
    expect(await sender.receive({ signal: signal() })).toEqual({ done: true });
    await Promise.all([sender.finish({ signal: signal() }), receiver.finish({ signal: signal() })]);
    expect(await sender.waitCleanup({ signal: signal() })).toMatchObject({ status: "complete" });
    expect(await receiver.waitCleanup({ signal: signal() })).toMatchObject({ status: "complete" });
  } finally { await Promise.all([sender?.close(), receiver?.close()]); await owner.close(); }
});
