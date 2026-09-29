import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { NoiseHandshake } from "./runtime/noiseHandshake.js";
import { profileDHPublicReference } from "./profileDHReference.js";
import { TrustedClock, trustedClockCharge } from "./runtime/clock.js";
import { ClockRate } from "./runtime/timeArithmetic.js";
import { TrustedDeadline } from "./runtime/deadline.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { CryptoUsageLedger, cryptoUsageCharge } from "./runtime/cryptoUsage.js";
import { recordEpochCharge } from "./runtime/recordCrypto.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { Domains } from "./testSupport/domains.js";
import { bytes, encode, map, text, u } from "./testSupport/credentials.js";
import { PrimitiveNoiseHandshake } from "./testSupport/noisePrimitive.js";

const corpus = JSON.parse(readFileSync(new URL("../../../testdata/transport_v4/noise.json", import.meta.url), "utf8")) as {
  inputs: Record<string, string>; transcripts: { profile: NoiseHandshake["profile"]; message1_hex: string; message2_hex: string; handshake_hash_hex: string; initial_root_hex: string }[];
};
const domainCorpus = JSON.parse(readFileSync(new URL("../../../testdata/transport_v4/domains.json", import.meta.url), "utf8")) as {
  vectors: { domain: string; inputs: { fsb: { $bytes: string }; fsa: { $bytes: string } } }[];
};
const prologueInputs = domainCorpus.vectors.find(value => value.domain === "noise_prologue")!.inputs;
const hex = (value: string | undefined) => {
  if (value === undefined) throw new Error("missing Noise fixture input");
  return Uint8Array.from(Buffer.from(value, "hex"));
};
const publicKey = (profile: string, secret: Uint8Array) => profileDHPublicReference(profile, secret);

function timingFixture(profile: string) {
  let tick = 0n, nextOwner = 1n;
  const limit = new ResourceVector([64n * 1024n * 1024n, 0n, 0n, 10000n, 100n, 100n, 100n, 100n, 100n, 100n, 100n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 8, reservations: 40, references: 80,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const tenant = "1".repeat(32), environment = "2".repeat(32);
  const accounts = [root.account("tenant", tenant, limit), root.account("environment", environment, limit)];
  const reserve = (kind: string, charge: ResourceVector) => root.reserve({ owner: {
    tenant, environment, kind, backing: (nextOwner++).toString(16).padStart(32, "0") }, charge, accounts });
  const clock = new TrustedClock({ rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1_000_000_000n, maxRoundTripMS: 100n },
    () => ({ milliseconds: tick, incarnation: "3".repeat(32) }), 128n, reserve("clock", trustedClockCharge(128n)));
  clock.installTrusted(clock.monotonic(), { lowerMS: 1000n, upperMS: 1000n });
  const config = { clock, authorizationDeadline: new TrustedDeadline(clock, 1_000_000_000n), preparationDeadline: new TrustedDeadline(clock, 1_000_000_000n) };
  const usageConfig = { clock, profile, sendDirection: 0 as const, keys: 8, maintenance: { calls: 1n, blocks: 1n, bytes: 1n }, runtimeBytes: 128n };
  const ledger = new CryptoUsageLedger(usageConfig, reserve("ledger", cryptoUsageCharge(usageConfig)));
  return { config, ledger, reserve, advance: (value: bigint) => { tick += value; }, close: () => {
    ledger.close(); clock.close(); expect(root.snapshot().reservations).toBe(0);
  } };
}

describe("v4 Noise KKpsk0 owner", () => {
  it.each(corpus.transcripts)("matches the primitive messages, final hash and initial root for $profile", transcript => {
    const c = corpus.inputs;
    const clientStatic = hex(c.client_static_private_hex), serverStatic = hex(c.server_static_private_hex);
    const shared = { profile: transcript.profile, psk: hex(c.psk_hex), contextDigest: hex(c.context_digest_hex), prologue: hex(c.prologue_hex) };
    const client = new PrimitiveNoiseHandshake({ ...shared, role: "client", localStaticPrivate: clientStatic,
      localStaticPublic: publicKey(transcript.profile, clientStatic), peerStaticPublic: publicKey(transcript.profile, serverStatic), ephemeralPrivate: hex(c.client_ephemeral_private_hex) });
    const server = new PrimitiveNoiseHandshake({ ...shared, role: "server", localStaticPrivate: serverStatic,
      localStaticPublic: publicKey(transcript.profile, serverStatic), peerStaticPublic: publicKey(transcript.profile, clientStatic), ephemeralPrivate: hex(c.server_ephemeral_private_hex) });
    try {
      const first = client.writeMessage(); expect(first).toEqual(hex(transcript.message1_hex)); server.readMessage(first);
      const second = server.writeMessage(); expect(second).toEqual(hex(transcript.message2_hex)); client.readMessage(second);
      for (const peer of [client, server]) {
        const result = peer.finish();
        try {
          expect(result.handshakeHash).toEqual(hex(transcript.handshake_hash_hex));
          expect(result.initialRoot).toEqual(hex(transcript.initial_root_hex));
        } finally { result.initialRoot.fill(0); }
      }
    } finally { client.close(); server.close(); }
  });
  it("reuses internal key positions only after both epoch keys exit", () => {
    const fixture = timingFixture(corpus.transcripts[0]!.profile), ledger = fixture.ledger;
    const reference = fixture.reserve("key_positions", new ResourceVector([1024n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
    const pool = ledger.reserveReusableKeyPositions(0, reference), other = ledger.reserveReusableKeyPositions(1, reference);
    const first = ledger.newEpoch(0), second = ledger.newEpoch(1);
    try {
      expect(() => ledger.prepareKeyPositions(0, reference)).toThrow("crypto_busy");
      const lease = ledger.bindKeyPositions(pool.checkout(), 1n, 0, reference);
      const oldKey = ledger.derive(first, 1n, 0, lease), newKey = ledger.derive(second, 1n, 0, lease);
      lease.close(); expect(pool.available()).toBe(false);
      oldKey.close(); expect(pool.available()).toBe(false);
      newKey.close(); expect(pool.available()).toBe(true);
      const duplicate = ledger.bindKeyPositions(pool.checkout(), 1n, 0, reference);
      expect(() => ledger.derive(second, 1n, 0, duplicate)).toThrow("record_scope");
      duplicate.close();
      const renewed = ledger.bindKeyPositions(pool.checkout(), 3n, 0, reference);
      const key = ledger.derive(second, 3n, 0, renewed);
      lease.close(); expect(pool.available()).toBe(false);
      pool.close(); renewed.close();
      expect(() => ledger.prepareKeyPositions(0, reference)).toThrow("crypto_busy");
      key.close();
      const returned = ledger.prepareKeyPositions(0, reference); returned.close();
    } finally { pool.close(); other.close(); first.close(); second.close(); reference.release(); fixture.close(); }
  });
  it.each(["valid", "expired_root", "submission_rejected", "create_context_mismatch", "verify_context_mismatch"])("runs both profiles with %s READY binding", mode => {
    for (const transcript of corpus.transcripts) {
      const c = corpus.inputs;
      const timing = timingFixture(transcript.profile);
      const clientStatic = hex(c.client_static_private_hex), serverStatic = hex(c.server_static_private_hex);
      const client = new NoiseHandshake({ ...timing.config, profile: transcript.profile, role: "client", localStaticPrivate: clientStatic,
        localStaticPublic: publicKey(transcript.profile, clientStatic), peerStaticPublic: publicKey(transcript.profile, serverStatic),
        psk: hex(c.psk_hex), ephemeralPrivate: hex(c.client_ephemeral_private_hex), contextDigest: hex(c.context_digest_hex), fsb: hex(prologueInputs.fsb.$bytes), fsa: hex(prologueInputs.fsa.$bytes) });
      const server = new NoiseHandshake({ ...timing.config, profile: transcript.profile, role: "server", localStaticPrivate: serverStatic,
        localStaticPublic: publicKey(transcript.profile, serverStatic), peerStaticPublic: publicKey(transcript.profile, clientStatic),
        psk: hex(c.psk_hex), ephemeralPrivate: hex(c.server_ephemeral_private_hex), contextDigest: hex(c.context_digest_hex), fsb: hex(prologueInputs.fsb.$bytes), fsa: hex(prologueInputs.fsa.$bytes) });
      const message1 = client.writeMessage();
      expect(message1.byteLength).toBe(transcript.message1_hex.length / 2);
      server.readMessage(message1);
      const message2 = server.writeMessage();
      expect(message2.byteLength).toBe(transcript.message2_hex.length / 2);
      client.readMessage(message2);
      const ready = {
        localCertificateDigest: new Uint8Array(32).fill(0x11), peerCertificateDigest: new Uint8Array(32).fill(0x22),
        fsbDigest: hex("ab459494a2549f0337176450ca29c197e815de82716b792049e9a829d79ae123"),
        fsaDigest: hex("d8815eba80472a3636f69f18ae4d39680500386d61102bc86ba0e6d122dc0f64"),
        admissionBinding: new Uint8Array(32).fill(0x55), transportContextDigest: hex(c.context_digest_hex), selectedFeatures: 0n,
      } as const;
      const clientSeed = new Uint8Array(32).fill(0x61), serverSeed = new Uint8Array(32).fill(0x71);
      const clientSigner = { publicKey: ed25519.getPublicKey(clientSeed), sign: (message: Uint8Array) => ed25519.sign(message, clientSeed) };
      const serverSigner = { publicKey: ed25519.getPublicKey(serverSeed), sign: (message: Uint8Array) => ed25519.sign(message, serverSeed) };
      if (mode === "create_context_mismatch" || mode === "verify_context_mismatch") {
        const wrong = { ...ready, transportContextDigest: new Uint8Array(32).fill(0x99) };
        if (mode === "create_context_mismatch") {
          expect(() => client.createReady(clientSigner, wrong)).toThrow(/noise_authentication/u);
        } else {
          const serverReady = server.createReady(serverSigner, { ...ready, localCertificateDigest: ready.peerCertificateDigest, peerCertificateDigest: ready.localCertificateDigest });
          expect(() => client.verifyReady(serverReady, serverSigner.publicKey, wrong)).toThrow(/noise_authentication/u);
        }
        client.close(); server.close(); timing.close();
        continue;
      }
      const clientReady = client.createReady(clientSigner, ready);
      const serverReady = server.createReady(serverSigner, { ...ready, localCertificateDigest: ready.peerCertificateDigest, peerCertificateDigest: ready.localCertificateDigest });
      // Consume the primitive ABI's initial root through an independent
      // registry oracle. Two copies of the production wrapper could otherwise
      // agree on an extra KDF step and still accept each other's READY.
      const domains = new Domains();
      const lp = (value: Uint8Array): Uint8Array => { const length = Buffer.alloc(4); length.writeUInt32BE(value.length); return Buffer.concat([length, value]); };
      const prologue = Buffer.concat([Buffer.from("flowersec/v4/noise-prologue\0"), lp(Buffer.from("4")), lp(Buffer.from(transcript.profile)), Buffer.from([0, 1]),
        lp(ready.transportContextDigest), lp(hex(prologueInputs.fsb.$bytes)), lp(hex(prologueInputs.fsa.$bytes))]);
      const primitive = new PrimitiveNoiseHandshake({ profile: transcript.profile, role: "server", localStaticPrivate: serverStatic,
        localStaticPublic: publicKey(transcript.profile, serverStatic), peerStaticPublic: publicKey(transcript.profile, clientStatic),
        psk: hex(c.psk_hex), ephemeralPrivate: hex(c.server_ephemeral_private_hex), contextDigest: ready.transportContextDigest, prologue });
      primitive.readMessage(message1); expect(primitive.writeMessage()).toEqual(message2);
      const expectedRoot = primitive.finish();
      for (const [role, wire, certificate] of [[0, clientReady, ready.localCertificateDigest], [1, serverReady, ready.peerCertificateDigest]] as const) {
        const key = domains.evaluate("ready_key", { profile: transcript.profile, handshake_hash: expectedRoot.handshakeHash,
          context_digest: ready.transportContextDigest, role, epoch_root: expectedRoot.initialRoot }, undefined, 65536n).output!;
        const macInput = encode(map({ 0: u(role), 1: text(transcript.profile), 2: bytes(expectedRoot.handshakeHash),
          3: bytes(ready.fsbDigest), 4: bytes(ready.fsaDigest), 5: bytes(ready.transportContextDigest),
          6: bytes(ready.admissionBinding), 7: bytes(certificate), 8: u(ready.selectedFeatures), 9: bytes(wire.subarray(4, 68)) }));
        const expected = domains.evaluate("ready_mac", { mac_input: macInput, ready_key: key }, undefined, 65536n).output;
        expect(wire.subarray(71)).toEqual(expected);
        key.fill(0);
      }
      expectedRoot.initialRoot.fill(0);
      client.verifyReady(serverReady, serverSigner.publicKey, ready);
      server.verifyReady(clientReady, clientSigner.publicKey, { ...ready, localCertificateDigest: ready.peerCertificateDigest, peerCertificateDigest: ready.localCertificateDigest });
      expect(clientReady.byteLength).toBe(103); expect(serverReady.byteLength).toBe(103);
      const epochReference = timing.reserve("epoch", recordEpochCharge(128n));
      expect(() => client.finish({ runtimeBytes: 128n }, timing.ledger, epochReference)).toThrow(/noise_state/u);
      if (mode === "submission_rejected") {
        expect(() => client.submitReady({ submitReady: () => false })).toThrow(/noise_busy/u);
        epochReference.release();
      } else {
        clientReady.fill(0); // Public output mutation cannot alter the original publication.
        client.submitReady({ submitReady: (payload) => { expect(payload[0]).toBe(0xa2); return true; } });
        if (mode === "expired_root") {
          timing.advance(timing.ledger.rootMaxAgeMS);
          expect(() => client.finish({ runtimeBytes: 128n }, timing.ledger, epochReference)).toThrow(/time_expired/u);
        } else {
          const epoch = client.finish({ runtimeBytes: 128n }, timing.ledger, epochReference);
          epoch.close();
        }
      }
      client.close(); server.close(); timing.close();
    }
  });
});
