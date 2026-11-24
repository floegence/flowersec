import { describe, expect, test, vi } from "vitest";
import { getCACertificates, rootCertificates, setDefaultCACertificates } from "node:tls";
import { X509Certificate } from "node:crypto";

import type { ArtifactV3, CanonicalArtifactCandidateV3 } from "../v3/artifact.js";
import type { NativeCarrierSessionV3 } from "../v3/carrier.js";
import type { NativeRawQuicConnectOptions, NativeRawQuicDriver } from "./nativeTransportAddon.js";
import { createNodeRawQuicClientV3 } from "./rawQuicAdapterV3.js";

const pin = new Uint8Array(32).fill(7);
const artifact = {
  path: { kind: "direct" },
  session: { max_inbound_streams: 8 },
} as ArtifactV3;

describe("Node raw QUIC v5 adapter", () => {
  test("uses the current process trust set for each CA attempt unless roots are explicit", async () => {
    const original = getCACertificates("default");
    const calls: NativeRawQuicConnectOptions[] = [];
    try {
      for (const cert of rootCertificates.slice(0, 2)) {
        setDefaultCACertificates([cert]);
        await createNodeRawQuicClientV3(driver(calls), candidate({ mode: "ca" }), artifact, now());
        expect(calls.at(-1)?.trustRootsDer).toEqual([new Uint8Array(new X509Certificate(cert).raw)]);
      }
      setDefaultCACertificates([]);
      const cert = rootCertificates[0]!;
      await createNodeRawQuicClientV3(driver(calls), candidate({ mode: "ca" }), artifact, now(), { roots: cert });
      expect(calls.at(-1)?.trustRootsDer).toEqual([new Uint8Array(new X509Certificate(cert).raw)]);
    } finally { setDefaultCACertificates(original); }
  });

  test("passes CA roots without any pin field", async () => {
    const calls: NativeRawQuicConnectOptions[] = [];
    const roots = rootCertificates[0]!;
    await createNodeRawQuicClientV3(driver(calls), candidate({ mode: "ca" }), artifact, now(), { roots });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ tlsMode: "ca", path: "direct" });
    expect(calls[0]).toHaveProperty("trustRootsDer");
    expect(calls[0]).not.toHaveProperty("activeLeafDerSha256");
  });

  test("snapshots active pins without passing trust roots", async () => {
    const calls: NativeRawQuicConnectOptions[] = [];
    await createNodeRawQuicClientV3(driver(calls), candidate({
      mode: "pin",
      pins: [{
        algorithm: "sha-256",
        not_after_unix_s: now() + 60,
        value_b64u: Buffer.from(pin).toString("base64url"),
      }],
    }), artifact, now(), { roots: "ignored in pin mode" });

    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ tlsMode: "pin", path: "direct" });
    expect(calls[0]).toHaveProperty("activeLeafDerSha256");
    expect(calls[0]).not.toHaveProperty("trustRootsDer");
  });

  test("maps native pin mismatch without attempting a CA fallback", async () => {
    const connectRawQuic = vi.fn(async (_options: NativeRawQuicConnectOptions) => { throw new Error("pin_mismatch"); });
    const nativeDriver = {
      connectRawQuic,
      bindRawQuic: async () => { throw new Error("unused"); },
    } as NativeRawQuicDriver;

    await expect(createNodeRawQuicClientV3(nativeDriver, candidate({
      mode: "pin",
      pins: [{
        algorithm: "sha-256",
        not_after_unix_s: now() + 60,
        value_b64u: Buffer.from(pin).toString("base64url"),
      }],
    }), artifact, now(), { roots: "must never be used" })).rejects.toMatchObject({
      code: "tls_failed",
      detail: "pin_mismatch",
    });
    expect(connectRawQuic).toHaveBeenCalledOnce();
    expect(connectRawQuic.mock.calls[0]![0]).not.toHaveProperty("trustRootsDer");
  });
});

function driver(calls: NativeRawQuicConnectOptions[]): NativeRawQuicDriver {
  return {
    connectRawQuic: async (options) => {
      calls.push(options);
      return {} as NativeCarrierSessionV3;
    },
    bindRawQuic: async () => { throw new Error("unused"); },
  };
}

function candidate(tls: CanonicalArtifactCandidateV3["tls"]): CanonicalArtifactCandidateV3 {
  return {
    carrier: "raw_quic",
    id: "raw-quic",
    normalized_url: "quic://localhost:443",
    tls,
    wire_profile: "flowersec-direct/5",
  };
}

function now(): number {
  return 1_900_000_000;
}
