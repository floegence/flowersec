import { afterEach, describe, expect, test, vi } from "vitest";
import { WebSocket as NodeWebSocket } from "ws";

import { createCurrentPeerClient, peerLimits, peerRequirements, peerServices, pingCurrentPeer, type CurrentPeerClient } from "./currentPeer.js";
import { connect } from "../node/index.js";
import { startHTTPApplicationPeer } from "./httpApplicationPeer.js";

describe("private loopback current-wire TypeScript-Go interoperability", () => {
  afterEach(() => vi.unstubAllGlobals());

  test("establishes a real Session, performs RPC, spends once, and releases once", async () => {
    const peer = await startHTTPApplicationPeer("local");
    let fixture: CurrentPeerClient | undefined;
    let failure: unknown;
    try {
      const endpoint = peer.ready;
      if (endpoint.artifact_json === undefined || endpoint.bridge_token === undefined) throw new Error("local bridge installation is absent");
      const bridgeToken = endpoint.bridge_token;
      class PrivateWebSocket extends NodeWebSocket {
        constructor(url: string, protocols?: string | string[]) {
          super(url, protocols, {
            origin: endpoint.origin,
            perMessageDeflate: false,
            headers: { "X-Flowersec-Private-Bridge-Token": bridgeToken },
          });
        }
      }
      vi.stubGlobal("WebSocket", PrivateWebSocket);
      vi.stubGlobal("WebTransport", undefined);
      vi.stubGlobal("location", { origin: endpoint.origin });
      expect(endpoint.wire_revision).toBe(4);
      fixture = await createCurrentPeerClient(endpoint.artifact_json, endpoint.trust_pem === undefined ? {} : { trustPEM: endpoint.trust_pem });
      const { configureLocalBrowserBridge } = await import("../browser/index.js");
      const identityKey = await crypto.subtle.importKey("jwk", fixture.identityKey.export({ format: "jwk" }), { name: "Ed25519" }, true, ["sign"]);
      const noiseJWK = fixture.noiseKey.export({ format: "jwk" });
      const noiseKey = await crypto.subtle.importKey("jwk", noiseJWK,
        fixture.material.profile.includes("x25519") ? { name: "X25519" } : { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      noiseJWK.d = "";
      const bridge = await configureLocalBrowserBridge(fixture.environment, { identityKey, noiseKey, poolStore: fixture.poolStore, limits: peerLimits,
        ...(fixture.applicationProfile === "services" ? { services: peerServices } : {}), carrier: {
          deployment: { endpoint: fixture.endpoint, applicationOrigin: endpoint.origin, routeDigest: fixture.routeDigest,
            notBeforeMS: fixture.initiation.from, notAfterMS: fixture.initiation.until,
            applicationAuthAssurance: "application_origin", ambientCredentialScope: "trusted_local_services" },
          queueMessages: 8, sendBufferBytes: 65544, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n,
        } });

      const session = await connect(fixture.environment, fixture.registerSource(bridge), {
        ...peerRequirements, local_consumer_tls13_verification: false, application_profile: fixture.applicationProfile,
      });
      expect((await session.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
      expect(await pingCurrentPeer(fixture, session, "ping")).toEqual({ server: "private-loopback" });
      expect(fixture.spentCount()).toBe(1);
      expect((await session.close()).cleanup_status.status).toBe("complete");
      // Closing the Session never rolls back or deletes its consumed lease.
      expect(fixture.spentCount()).toBe(1);
      await peer.wait();
    } catch (error) { failure = error; throw error; }
    finally {
      const cleanup = await Promise.allSettled([fixture?.close()]);
      try { await peer.stop(); } catch (error) { cleanup.push({ status: "rejected", reason: error }); }
      const errors = cleanup.flatMap(result => result.status === "rejected" ? [result.reason] : []);
      if (errors.length > 0) {
        if (failure !== undefined) errors.unshift(failure);
        throw new AggregateError(errors, errors.map(String).join("\n"));
      }
    }
  }, 90_000);
});
