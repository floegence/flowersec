import { describe, expect, test } from "vitest";
import { startHTTPApplicationPeer } from "./httpApplicationPeer.js";
import { Reference } from "../v4/testSupport/cbor.js";
import { peerBytes, peerField } from "./currentPeer.js";
import { connectCurrentPeerWSS, createCurrentPeerClient, pingCurrentPeer, type CurrentPeerClient } from "./currentPeer.js";

describe("HTTP direct TypeScript-Go interoperability", () => {
  test("shares one application port and preserves two independent sessions", async () => {
    const peer = await startHTTPApplicationPeer("direct");
    const fixtures: CurrentPeerClient[] = [];
    let failure: unknown;
    try {
      const {origin, trust_pem: trustPEM, wire_revision: wireRevision} = peer.ready;
      expect(wireRevision).toBe(4);
      expect(await (await fetch(origin)).text()).toBe("application");
      // The normal application HTTP owner stays on its original port. The
      // trusted native Flowersec owner verifies the independent signed route;
      // an insecure page never manufactures a network TLS assurance.
      const prepare = async () => {
        const fixture = await createCurrentPeerClient(await (await fetch(origin + "/artifact")).text(), { trustPEM });
        fixtures.push(fixture);
        const route = new URL(fixture.endpoint), application = new URL(origin);
        expect(route.protocol).toBe("wss:"); expect(route.port).toBe(application.port);
        expect(route.pathname).toBe("/flowersec/v4/direct");
        return fixture;
      };
      // Both immutable leases share one durable admission work position. Each
      // admission completes before the next begins; both Sessions stay live.
      const firstFixture = await prepare();
      const first = { fixture: firstFixture, session: await connectCurrentPeerWSS(firstFixture, origin, trustPEM) };
      const secondFixture = await prepare();
      const second = { fixture: secondFixture, session: await connectCurrentPeerWSS(secondFixture, origin, trustPEM) };
      // Each generation belongs to its own original Environment/source/store.
      // Equal numeric generations never merge the separate signed pool leases.
      expect(first.fixture.environment).not.toBe(second.fixture.environment);
      expect(first.fixture.poolStore).not.toBe(second.fixture.poolStore);
      expect(first.fixture.material.generation.generation).toBe(1);
      expect(second.fixture.material.generation.generation).toBe(1);
      expect(first.fixture.material.activation).not.toBe(second.fixture.material.activation);
      const reference = new Reference();
      const lease = (fixture: CurrentPeerClient) => {
        const raw = peerBytes(fixture.material.artifact, 65536);
        try {
          const artifact = reference.decode(raw, "Artifact", {}, 65536n);
          if (!artifact.ok) throw new Error("invalid signed application lease");
          const id = peerField(artifact.value, "Artifact", "lease_id");
          if (id.kind !== "bytes") throw new Error("invalid signed lease ID");
          return Buffer.from(id.value).toString("hex");
        } finally { raw.fill(0); }
      };
      expect(lease(first.fixture)).not.toBe(lease(second.fixture));
      const response = {server: "http-direct"};
      expect(await pingCurrentPeer(first.fixture, first.session, "first")).toEqual(response);
      expect(await pingCurrentPeer(second.fixture, second.session, "second")).toEqual(response);
      expect((await first.session.close()).cleanup_status.status).toBe("complete");
      expect((await second.session.probeLiveness()).elapsedMS).toBeGreaterThanOrEqual(0n);
      expect(await pingCurrentPeer(second.fixture, second.session, "")).toEqual(response);
      expect(first.fixture.spentCount() + second.fixture.spentCount()).toBe(2);
      expect((await second.session.close()).cleanup_status.status).toBe("complete");
      expect(first.fixture.spentCount() + second.fixture.spentCount()).toBe(2);
      await peer.wait();
    } catch (error) { failure = error; throw error; }
    finally {
      const cleanup = await Promise.allSettled(fixtures.map(fixture => fixture.close()));
      try { await peer.stop(); } catch (error) { cleanup.push({ status: "rejected", reason: error }); }
      const errors = cleanup.flatMap(result => result.status === "rejected" ? [result.reason] : []);
      if (errors.length > 0) {
        if (failure !== undefined) errors.unshift(failure);
        throw new AggregateError(errors, errors.map(String).join("\n"));
      }
    }
  }, 90_000);
});
