import { readFileSync } from "node:fs";

import { describe, expect, test } from "vitest";

import {
  buildFSB3RequestV3,
  computeSessionContractHashV3,
  decodeArtifactV3JSON,
  decodeFSB3RequestV3,
  encodeArtifactV3JSON,
  encodeFSB3RequestV3,
  type ArtifactV3,
} from "../v3/artifact.js";
import { parseArtifactV3 } from "../v3/publicApi.js";
import {
  inspectTunnelAuthorizationGrantV3,
  runtimeAuthorizationRequestV3FromDecoded,
  validateTunnelAuthorizationGrantV3,
  verifyTunnelAuthorizationGrantV3,
} from "./runtimeAuthorizationV3.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const tunnel = decodeArtifactV3JSON(fixture.positive.find(({ artifact_json }) =>
  JSON.parse(artifact_json).path.kind === "tunnel")!.artifact_json);

describe("Node v3 secret-free tunnel authorization grants", () => {
  test("mints an opaque request-bound grant without retaining artifact secrets", () => {
    const request = observed(tunnel);
    const grant = verifyTunnelAuthorizationGrantV3(
      request,
      handle(tunnel),
      { leaseId: "lease-secret-free", allowReplacement: true },
    );

    expect(Object.keys(grant)).toEqual([]);
    expect(JSON.stringify(grant)).toBe("{}");
    expect(JSON.stringify(inspectTunnelAuthorizationGrantV3(grant))).not.toContain("e2ee_psk");
    expect(validateTunnelAuthorizationGrantV3(grant, request)).toMatchObject({
      credentialId: request.lookupKey(),
      leaseId: "lease-secret-free",
      expiresAtUnixSeconds: tunnel.session.init_expire_at_unix_s,
      allowReplacement: true,
    });
  });

  test("rejects a same-credential artifact whose complete FSB3 projection differs", () => {
    const request = observed(tunnel);
    const session = {
      ...tunnel.session,
      max_inbound_streams: tunnel.session.max_inbound_streams + 1,
    };
    const modified: ArtifactV3 = {
      ...tunnel,
      session: {
        ...session,
        contract_hash_b64u: computeSessionContractHashV3(session).hashBase64URL,
      },
    };

    expect(() => verifyTunnelAuthorizationGrantV3(
      request,
      handle(modified),
      { leaseId: "lease-modified-fsb3" },
    )).toThrow("invalid Flowersec tunnel authorization");
  });

  test("rejects expired artifacts and invalid self-peer artifacts", () => {
    if (tunnel.path.kind !== "tunnel") throw new Error("expected tunnel fixture");
    const request = observed(tunnel);
    const expired: ArtifactV3 = {
      ...tunnel,
      session: { ...tunnel.session, init_expire_at_unix_s: Math.floor(Date.now() / 1_000) - 1 },
    };
    const peerMismatch: ArtifactV3 = {
      ...tunnel,
      path: {
        ...tunnel.path,
        expected_peer_endpoint_instance_id: tunnel.path.local_endpoint_instance_id,
      },
    };

    expect(() => verifyTunnelAuthorizationGrantV3(
      request,
      handle(expired),
      { leaseId: "lease-expired" },
    )).toThrow("invalid Flowersec tunnel authorization");
    expect(() => handle(peerMismatch)).toThrow("invalid Flowersec v3 artifact");
  });

  test("does not accept a structural grant forgery or a grant for another request", () => {
    if (tunnel.path.kind !== "tunnel") throw new Error("expected tunnel fixture");
    const request = observed(tunnel);
    const grant = verifyTunnelAuthorizationGrantV3(request, handle(tunnel), { leaseId: "lease-bound" });
    const otherArtifact: ArtifactV3 = {
      ...tunnel,
      path: {
        ...tunnel.path,
        listener_audience: `${tunnel.path.listener_audience}-other`,
      },
    };
    const otherRequest = observed(otherArtifact);

    expect(validateTunnelAuthorizationGrantV3({} as never, request)).toBeUndefined();
    expect(validateTunnelAuthorizationGrantV3(grant, otherRequest)).toBeUndefined();
  });
});

function observed(artifact: ArtifactV3) {
  const chosen = artifact.path.candidates[0];
  if (chosen === undefined) throw new Error("tunnel fixture has no candidate");
  return runtimeAuthorizationRequestV3FromDecoded(decodeFSB3RequestV3(
    encodeFSB3RequestV3(buildFSB3RequestV3(artifact, chosen.id)),
  ));
}

function handle(artifact: ArtifactV3) {
  return parseArtifactV3(encodeArtifactV3JSON(artifact));
}
