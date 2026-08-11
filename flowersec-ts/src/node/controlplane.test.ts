import { describe, expect, test } from "vitest";
import {
  buildFSB2RequestV2,
  decodeArtifactV2JSON,
  encodeFSB2RequestV2,
} from "../v2/artifact.js";
import { base64urlEncode } from "../utils/base64url.js";

import {
  AuthorizationRecord,
  Issuer,
  RuntimeAuthorizationRequest,
  authorizeTunnelRuntime,
  authorizeRuntime,
  createEndpointSet,
  rejectRuntime,
} from "./controlplane.js";

describe("Node control-plane public contract", () => {
  test("issues, persists, parses, and authorizes a direct artifact", () => {
    const now = Math.floor(Date.now() / 1000);
    const issuer = new Issuer();
    const endpoints = createEndpointSet(
      "wss://edge.example/flowersec/v2/direct",
      "quic://edge.example",
      "https://edge.example/flowersec/webtransport/v2/direct",
    );
    const issued = issuer.issueDirect({
      session: { channelId: "direct", expiresAtUnixSeconds: now + 60 },
      endpoints,
      rendezvousGroupId: "group",
      listenerAudience: "audience",
      upstreamAddress: "127.0.0.1:9000",
    });
    const artifact = issued.artifactJSON();
    expect(artifact).toBeInstanceOf(Uint8Array);
    const record = AuthorizationRecord.parse(issued.authorizationRecord().encode());
    expect(record.lookupKey()).toBe(issued.lookupKey());

    const decodedArtifact = decodeArtifactV2JSON(artifact);
    const candidate = decodedArtifact.path.candidates[0]!;
    const request = RuntimeAuthorizationRequest.parse(JSON.stringify({
      fsb2_base64url: base64urlEncode(encodeFSB2RequestV2(buildFSB2RequestV2(decodedArtifact, candidate.id))),
      carrier: candidate.carrier,
      remote_address: "127.0.0.1:23998",
    }));
    const response = authorizeRuntime(request, record, "lease-direct", now);
    expect(JSON.parse(new TextDecoder().decode(response.json()))).toMatchObject({
      decision: "allow",
      credential_id: issued.lookupKey(),
      lease_id: "lease-direct",
      direct: { upstream: { network: "tcp", address: "127.0.0.1:9000" } },
    });
  });

  test("issues a tunnel pair and rejects a cross-record request", () => {
    const now = Math.floor(Date.now() / 1000);
    const issuer = new Issuer();
    const pair = issuer.issueTunnelPair({
      session: { channelId: "tunnel", expiresAtUnixSeconds: now + 60 },
      endpoints: createEndpointSet("wss://edge.example/flowersec/v2/tunnel"),
      rendezvousGroupId: "group",
      listenerAudience: "audience",
      firstEndpointId: "endpoint-a",
      secondEndpointId: "endpoint-b",
      allowReplacement: true,
    });
    const firstRecord = pair.first.authorizationRecord();
    const secondRecord = pair.second.authorizationRecord();
    const artifact = decodeArtifactV2JSON(pair.first.artifactJSON());
    const candidate = artifact.path.candidates[0]!;
    const request = RuntimeAuthorizationRequest.parse(JSON.stringify({
      fsb2_base64url: base64urlEncode(encodeFSB2RequestV2(buildFSB2RequestV2(artifact, candidate.id))),
      carrier: candidate.carrier,
      remote_address: "127.0.0.1:23998",
    }));
    expect(() => authorizeRuntime(request, secondRecord, "lease-cross", now)).toThrow(/invalid/u);
    expect(() => authorizeRuntime(request, firstRecord, "lease-first", now)).toThrow(/invalid/u);
    const response = JSON.parse(new TextDecoder().decode(authorizeTunnelRuntime(request, firstRecord, "lease-first", now).json())) as Record<string, unknown>;
    expect(response).toMatchObject({
      decision: "allow",
      expected_peer_endpoint_instance_id: "endpoint-b",
      allow_replacement: true,
    });
    expect(JSON.stringify(response)).not.toMatch(/session|psk|suite|secret/iu);
  });

  test("strictly validates runtime requests and bounded reject/retry responses", () => {
    expect(() => RuntimeAuthorizationRequest.parse(JSON.stringify({ fsb2_base64url: "bad", carrier: "websocket", remote_address: "127.0.0.1" }))).toThrow();
    expect(JSON.parse(new TextDecoder().decode(rejectRuntime("permission_denied", false).json()))).toEqual({ decision: "reject", reason: "permission_denied" });
    expect(JSON.parse(new TextDecoder().decode(rejectRuntime("busy", true).json()))).toEqual({ decision: "retry", reason: "busy" });
    expect(() => rejectRuntime("Secret Detail", false)).toThrow();
  });
});
