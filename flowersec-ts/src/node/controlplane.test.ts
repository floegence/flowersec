import { readFileSync } from "node:fs";

import { describe, expect, test } from "vitest";
import {
  buildFSB2RequestV2,
  decodeArtifactV2JSON,
  decodeFSB2RequestV2,
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
} from "./v2.js";
import type { AuthorizationDecision } from "./acceptor.js";

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
    const decision: AuthorizationDecision = response;
    expect(decision.decision).toBe("allow");
    expect(response.leaseId).toBe("lease-direct");
    expect(response.artifact).toBeDefined();
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
    expect(Object.keys(response).sort()).toEqual([
      "allow_replacement",
      "credential_id",
      "decision",
      "expected_peer_endpoint_instance_id",
      "expires_at",
      "lease_id",
    ]);
    expect(Object.keys(response)).not.toEqual(expect.arrayContaining([
      expect.stringMatching(/session|psk|suite|secret/iu),
    ]));
    const secretMarkers = [
      artifact.session.e2ee_psk_b64u,
      ...(artifact.path.kind === "tunnel" ? [artifact.path.token] : []),
    ];
    for (const marker of secretMarkers) {
      expect(Object.values(response)).not.toContain(marker);
    }
  });

  test("compares bound admission requests with the Node constant-time primitive", () => {
    const now = Math.floor(Date.now() / 1000);
    const issued = new Issuer().issueDirect({
      session: { channelId: "constant-time", expiresAtUnixSeconds: now + 60 },
      endpoints: createEndpointSet("wss://edge.example/flowersec/v2/direct"),
      rendezvousGroupId: "constant-time-group",
      listenerAudience: "constant-time-audience",
      upstreamAddress: "127.0.0.1:9000",
    });
    const artifact = decodeArtifactV2JSON(issued.artifactJSON());
    const candidate = artifact.path.candidates[0]!;
    const raw = encodeFSB2RequestV2(buildFSB2RequestV2(artifact, candidate.id));
    const decoded = decodeFSB2RequestV2(raw);
    const authorize = (candidateRaw: Uint8Array) => authorizeRuntime(
      RuntimeAuthorizationRequest.fromDecoded({ ...decoded, raw: candidateRaw }, candidate.carrier),
      issued.authorizationRecord(),
      "constant-time-lease",
      now,
    );

    expect(() => authorize(raw.slice())).not.toThrow();
    const first = raw.slice();
    first[0] = (first[0] ?? 0) ^ 1;
    expect(() => authorize(first)).toThrow();
    const last = raw.slice();
    last[last.length - 1] = (last[last.length - 1] ?? 0) ^ 1;
    expect(() => authorize(last)).toThrow();
    expect(() => authorize(raw.subarray(0, raw.length - 1))).toThrow();

    const source = readFileSync(new URL("./controlplane.ts", import.meta.url), "utf8");
    expect(source).toMatch(/import\s*\{[^}]*timingSafeEqual[^}]*\}\s*from\s*["']node:crypto["']/su);
    expect(source).toMatch(/return timingSafeEqual\(a, b\)/u);
  });

  test("strictly validates runtime requests and bounded reject/retry responses", () => {
    expect(() => RuntimeAuthorizationRequest.parse(JSON.stringify({ fsb2_base64url: "bad", carrier: "websocket", remote_address: "127.0.0.1" }))).toThrow();
    expect(JSON.parse(new TextDecoder().decode(rejectRuntime("permission_denied", false).json()))).toEqual({ decision: "reject", reason: "permission_denied" });
    expect(JSON.parse(new TextDecoder().decode(rejectRuntime("busy", true).json()))).toEqual({ decision: "retry", reason: "busy" });
    expect(() => rejectRuntime("Secret Detail", false)).toThrow();
  });

  test("returns typed tunnel decisions without requiring response JSON parsing", () => {
    const now = Math.floor(Date.now() / 1000);
    const issuer = new Issuer();
    const pair = issuer.issueTunnelPair({
      session: { channelId: "typed-tunnel", expiresAtUnixSeconds: now + 60 },
      endpoints: createEndpointSet("wss://edge.example/flowersec/v2/tunnel"),
      rendezvousGroupId: "group",
      listenerAudience: "audience",
      firstEndpointId: "endpoint-a",
      secondEndpointId: "endpoint-b",
    });
    const record = pair.first.authorizationRecord();
    const artifact = decodeArtifactV2JSON(pair.first.artifactJSON());
    const candidate = artifact.path.candidates[0]!;
    const request = RuntimeAuthorizationRequest.parse(JSON.stringify({
      fsb2_base64url: base64urlEncode(encodeFSB2RequestV2(buildFSB2RequestV2(artifact, candidate.id))),
      carrier: candidate.carrier,
      remote_address: "127.0.0.1:23998",
    }));
    const response = authorizeTunnelRuntime(request, record, "lease-tunnel", now);
    expect(response.decision).toBe("allow");
    expect(response.leaseId).toBe("lease-tunnel");
    expect(response.expectedPeerEndpointInstanceId).toBe("endpoint-b");
    expect(response.reason).toBeUndefined();
  });
});
