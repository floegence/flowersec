import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";

import { ChannelInitService } from "./channelInit.js";
import { bearerToken, decodeArtifactRequest, encodeControlplaneError } from "./http.js";
import { IssuerKeyset } from "./issuer.js";
import { signToken, verifyToken, type TokenPayload } from "./token.js";

describe("controlplane server capabilities", () => {
  test("matches the shared FST2 Ed25519 golden vector", async () => {
    const path = new URL("../../../idl/flowersec/testdata/v1/token_vectors.json", import.meta.url);
    const fixture = JSON.parse(await readFile(path, "utf8")) as {
      cases: Array<{ inputs: { ed25519_seed_hex: string; payload: TokenPayload }; expected: { token: string } }>;
    };
    const vector = fixture.cases[0]!;
    const seed = Uint8Array.from(vector.inputs.ed25519_seed_hex.match(/../g)!.map((byte) => Number.parseInt(byte, 16)));
    const token = signToken(seed, vector.inputs.payload);
    expect(token).toBe(vector.expected.token);
    const issuer = new IssuerKeyset(vector.inputs.payload.kid, seed);
    expect(verifyToken(token, issuer.publicKeys(), {
      nowUnixS: vector.inputs.payload.iat,
      audience: vector.inputs.payload.aud,
      issuer: vector.inputs.payload.iss,
    })).toEqual(vector.inputs.payload);
    issuer.dispose();
    seed.fill(0);
  });

  test("issues paired channel grants and reissues a tunnel token", () => {
    const issuer = new IssuerKeyset("kid-1", new Uint8Array(32).fill(7));
    let now = 1_700_000_000;
    const service = new ChannelInitService(
      issuer,
      {
        tunnelUrl: "wss://tunnel.example.test/v1/connect",
        tunnelAudience: "flowersec-tunnel:test",
        issuerId: "issuer-test",
        allowedSuites: [1, 2],
        defaultSuite: 2,
      },
      () => now,
    );
    const grants = service.issue("channel-1");
    expect(grants.client.role).toBe(1);
    expect(grants.server.role).toBe(2);
    expect(grants.client.e2ee_psk_b64u).toBe(grants.server.e2ee_psk_b64u);
    expect(verifyToken(grants.client.token, issuer.publicKeys(), {
      nowUnixS: now,
      audience: "flowersec-tunnel:test",
      issuer: "issuer-test",
    }).channel_id).toBe("channel-1");
    now += 10;
    const refreshed = service.reissue(grants.client);
    expect(refreshed.token).not.toBe(grants.client.token);
    expect(refreshed.e2ee_psk_b64u).toBe(grants.client.e2ee_psk_b64u);
    issuer.dispose();
  });

  test("decodes bounded HTTP envelopes and bearer credentials", () => {
    const request = decodeArtifactRequest(
      "application/json; charset=utf-8",
      new TextEncoder().encode(JSON.stringify({ endpoint_id: " endpoint-1 ", correlation: { trace_id: " trace-1 " } })),
    );
    expect(request).toEqual({ endpoint_id: "endpoint-1", correlation: { trace_id: "trace-1" } });
    expect(bearerToken("Bearer ticket-1")).toBe("ticket-1");
    expect(JSON.parse(new TextDecoder().decode(encodeControlplaneError("denied", "not allowed")))).toEqual({
      error: { code: "denied", message: "not allowed" },
    });
  });
});
