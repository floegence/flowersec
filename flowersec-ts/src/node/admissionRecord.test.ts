import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { encodeParentWinner } from "./admissionRecord.js";

it("encodes the shared Go/TypeScript pool winner control vector", () => {
  const v = JSON.parse(readFileSync(new URL("../../../testdata/interop/pool_winner_projection.json", import.meta.url), "utf8")) as Record<string, string | number>;
  const text = (key: string): string => String(v[key]);
  const bytes = (key: string): Uint8Array => Buffer.from(text(key), "hex");
  const fields = {
    source: "preauthorized_pool" as const, tenant: text("tenant"), winnerAuthority: text("winner_authority"), audience: text("audience"),
    issuer: bytes("issuer"), lease: bytes("lease"), artifactDigest: bytes("artifact"), proofDigest: bytes("proof"),
    candidateSet: bytes("candidate_set"), candidateID: bytes("candidate"), routeDigest: bytes("route"), attempt: bytes("attempt"),
    identities: [bytes("client_identity"), bytes("server_identity")] as const,
    issuedAt: BigInt(v.issued_at!), activationEnd: BigInt(v.activation_end!), sessionEnd: BigInt(v.session_end!),
    profile: "", spendAuthority: "", signingKey: "", initiationEnd: 0n, sessionNonce: new Uint8Array(32),
  };
  const result = encodeParentWinner(new Uint8Array(8192), fields);
  expect(Buffer.from(result).toString("hex")).toBe(text("hex"));
});
