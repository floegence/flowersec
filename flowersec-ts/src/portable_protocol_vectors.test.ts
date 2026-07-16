import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { assertRpcEnvelope } from "./gen/flowersec/rpc/v1.gen.js";
import type { DiagnosticEvent } from "./observability/observer.js";
import type { HttpRequestMetaV1, WsOpenMetaV1 } from "./proxy/types.js";
import {
  AllowPlaintext,
  AllowPlaintextForLoopback,
  createNetworkPlaintextPolicy,
  PlaintextRiskAcceptance,
  enforceTransportSecurity,
  RequireTLS,
  type TransportSecurityPolicy,
} from "./client-connect/transportSecurity.js";
import type { ControlplaneErrorEnvelope } from "./controlplane/request.js";
import { decodeHeader, encodeHeader } from "./yamux/header.js";

type PortableVectors = Readonly<{
  version: number;
  transport_policy: ReadonlyArray<Readonly<{
    url: string;
    policy: "require_tls" | "allow_plaintext_for_loopback" | "allow_plaintext" | "network_plaintext";
    allowed_hosts?: readonly string[];
    risk_acceptance?: string;
    allowed: boolean;
  }>>;
  yamux_header: Readonly<{
    bytes_hex: string;
    version: number;
    type: number;
    flags: number;
    stream_id: number;
    length: number;
  }>;
  rpc_envelope: unknown;
  controlplane_error_envelope: ControlplaneErrorEnvelope;
  proxy_http_request_meta: HttpRequestMetaV1;
  proxy_ws_open_meta: WsOpenMetaV1;
  diagnostic_event: DiagnosticEvent;
}>;

type CodeRegistry = Readonly<{
  codes: ReadonlyArray<Readonly<{ code: string }>>;
}>;

const vectors = readJSON<PortableVectors>("../../testdata/portable_protocol_vectors.json");

describe("portable protocol vectors", () => {
  test("match transport, Yamux, RPC, controlplane, proxy, and diagnostic contracts", async () => {
    expect(vectors.version).toBe(1);

    for (const item of vectors.transport_policy) {
      const operation = enforceTransportSecurity({
        rawUrl: item.url,
        path: "direct",
        policy: transportPolicy(item),
      });
      if (item.allowed) {
        await expect(operation).resolves.toBeUndefined();
      } else {
        await expect(operation).rejects.toMatchObject({
          path: "direct",
          stage: "validate",
          code: "transport_policy_denied",
        });
      }
    }

    const headerBytes = decodeHex(vectors.yamux_header.bytes_hex);
    const header = decodeHeader(headerBytes, 0);
    expect(header).toEqual({
      version: vectors.yamux_header.version,
      type: vectors.yamux_header.type,
      flags: vectors.yamux_header.flags,
      streamId: vectors.yamux_header.stream_id,
      length: vectors.yamux_header.length,
    });
    expect(Array.from(encodeHeader(header))).toEqual(Array.from(headerBytes));

    const rpc = assertRpcEnvelope(vectors.rpc_envelope);
    expect(rpc).toMatchObject({
      type_id: 7,
      request_id: 42,
      response_to: 0,
      payload: { message: "flowersec" },
    });
    expect(vectors.controlplane_error_envelope.error).toEqual({
      code: "artifact_not_found",
      message: "No artifact is available.",
    });
    expect(vectors.proxy_http_request_meta).toMatchObject({
      v: 1,
      method: "POST",
      timeout_ms: 1500,
    });
    expect(vectors.proxy_ws_open_meta).toMatchObject({
      v: 1,
      conn_id: "connection-vector-1",
    });
    expect(vectors.diagnostic_event).toMatchObject({
      path: "tunnel",
      stage: "yamux",
      code_domain: "event",
      code: "liveness_timeout",
      result: "fail",
    });

    expect(registryCodes("../../stability/connect_error_code_registry.json")).toContain("resource_exhausted");
    expect(registryCodes("../../stability/connect_diagnostics_code_registry.json")).toContain(vectors.diagnostic_event.code);
  });
});

function transportPolicy(item: PortableVectors["transport_policy"][number]): TransportSecurityPolicy {
  switch (item.policy) {
    case "require_tls": return RequireTLS;
    case "allow_plaintext_for_loopback": return AllowPlaintextForLoopback;
    case "allow_plaintext": return AllowPlaintext;
    case "network_plaintext":
      if (item.risk_acceptance !== PlaintextRiskAcceptance.acceptPreE2ECredentialExposure) {
        throw new Error("invalid network plaintext risk acceptance");
      }
      return createNetworkPlaintextPolicy({
        allowedHosts: item.allowed_hosts ?? [],
        riskAcceptance: PlaintextRiskAcceptance.acceptPreE2ECredentialExposure,
      });
  }
}

function decodeHex(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new Error("hex input must have an even length");
  const output = new Uint8Array(value.length / 2);
  for (let i = 0; i < output.length; i++) {
    const byte = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    if (!Number.isFinite(byte)) throw new Error("invalid hex input");
    output[i] = byte;
  }
  return output;
}

function registryCodes(path: string): string[] {
  return readJSON<CodeRegistry>(path).codes.map((entry) => entry.code);
}

function readJSON<T>(path: string): T {
  return JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8")) as T;
}
