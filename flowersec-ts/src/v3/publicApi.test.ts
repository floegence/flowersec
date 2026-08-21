import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import {
  ArtifactHandleV3,
  ArtifactLeaseV3,
  ArtifactParseErrorV3,
  createArtifactLeaseV3,
  parseArtifactV3,
} from "../facade.js";
import * as browser from "../browser/index.js";
import * as node from "../node/index.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{
  positive: readonly Readonly<{ artifact_json: string }>[];
  negative: readonly Readonly<{ value: string }>[];
}>;
const v2Fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v2/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;

describe("transport v3 public entry surface", () => {
  test("parses and leases an opaque v3 artifact without exposing credentials or pins", () => {
    const handle = parseArtifactV3(fixture.positive[0]!.artifact_json);
    const lease = createArtifactLeaseV3(handle, vi.fn(async () => undefined));
    expect(handle).toBeInstanceOf(ArtifactHandleV3);
    expect(lease).toBeInstanceOf(ArtifactLeaseV3);
    expect(JSON.stringify(handle)).toBe("{}");
    expect(JSON.stringify(lease)).toBe("{}");
    expect("path" in handle).toBe(false);
    expect("tls" in handle).toBe(false);
    expect("pins" in handle).toBe(false);
  });

  test("projects all parse failures into the stable redacted public error", () => {
    for (const vector of fixture.negative) {
      expect(() => parseArtifactV3(vector.value)).toThrowError(ArtifactParseErrorV3);
      try { parseArtifactV3(vector.value); } catch (error) {
        expect((error as Error).message).not.toContain("https://");
        expect((error as Error).message).not.toContain("value_b64u");
      }
    }
  });

  test("exports v3 connect and controller factories from both runtime entries", () => {
    expect(browser.connect).toBe(browser.connectV3);
    expect(browser.connectV3).toBeTypeOf("function");
    expect(browser.createConnectionControllerV3).toBeTypeOf("function");
    expect(node.connect).toBe(node.connectV3);
    expect(node.connectV3).toBeTypeOf("function");
    expect(node.createConnectionControllerV3).toBeTypeOf("function");
    expect(browser.v2.connect).not.toBe(browser.connect);
    expect(node.v2.connect).not.toBe(node.connect);
  });

  test("keeps Node v2 server and issuer APIs behind the explicit namespace", () => {
    expect(node.createAcceptor).toBe(node.createAcceptorV3);
    expect(node.createTunnelRuntime).toBe(node.createTunnelRuntimeV3);
    expect(node.RPCHandlers).toBeTypeOf("function");
    expect(node.SessionHandlers).toBeTypeOf("function");
    expect(node.SessionHandlers).not.toBe(node.v2.SessionHandlers);
    for (const legacyExport of [
      "AuthorizationRecord",
      "ControlPlaneError",
      "EndpointSet",
      "IssuedArtifact",
      "Issuer",
      "ProxyServer",
      "RuntimeAuthorizationRequest",
      "authorizeRuntime",
      "authorizeTunnelRuntime",
    ]) {
      expect(legacyExport in node).toBe(false);
    }
    expect(node.v2.Issuer).toBeTypeOf("function");
    expect(node.v2.authorizeRuntime).toBeTypeOf("function");
    expect(node.v2.createAcceptor).toBeTypeOf("function");
    expect(node.v2.createTunnelRuntime).toBeTypeOf("function");
    expect(node.v2.ProxyServer).toBeTypeOf("function");
  });

  test("keeps v2 parsing only behind the explicit namespace", () => {
    const raw = v2Fixture.positive[0]!.artifact_json;
    expect(() => parseArtifactV3(raw)).toThrowError(expect.objectContaining({ code: "invalid_artifact" }));
    expect(JSON.stringify(browser.v2.parseArtifact(raw))).toBe("{}");
    expect(JSON.stringify(node.v2.parseArtifact(raw))).toBe("{}");
  });
});
