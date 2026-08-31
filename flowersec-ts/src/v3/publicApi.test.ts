import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import {
  Artifact,
  ArtifactError,
  ArtifactLease,
  createArtifactLease,
  parseArtifact,
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

describe("current public entry surface", () => {
  test("parses and leases an opaque Transport v3 artifact", () => {
    const handle = parseArtifact(fixture.positive[0]!.artifact_json);
    const lease = createArtifactLease(handle, vi.fn(async () => undefined));
    expect(handle).toBeInstanceOf(Artifact);
    expect(lease).toBeInstanceOf(ArtifactLease);
    expect(JSON.stringify(handle)).toBe("{}");
    expect(JSON.stringify(lease)).toBe("{}");
    expect("path" in handle).toBe(false);
    expect("tls" in handle).toBe(false);
  });

  test("projects parse failures and v2 artifacts to invalid_artifact", () => {
    for (const vector of fixture.negative) {
      expect(() => parseArtifact(vector.value)).toThrowError(ArtifactError);
    }
    expect(() => parseArtifact('{"profile":"flowersec/2","v":2}')).toThrowError(
      expect.objectContaining({ code: "invalid_artifact" }),
    );
  });

  test("exports only unversioned runtime and server names", () => {
    for (const runtime of [browser, node]) {
      expect(runtime.connect).toBeTypeOf("function");
      expect(runtime.createConnectionController).toBeTypeOf("function");
      expect("connectV3" in runtime).toBe(false);
      expect("createConnectionControllerV3" in runtime).toBe(false);
      expect("v2" in runtime).toBe(false);
    }
    expect(node.createAcceptor).toBeTypeOf("function");
    expect(node.createTunnelRuntime).toBeTypeOf("function");
    expect(node.ProxyServer).toBeTypeOf("function");
    expect(node.SessionHandlers).toBeTypeOf("function");
    expect("createAcceptorV3" in node).toBe(false);
    expect("createTunnelRuntimeV3" in node).toBe(false);
  });

  test("composes the authorizer with only an opaque public artifact", () => {
    const artifact = parseArtifact(fixture.positive[0]!.artifact_json);
    const authorize: node.AcceptorOptions["authorize"] = async () => ({
      accepted: true,
      artifact,
    });
    expect(authorize).toBeTypeOf("function");
    const declaration = readFileSync(
      new URL("../../dist/node/acceptorV3.d.ts", import.meta.url),
      "utf8",
    );
    expect(declaration).toContain("ArtifactHandleV3");
    expect(declaration).not.toMatch(/\bArtifactV3\b/u);
  });
});
