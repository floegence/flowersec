import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

function readRepoFile(...parts: string[]): string {
  return fs.readFileSync(path.join(process.cwd(), "..", ...parts), "utf8");
}

describe("cookbook documentation contracts", () => {
  it("keeps the root README focused on source-first SDK and cookbook navigation", () => {
    const doc = readRepoFile("README.md");

    expect(doc).toContain("End-to-end encrypted communication, consistently implemented across Go, TypeScript, Swift, and Rust.");
    expect(doc).toContain("examples/go/README.md");
    expect(doc).toContain("examples/ts/README.md");
    expect(doc).toContain("examples/swift/README.md");
    expect(doc).toContain("examples/rust/README.md");
    expect(doc).toContain("ConnectArtifact -> connect -> RPC / stream / proxy");
    expect(doc).not.toMatch(/Migration\s+guide/);
    expect(doc).not.toContain('from "@floegence/flowersec-core');
  });

  it("keeps a common runnable structure across all language cookbooks", () => {
    const cookbooks: ReadonlyArray<readonly [string, string]> = [
      ["go", "go_client_tunnel_simple"],
      ["ts", "node-artifact-client.mjs"],
      ["swift", "swift run --package-path ./examples/swift"],
      ["rust", "cargo run --manifest-path ./examples/rust/Cargo.toml"],
    ];

    for (const [language, entrypoint] of cookbooks) {
      const doc = readRepoFile("examples", language, "README.md");
      expect(doc).toContain("## Run");
      expect(doc).toContain("## Examples");
      expect(doc).toContain("## Source Map");
      expect(doc).toContain("## Runtime Boundaries");
      expect(doc).toContain("## Troubleshooting");
      expect(doc).toContain(entrypoint);
      expect(doc).toContain("token_replay");
    }
  });

  it("keeps the cookbook index aligned with the shared demo contract", () => {
    const doc = readRepoFile("examples", "README.md");

    expect(doc).toContain("go/README.md");
    expect(doc).toContain("ts/README.md");
    expect(doc).toContain("swift/README.md");
    expect(doc).toContain("rust/README.md");
    expect(doc).toContain("node ./examples/ts/dev-server.mjs");
    expect(doc).toContain("controlplane_http_url");
  });

  it("keeps the TypeScript package README linked to runtime entrypoints and its cookbook", () => {
    const doc = fs.readFileSync(path.join(process.cwd(), "README.md"), "utf8");

    expect(doc).toContain("https://github.com/floegence/flowersec/tree/main/examples/ts");
    expect(doc).toContain("@floegence/flowersec-core/browser");
    expect(doc).toContain("@floegence/flowersec-core/node");
    expect(doc).toContain("@floegence/flowersec-core/controlplane");
    expect(doc).toContain("@floegence/flowersec-core/proxy");
  });

  it("keeps the connect artifact contract and compatibility rejections explicit", () => {
    const doc = readRepoFile("docs", "CONNECT_ARTIFACTS.md");

    expect(doc).toContain("assertConnectArtifact(...)");
    expect(doc).toContain("protocolio.DecodeConnectArtifactJSON(...)");
    expect(doc).toContain("requestConnectArtifact");
    expect(doc).toContain("grant_server");
    expect(doc).toContain("token` / `role`");
  });

  it("keeps the controlplane envelope and helper error contract explicit", () => {
    const doc = readRepoFile("docs", "CONTROLPLANE_ARTIFACT_FETCH.md");

    expect(doc).toContain('"connect_artifact"');
    expect(doc).toContain("ControlplaneRequestError");
    expect(doc).toContain("client.RequestError");
    expect(doc).toContain("controlplanehttp.NewArtifactHandler(...)");
    expect(doc).toContain("connectNode(artifactEnvelope.connect_artifact");
    expect(doc).toContain("error.code");
    expect(doc).toContain("error.message");
  });

  it("keeps diagnostic overflow and scope warning codes documented", () => {
    const doc = readRepoFile("docs", "CORRELATION_AND_DIAGNOSTICS.md");

    expect(doc).toContain("diagnostics_overflow");
    expect(doc).toContain("scope_ignored_missing_resolver");
    expect(doc).toContain("scope_ignored_relaxed_validation");
    expect(doc).toContain("attempt_seq");
    expect(doc).toContain("session_id");
  });
});
