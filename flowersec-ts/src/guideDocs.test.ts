import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

function readRepoFile(...parts: string[]): string {
  return fs.readFileSync(path.join(process.cwd(), "..", ...parts), "utf8");
}

describe("documentation contracts", () => {
  it("README quickstart stays aligned with artifact-first browser and node flows", () => {
    const doc = readRepoFile("README.md");

    expect(doc).toContain('import { connectBrowser, requestConnectArtifact } from "@floegence/flowersec-core/browser";');
    expect(doc).toContain("connectBrowser(artifact)");
    expect(doc).toContain('import { connectNode } from "@floegence/flowersec-core/node";');
    expect(doc).toContain("const artifactEnvelope = await fetch(");
    expect(doc).toContain("connectNode(artifactEnvelope.connect_artifact");
    expect(doc).toContain('body: JSON.stringify({ endpoint_id: "env_demo" })');
  });

  it("package README keeps the TypeScript package examples on the recommended artifact-first path", () => {
    const doc = fs.readFileSync(path.join(process.cwd(), "README.md"), "utf8");

    expect(doc).toContain('import { connectBrowser, requestConnectArtifact } from "@floegence/flowersec-core/browser";');
    expect(doc).toContain("requestConnectArtifact({");
    expect(doc).toContain("connectBrowser(artifact)");
    expect(doc).toContain("const artifactEnvelope = await fetch(");
    expect(doc).toContain("connectNode(artifactEnvelope.connect_artifact");
  });

  it("integration guide keeps browser and node examples aligned with the stable helper contract", () => {
    const doc = readRepoFile("docs", "INTEGRATION_GUIDE.md");

    expect(doc).toContain("requestConnectArtifact(...)");
    expect(doc).toContain("requestEntryConnectArtifact(...)");
    expect(doc).toContain("connectBrowser(artifact, {})");
    expect(doc).toContain("connectNode(artifactEnvelope.connect_artifact");
    expect(doc).toContain("client.RequestConnectArtifact(...)");
  });

  it("connect artifacts doc lists the stable artifact exports and compatibility rejections", () => {
    const doc = readRepoFile("docs", "CONNECT_ARTIFACTS.md");

    expect(doc).toContain("assertConnectArtifact(...)");
    expect(doc).toContain("protocolio.DecodeConnectArtifactJSON(...)");
    expect(doc).toContain("requestConnectArtifact");
    expect(doc).toContain("grant_server");
    expect(doc).toContain("token` / `role`");
  });

  it("controlplane artifact fetch doc keeps the stable envelope and helper error contract explicit", () => {
    const doc = readRepoFile("docs", "CONTROLPLANE_ARTIFACT_FETCH.md");

    expect(doc).toContain('"connect_artifact"');
    expect(doc).toContain("ControlplaneRequestError");
    expect(doc).toContain("client.RequestError");
    expect(doc).toContain("artifactEnvelope.connect_artifact");
    expect(doc).toContain("error.code");
    expect(doc).toContain("error.message");
  });

  it("correlation and diagnostics doc keeps the stable overflow and scope warning codes documented", () => {
    const doc = readRepoFile("docs", "CORRELATION_AND_DIAGNOSTICS.md");

    expect(doc).toContain("diagnostics_overflow");
    expect(doc).toContain("scope_ignored_missing_resolver");
    expect(doc).toContain("scope_ignored_relaxed_validation");
    expect(doc).toContain("attempt_seq");
    expect(doc).toContain("session_id");
  });
});
