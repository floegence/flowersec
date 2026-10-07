import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

type APIContractManifest = {
  docs: {
    api_contract: string;
    cli_tokens: string[];
  };
  go: {
    compile_targets: Array<{
      doc_package_token: string;
      entries: Array<{ doc_token: string }>;
    }>;
  };
  ts: {
    subpaths: Array<{
      specifier: string;
      doc_tokens: string[];
    }>;
  };
  swift: {
    doc_tokens: string[];
  };
  rust: {
    doc_tokens: string[];
  };
};

describe("docs/API_CONTRACT.md", () => {
  it("covers manifest-defined public API tokens", () => {
    const repoRoot = path.join(process.cwd(), "..");
    const manifest = JSON.parse(
      fs.readFileSync(path.join(repoRoot, "stability", "api_contract_manifest.json"), "utf8")
    ) as APIContractManifest;

    const doc = fs.readFileSync(path.join(repoRoot, manifest.docs.api_contract), "utf8");
    const tokens = [
      ...manifest.docs.cli_tokens,
      "`docs/API_CHANGE_POLICY.md`",
      "`stability/api_contract_manifest.json`",
      ...manifest.go.compile_targets.flatMap((target) => [
        target.doc_package_token,
        ...target.entries.map((entry) => entry.doc_token),
      ]),
      ...manifest.ts.subpaths.flatMap((subpath) => subpath.doc_tokens),
      ...manifest.swift.doc_tokens,
      ...manifest.rust.doc_tokens,
    ];

    for (const token of tokens) {
      expect(doc).toContain(token);
    }
  });

  it("documents original TypeScript pool observation and surface ownership", () => {
    const repoRoot = path.join(process.cwd(), "..");
    const manifest = JSON.parse(fs.readFileSync(path.join(repoRoot, "stability", "api_contract_manifest.json"), "utf8")) as APIContractManifest;
    const doc = fs.readFileSync(path.join(repoRoot, manifest.docs.api_contract), "utf8");
    const start = doc.indexOf("## TypeScript\n"), end = doc.indexOf("\n## Swift", start);
    expect(start).toBeGreaterThanOrEqual(0); expect(end).toBeGreaterThan(start);
    const section = doc.slice(start, end);
    for (const name of ["PreauthorizedPoolSource", "TopUpHandle", "PoolSourceConfiguration", "TopUpOptions", "TopUpState", "TopUpResult", "TopUpControlTransport", "TopUpExchangeResult", "PoolControlReplyDecoder", "createSessionPoolControl",
      "ProxyCredentialPolicy", "ProxyCookieScope", "ProxyCredentialAuthentication", "createProxySurface", "ProxySurface", "ProxySurfaceOptions", "ProxySurfaceMode", "ProxySessionBinding", "ProxySurfaceRequestPolicy", "ProxyPublicationOwner", "ProxyClearResult"]) {
      expect(section).toContain("`" + name + "`");
    }
    expect(section).toContain("A stale handle never observes a later");
    expect(section).toContain("proof, control and persistence tails");
    expect(section).toContain("preserves the independent `server_invalidated` fact");
  });

  it("documents the current cross-language service error boundary", () => {
    const repoRoot = path.join(process.cwd(), "..");
    const manifest = JSON.parse(
      fs.readFileSync(path.join(repoRoot, "stability", "api_contract_manifest.json"), "utf8")
    ) as APIContractManifest;
    const doc = fs.readFileSync(path.join(repoRoot, manifest.docs.api_contract), "utf8");

    expect(doc).toContain("Remote application failures are semantically separate");
    expect(doc).toContain("TypeScript declares bounded `ApplicationErrorDefinition`");
    expect(doc).toContain("its handlers throw `ServiceError`");
    expect(doc).toContain("Swift exposes `ServiceApplicationError`");
    expect(doc).toContain("Rust exposes `ServiceError`");
  });
});
