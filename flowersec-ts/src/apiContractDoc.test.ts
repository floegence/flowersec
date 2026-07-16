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
      doc_tokens: string[];
    }>;
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
    ];

    for (const token of tokens) {
      expect(doc).toContain(token);
    }
  });
});
