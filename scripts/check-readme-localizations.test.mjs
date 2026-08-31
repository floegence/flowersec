import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  transportV3CommonReadmeLiterals,
  transportV3ReadmeContracts,
  transportV3SemanticReadmeContracts,
  validateTransportV3Readmes,
} from "./readme-transport-v3-contract.mjs";
import {
  extractInlineCodeLiterals,
  extractMarkdownShape,
} from "./readme-localization-contract.mjs";

function createTransportReadmeFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-readme-contract-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const files = new Set([
    ...Object.keys(transportV3ReadmeContracts),
    ...Object.keys(transportV3SemanticReadmeContracts),
  ]);
  for (const file of files) {
    const target = path.join(root, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, [
      ...transportV3CommonReadmeLiterals,
      transportV3ReadmeContracts[file],
      ...Object.values(transportV3SemanticReadmeContracts[file] ?? {}),
      "",
    ].filter((value) => value !== undefined).join("\n"));
  }
  return root;
}

function removeSemanticContract(root, file, contract) {
  const target = path.join(root, file);
  const literal = transportV3SemanticReadmeContracts[file][contract];
  fs.writeFileSync(
    target,
    fs.readFileSync(target, "utf8").replace(literal, "stale capability claim"),
  );
}

test("README contract accepts the current user-facing support matrix", (t) => {
  const root = createTransportReadmeFixture(t);
  assert.deepEqual(validateTransportV3Readmes(root), []);
});

test("README contract rejects a missing user-facing support description", (t) => {
  const root = createTransportReadmeFixture(t);
  const target = path.join(root, "flowersec-go/README.md");
  fs.writeFileSync(target, "Supports connections.\n");
  assert.match(validateTransportV3Readmes(root).join("\n"), /flowersec-go\/README\.md.*user-facing support/);
});

test("README contract rejects overstated SDK support", (t) => {
  const root = createTransportReadmeFixture(t);
  const target = path.join(root, "flowersec-rust/README.md");
  fs.writeFileSync(
    target,
    fs.readFileSync(target, "utf8").replace(
      transportV3ReadmeContracts["flowersec-rust/README.md"],
      "The native Rust runtime supports every connection type.",
    ),
  );
  assert.match(validateTransportV3Readmes(root).join("\n"), /flowersec-rust\/README\.md.*user-facing support/);
});

test("README contract rejects localized WebTransport H4 drift", (t) => {
  const root = createTransportReadmeFixture(t);
  removeSemanticContract(root, "README.zh-CN.md", "webtransport_h4");
  assert.match(validateTransportV3Readmes(root).join("\n"), /README\.zh-CN\.md.*webtransport h4 semantics/);
});

test("README contract rejects localized v3 issuer drift", (t) => {
  const root = createTransportReadmeFixture(t);
  removeSemanticContract(root, "README.ja-JP.md", "go_only_v3_issuer");
  assert.match(validateTransportV3Readmes(root).join("\n"), /README\.ja-JP\.md.*go only v3 issuer semantics/);
});

test("README contract rejects localized WebTransport server profile drift", (t) => {
  const root = createTransportReadmeFixture(t);
  removeSemanticContract(root, "README.de-DE.md", "webtransport_server_profile");
  assert.match(validateTransportV3Readmes(root).join("\n"), /README\.de-DE\.md.*webtransport server profile semantics/);
});

test("README contract rejects localized WebTransport server count drift", (t) => {
  const root = createTransportReadmeFixture(t);
  removeSemanticContract(root, "README.fr-FR.md", "webtransport_server_counts");
  assert.match(validateTransportV3Readmes(root).join("\n"), /README\.fr-FR\.md.*webtransport server counts semantics/);
});

test("README contract rejects Go direct-only WebTransport wording", (t) => {
  const root = createTransportReadmeFixture(t);
  removeSemanticContract(root, "flowersec-go/README.md", "webtransport_path_selection");
  assert.match(validateTransportV3Readmes(root).join("\n"), /flowersec-go\/README\.md.*webtransport path selection semantics/);
});

test("SDK README descriptions identify the final recovery owner", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  for (const file of ["flowersec-ts/README.md", "flowersec-swift/README.md"]) {
    const content = fs.readFileSync(path.join(repoRoot, file), "utf8");
    assert.match(
      content,
      /ConnectionController|RetryDisposition/u,
      `${file} should describe structured recovery ownership`,
    );
  }
});

test("README support claims state WebTransport and native package boundaries", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const rootReadme = fs.readFileSync(path.join(repoRoot, "README.md"), "utf8");
  const goReadme = fs.readFileSync(path.join(repoRoot, "flowersec-go/README.md"), "utf8");
  const typescriptReadme = fs.readFileSync(path.join(repoRoot, "flowersec-ts/README.md"), "utf8");
  const nativeReadme = fs.readFileSync(path.join(repoRoot, "flowersec-node-native/README.md"), "utf8");
  assert.match(rootReadme, /Browser profile uses the H3 WebTransport API when present/u);
  assert.match(rootReadme, /native-server carrier surface is\s+WebSocket and raw QUIC for Go, Rust, and Node\.js/u);
  assert.match(goReadme, /supports WebSocket, raw QUIC, and WebTransport across H4/u);
  assert.match(goReadme, /Go the H4\s+runtime that claims the complete `webtransport-server` profile/u);
  assert.match(goReadme, /WebSocket, raw QUIC,\s+and WebTransport are selected internally for either artifact-bound direct or\s+tunnel path/u);
  assert.doesNotMatch(goReadme, /WebTransport is selected only\s+for direct invitations/u);
  assert.match(typescriptReadme, /Browsers support WSS and optional browser-owned WebTransport/u);
  assert.match(typescriptReadme, /Node\.js does not expose WebTransport/u);
  assert.match(nativeReadme, /macOS\s+arm64, macOS x64, Linux arm64 glibc, and Linux x64 glibc/u);
  assert.match(nativeReadme, /Windows and\s+musl packages are not published/u);
});

test("test matrix labels the standalone registry consumer as manual and non-gating", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const matrix = fs.readFileSync(path.join(repoRoot, "docs/TEST_MATRIX.md"), "utf8");
  assert.match(matrix, /Manual published Go-to-Node raw QUIC consumer diagnostic/u);
  assert.match(matrix, /No workflow invokes this diagnostic, it is not release-gating evidence/u);
  assert.equal((matrix.match(/release\/npm-consumer\/go-node-raw-quic\/direct-session/gu) ?? []).length, 1);
  assert.doesNotMatch(matrix, /executed after publication on each supported native package platform/u);
});

test("README states the machine-readable parity counts without ambiguous aliases", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const content = fs.readFileSync(path.join(repoRoot, "README.md"), "utf8");
  assert.match(content, /18 aggregate\s+runtime-role-carrier tuples/u);
  assert.match(content, /24 supported\s+path-specific server units/u);
  assert.match(content, /18\s+direct cells/u);
  assert.match(content, /18\s+tunnel cells/u);
  assert.match(content, /10 direct cells and 14 pairwise tunnel cells that include Go/u);
  assert.match(content, /remaining 8 direct and 4 tunnel cells stay explicitly unverified/u);
  assert.match(content, /Four\s+additional WSS client profiles prove Swift and browser TypeScript against Go/u);
});

test("README localization contract captures structure and literals", () => {
  const source = [
    "# Flowersec",
    "Encrypted sessions for four SDKs.",
    "## Section",
    "- One",
    "- Two",
    "| A | B |",
    "| --- | --- |",
    "| x | y |",
    "```bash",
    "make test",
    "```",
    "`flowersec.Connect`",
  ].join("\n");
  assert.deepEqual(extractMarkdownShape(source), [
    "heading:1",
    "paragraph",
    "heading:2",
    "list-item",
    "list-item",
    "table-row:2",
    "table-row:2",
    "table-row:2",
    "code:bash",
    "paragraph",
  ]);
  assert.deepEqual(extractInlineCodeLiterals(source), ["flowersec.Connect"]);
});

test("README localization contract detects changed API literals", () => {
  const source = "# Flowersec\nEncrypted sessions.\n`flowersec.Connect`\n";
  assert.notDeepEqual(
    extractInlineCodeLiterals(source),
    extractInlineCodeLiterals(source.replace("`flowersec.Connect`", "`flowersec.LegacyConnect`")),
  );
});

test("README localization contract ignores multiline HTML comments", () => {
  const source = [
    "# Flowersec",
    "Visible paragraph.",
    "<!--",
    "## Hidden heading",
    "- Hidden list item with `hidden.API`",
    "-->",
    "## Visible section",
    "Visible `flowersec.Connect` API.",
  ].join("\n");

  assert.deepEqual(extractMarkdownShape(source), [
    "heading:1",
    "paragraph",
    "heading:2",
    "paragraph",
  ]);
  assert.deepEqual(extractInlineCodeLiterals(source), ["flowersec.Connect"]);
});

test("README localization contract preserves text around inline comments", () => {
  const source = "Visible <!-- hidden `hidden.API` --> paragraph with `public.API`.";

  assert.deepEqual(extractMarkdownShape(source), ["paragraph"]);
  assert.deepEqual(extractInlineCodeLiterals(source), ["public.API"]);
});

test("README localization contract ignores unterminated HTML comments", () => {
  const source = "# Flowersec\n<!-- hidden\n## Hidden heading\n`hidden.API`";

  assert.deepEqual(extractMarkdownShape(source), ["heading:1"]);
  assert.deepEqual(extractInlineCodeLiterals(source), []);
});
