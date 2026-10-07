import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { transportReadmeContracts, validateTransportReadmes } from "./readme-transport-contract.mjs";
import {
  extractInlineCodeLiterals,
  extractMarkdownShape,
} from "./readme-localization-contract.mjs";

function createTransportReadmeFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-readme-contract-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [file, literals] of Object.entries(transportReadmeContracts)) {
    const target = path.join(root, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `${literals.join("\n")}\n`);
  }
  return root;
}

test("README contract accepts current public owners", (t) => {
  assert.deepEqual(validateTransportReadmes(createTransportReadmeFixture(t)), []);
});

test("README contract rejects a missing current SDK owner", (t) => {
  const root = createTransportReadmeFixture(t);
  fs.writeFileSync(path.join(root, "flowersec-swift/README.md"), "TransportEnvironment ConnectionController\n");
  assert.match(validateTransportReadmes(root).join("\n"), /flowersec-swift.*ServeHandle/u);
});

test("README contract rejects an obsolete envelope claim", (t) => {
  const root = createTransportReadmeFixture(t);
  fs.appendFileSync(path.join(root, "README.md"), "flowersec-private-loopback/1\n");
  assert.match(validateTransportReadmes(root).join("\n"), /retired transport contract/u);
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

test("README support claims retain explicit current qualification", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const rootReadme = fs.readFileSync(path.join(repoRoot, "README.md"), "utf8");
  assert.match(rootReadme, /provider qualification/u);
  assert.match(rootReadme, /local_loopback/u);
  assert.match(rootReadme, /docs\/TRANSPORT_V4_BINDING\.md/u);
});

test("test matrix labels the standalone registry consumer as manual and non-gating", () => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const matrix = fs.readFileSync(path.join(repoRoot, "docs/TEST_MATRIX.md"), "utf8");
  assert.match(matrix, /Manual published Go-to-Node raw QUIC consumer diagnostic/u);
  assert.match(matrix, /No workflow invokes this diagnostic, it is not release-gating evidence/u);
  assert.equal((matrix.match(/release\/npm-consumer\/go-node-raw-quic\/direct-session/gu) ?? []).length, 1);
  assert.doesNotMatch(matrix, /executed after publication on each supported native package platform/u);
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
