import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  transportV2CommonReadmeLiterals,
  transportV2ReadmeContracts,
  validateTransportV2Readmes,
} from "./readme-transport-v2-contract.mjs";
import {
  extractInlineCodeLiterals,
  extractMarkdownShape,
} from "./readme-localization-contract.mjs";

function createTransportReadmeFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-readme-contract-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const [file, status] of Object.entries(transportV2ReadmeContracts)) {
    const target = path.join(root, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `${transportV2CommonReadmeLiterals.join("\n")}\n${status}\n`);
  }
  return root;
}

test("README contract accepts the current user-facing support matrix", (t) => {
  const root = createTransportReadmeFixture(t);
  assert.deepEqual(validateTransportV2Readmes(root), []);
});

test("README contract rejects a missing user-facing support description", (t) => {
  const root = createTransportReadmeFixture(t);
  const target = path.join(root, "flowersec-go/README.md");
  fs.writeFileSync(target, "Supports connections.\n");
  assert.match(validateTransportV2Readmes(root).join("\n"), /flowersec-go\/README\.md.*user-facing support/);
});

test("README contract rejects overstated SDK support", (t) => {
  const root = createTransportReadmeFixture(t);
  const target = path.join(root, "flowersec-rust/README.md");
  fs.writeFileSync(
    target,
    fs.readFileSync(target, "utf8").replace(
      transportV2ReadmeContracts["flowersec-rust/README.md"],
      "The native Rust runtime supports every connection type.",
    ),
  );
  assert.match(validateTransportV2Readmes(root).join("\n"), /flowersec-rust\/README\.md.*user-facing support/);
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
