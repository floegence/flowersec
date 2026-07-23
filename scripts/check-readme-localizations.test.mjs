import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  transportV2CommonReadmeLiterals,
  transportV2ReadmeContracts,
  validateTransportV2Readmes,
} from "./readme-transport-v2-contract.mjs";

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

test("Transport v2 README contract accepts the exact runtime support matrix", (t) => {
  const root = createTransportReadmeFixture(t);
  assert.deepEqual(validateTransportV2Readmes(root), []);
});

test("Transport v2 README contract rejects missing common semantics", (t) => {
  const root = createTransportReadmeFixture(t);
  const target = path.join(root, "flowersec-go/README.md");
  fs.writeFileSync(
    target,
    fs.readFileSync(target, "utf8").replace(transportV2CommonReadmeLiterals[1], "QUIC uses a mux."),
  );
  assert.match(validateTransportV2Readmes(root).join("\n"), /flowersec-go\/README\.md.*native FIN/);
});

test("Transport v2 README contract rejects overstated SDK support", (t) => {
  const root = createTransportReadmeFixture(t);
  const target = path.join(root, "flowersec-rust/README.md");
  fs.writeFileSync(
    target,
    fs.readFileSync(target, "utf8").replace(
      transportV2ReadmeContracts["flowersec-rust/README.md"],
      "Transport v2 production carrier support: raw QUIC.",
    ),
  );
  assert.match(validateTransportV2Readmes(root).join("\n"), /flowersec-rust\/README\.md.*production carrier support/);
});
