#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadTransportRegistry, provenance } from "./registry_provenance.mjs";

if (process.argv.length !== 3 || !["--check", "--write-provenance"].includes(process.argv[2])) {
  throw new Error("usage: validate_application_vectors.mjs --check|--write-provenance");
}

const root = dirname(fileURLToPath(import.meta.url));
const transport = loadTransportRegistry();
const names = [
  "idna_vectors.json",
  "open_unicode_vectors.json",
  "rpc_error_vectors.json",
  "rpc_malformed_envelopes.json",
  "rpc_notification_vectors.json",
  "session_handler_vectors.json",
];

for (const name of names) {
  const source = readFileSync(join(root, name), "utf8");
  const value = JSON.parse(source);
  assert.equal(source, `${JSON.stringify(value, null, 2)}\n`, `${name} must use stable JSON formatting`);
  assert.equal(value.transport_contract_version, 3, `${name} must be owned by Transport v3`);
  assert.equal(Object.hasOwn(value, "inherited_codec_from"), false, `${name} must be self-contained`);
  if (process.argv[2] === "--write-provenance") {
    writeFileSync(join(root, name), `${JSON.stringify(provenance(value, transport), null, 2)}\n`);
  } else {
    assert.equal(value.registry_sha256, transport.registrySha256, `${name} registry provenance`);
    assert.equal(value.design_sha256, transport.designSha256, `${name} design provenance`);
  }
}

const idna = JSON.parse(readFileSync(join(root, "idna_vectors.json"), "utf8"));
assert.equal(idna.unicode_version, "15.1.0");
assert.match(idna.processing, /UTS #46 non-transitional/);

const handlers = JSON.parse(readFileSync(join(root, "session_handler_vectors.json"), "utf8"));
const reserved = handlers.stream_kinds.filter(({ id }) => id.startsWith("reserved-"));
assert.deepEqual(reserved.map(({ unit }) => unit), ["flowersec.rpc.v2", "flowersec.rpc.v3"]);
