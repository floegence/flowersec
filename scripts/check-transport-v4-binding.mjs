#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { digest, repositoryRoot } from "./transport-v4-files.mjs";
import { verifyArchitectureReviews } from "./transport-v4-review-evidence.mjs";

const expectedDesignSHA = "3f155c57dc1be95d190af9ce2ac5b0113006650259372ab09521c6cff04bef79";

export function verifyTraceability(trace, schema, manifest) {
  assert.equal(trace.design_sha256, schema.design_sha256);
  assert.equal(trace.schema_revision, schema.schema_revision);
  assert.ok(trace.entries.length > 0, "empty implementation trace");
  const ids = new Set(), testIDs = new Set(), vectors = new Set([...manifest.vectors,...(manifest.domain_vectors ?? []),...(manifest.text_vectors ?? []),...(manifest.query_vectors ?? []),...(manifest.fragment_vectors ?? []),...(manifest.fragment_state_vectors ?? []),...(manifest.stream_state_vectors ?? []),...(manifest.api_vectors ?? []),...(manifest.application_header_vectors ?? []),...(manifest.notify_vectors ?? []),...(manifest.signature_vectors ?? []),...(manifest.strict_signature_vectors ?? []),...(manifest.dh_vectors ?? []),...(manifest.noise_vectors ?? []),...(manifest.record_vectors ?? []),...(manifest.ready_vectors ?? []),...(manifest.rekey_vectors ?? []),...(manifest.resource_vectors ?? []),...(manifest.resource_cost_vectors ?? []),...(manifest.time_arithmetic_vectors ?? []),...(manifest.crypto_usage_vectors ?? []),...(manifest.rekey_credit_vectors ?? [])].map((v) => v.id));
  for (const entry of trace.entries) {
    assert.match(entry.id, /^[a-z][a-z0-9_]*$/u);
    assert.ok(!ids.has(entry.id), `duplicate trace ID ${entry.id}`); ids.add(entry.id);
    for (const name of ["design_sections", "source_targets", "sdk_entries", "required_test_ids"]) {
      assert.ok(Array.isArray(entry[name]) && entry[name].length > 0, `${entry.id}: missing ${name}`);
    }
    for (const id of entry.required_test_ids) {
      assert.match(id, /^v4\.[a-z0-9_]+\.[a-z0-9_]+$/u);
      assert.ok(!testIDs.has(id), `duplicate required test ID ${id}`); testIDs.add(id);
    }
    for (const ref of entry.registry_refs) {
      assert.match(ref, /^(?:\/[a-zA-Z0-9_]+)+$/u);
      let definition = schema;
      for (const key of ref.slice(1).split("/")) {
        assert.ok(definition && Object.hasOwn(definition, key), `${entry.id}: unresolved registry reference ${ref}`);
        definition = definition[key];
      }
    }
    for (const id of entry.vector_ids) assert.ok(vectors.has(id), `${entry.id}: missing vector ${id}`);
  }
}

function resolveExternalPath(root, relative) {
  const direct = path.resolve(root, relative);
  if (fs.existsSync(direct)) return direct;
  // A managed worktree may live below <repository-parent>/worktrees/<name>.
  // The contract keeps external artifacts one directory above the repository,
  // so retry from the parent of that worktree when the direct path is absent.
  return path.resolve(path.dirname(root), relative);
}

export function verifyBinding({root = repositoryRoot, requireExternal = false, designPath, evidencePath} = {}) {
  const read = (file) => fs.readFileSync(path.join(root, file));
  const contract = JSON.parse(read("stability/transport_v4_contract.json"));
  const binding = read("docs/TRANSPORT_V4_BINDING.md").toString();
  assert.equal(contract.version, 4);
  assert.equal(contract.status, "draft");
  assert.equal(contract.design.sha256, expectedDesignSHA);
  assert.equal(contract.design.product_version, "6.0.0");
  assert.equal(contract.design.wire_profile, "flowersec/4");
  assert.ok(binding.includes(expectedDesignSHA));
  if (contract.design.review_evidence_sha256 !== null) {
    assert.match(contract.design.review_evidence_sha256, /^[a-f0-9]{64}$/u);
    assert.equal(contract.design.review_evidence_status, "pinned");
    assert.ok(binding.includes(contract.design.review_evidence_sha256));
  } else assert.equal(contract.design.review_evidence_status, "pending_independent_review");
  assert.equal(contract.schema.status, "not_frozen");
  assert.equal(contract.schema.path, "stability/transport_v4_schema.json");
  const schemaBytes = read(contract.schema.path), schema = JSON.parse(schemaBytes);
  assert.equal(digest(schemaBytes), contract.schema.sha256, "bound schema SHA drift");
  assert.equal(schema.design_sha256, expectedDesignSHA);
  assert.equal(schema.schema_revision, contract.schema.revision);
  assert.ok(binding.includes(`| Schema revision | \`${contract.schema.revision}\` |`), "binding document schema revision drift");
  assert.equal(schema.status, "draft");
  assert.ok(schema.unresolved.length > 0);
  const manifestBytes = read(`${contract.vectors.path}/manifest.json`), manifest = JSON.parse(manifestBytes);
  assert.equal(digest(manifestBytes), contract.vectors.manifest_sha256, "bound vector manifest SHA drift");
  assert.equal(manifest.schema_sha256, contract.schema.sha256);
  assert.equal(manifest.schema_revision, contract.schema.revision);
  assert.equal(manifest.design_sha256, expectedDesignSHA);
  assert.equal(manifest.coverage, contract.vectors.status);
  const trace = JSON.parse(read(contract.traceability.path));
  assert.equal(trace.design_sha256, expectedDesignSHA);
  assert.equal(trace.schema_revision, contract.schema.revision);
  verifyTraceability(trace, schema, manifest);
  for (const entry of trace.entries) {
    if (entry.artifact) assert.ok(fs.existsSync(path.join(root, entry.artifact)), `missing tracked artifact ${entry.artifact}`);
    for (const test of entry.tests) assert.ok(fs.existsSync(path.join(root, test)), `missing tracked test ${test}`);
  }
  const sources = [
    {name:"design", file:designPath ?? process.env.FLOWERSEC_V4_DESIGN_PATH ?? resolveExternalPath(root, contract.design.source_path), sha:expectedDesignSHA},
    {name:"review_evidence", file:evidencePath ?? process.env.FLOWERSEC_V4_EVIDENCE_PATH ?? resolveExternalPath(root, contract.design.review_evidence_path), sha:contract.design.review_evidence_sha256},
  ];
  const availability = {};
  for (const source of sources) {
    if (source.sha === null) {
      availability[source.name] = "unbound";
      if (requireExternal) throw new Error(`required ${source.name} has no verified evidence binding`);
      continue;
    }
    assert.match(source.sha, /^[a-f0-9]{64}$/u);
    if (!fs.existsSync(source.file)) {
      availability[source.name] = "missing";
      if (requireExternal) throw new Error(`required ${source.name} unavailable: ${source.file}`);
    } else {
      assert.equal(digest(fs.readFileSync(source.file)), source.sha, `external ${source.name} SHA changed`);
      if (source.name === "review_evidence") verifyArchitectureReviews(source.file, expectedDesignSHA);
      availability[source.name] = "verified";
    }
  }
  return {references:"verified", external:availability, schema_gate:"not_frozen"};
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length > 3 || (process.argv[2] && process.argv[2] !== "--require-external")) throw new Error("usage: check-transport-v4-binding.mjs [--require-external]");
  console.log(JSON.stringify(verifyBinding({requireExternal:process.argv[2] === "--require-external"})));
}
