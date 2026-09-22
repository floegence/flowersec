import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { buildSignatureCorpus, verifySignaturePlan } from "./transport-v4-signatures.mjs";

const {schema, files} = buildArtifacts();
const domains = JSON.parse(files.get("testdata/transport_v4/domains.json"));
const signatures = JSON.parse(files.get("testdata/transport_v4/signatures.json"));

test("v4.signatures.known_answer: RFC8032 test 1 anchors deterministic fixture signing", () => {
  const answer = signatures.vectors.find(v => v.domain === null && v.accept);
  assert.equal(answer.message_hex, "");
  assert.equal(answer.public_key_hex, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  assert.equal(answer.signature_hex,
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb882" +
    "1590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
  const changed = structuredClone(schema);
  changed.signature_vector_plan.known_answer.signature_hex = "00".repeat(64);
  assert.throws(() => buildSignatureCorpus(changed, domains), /known answer mismatch/u);
});

test("v4.signatures.domain_coverage: every registered Ed25519 input has exact signature bytes", () => {
  const registered = new Set(schema.domains.filter(d => d.operation === "ed25519").map(d => d.name));
  const inputs = domains.vectors.filter(v => !v.expected_error && registered.has(v.domain));
  const actual = signatures.vectors.filter(v => v.accept && v.domain !== null);
  assert.deepEqual(actual.map(v => v.domain_vector), inputs.map(v => v.id));
  for (const [index, vector] of actual.entries()) assert.equal(vector.message_hex, inputs[index].result.input_hex);
  const missing = structuredClone(domains);
  const removed = actual[0].domain;
  missing.vectors = missing.vectors.filter(v => v.domain !== removed);
  assert.throws(() => buildSignatureCorpus(schema, missing), /uncovered signature domain/u);
  assert.equal(signatures.qualification, "actual_public_fixture_signatures_only");
});

test("v4.signatures.mutations: every positive retains all canonicality and authenticity negatives", () => {
  const seen = new Set();
  for (const vector of signatures.vectors) {
    assert.ok(!seen.has(vector.id)); seen.add(vector.id);
    if (!vector.accept) continue;
    const negatives = signatures.vectors.filter(v => v.id.startsWith(vector.id + "_") && !v.accept);
    assert.deepEqual(negatives.map(v => v.mutation), schema.signature_vector_plan.negative_mutations);
    const noncanonical = negatives.find(v => v.mutation === "noncanonical_scalar");
    const scalar = hex => BigInt("0x" + Buffer.from(hex.slice(64), "hex").reverse().toString("hex"));
    assert.equal(scalar(noncanonical.signature_hex) - scalar(vector.signature_hex),
      (1n << 252n) + 27742317777372353535851937790883648493n);
    assert.equal(noncanonical.signature_hex.slice(0, 64), vector.signature_hex.slice(0, 64));
  }
  const weakened = structuredClone(schema);
  weakened.signature_vector_plan.negative_mutations.pop();
  assert.throws(() => verifySignaturePlan(weakened));
});
