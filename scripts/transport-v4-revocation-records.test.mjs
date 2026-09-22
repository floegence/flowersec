import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { cborHead, decodeCBOR, decodeMap, encodeCBOR, encodeMap, mapFromNames, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { checkIssuerImpactPurposesReference, joinIssuerImpactFrontiersReference, matchRevokedCertificateEvidenceReference, matchRevokedLeaseEvidenceReference } from "./transport-v4-revocation.mjs";

const {schema, files} = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const bytes = id => Buffer.from(corpus.vectors.find(v => v.id === id).hex,"hex");
const field = (name,key) => BigInt(Object.entries(schema.frame_maps[name].fields).find(([,f]) => f.name === key)[0]);
const value = (name,map,key) => map.get(field(name,key));
const encode = (name, values) => encodeMap(schema,name,mapFromNames(schema,name,values));
const rewrite = (name,input,changes) => {
  const map=decodeMap(schema,name,input);
  for(const [key,entry] of Object.entries(changes)) map.set(field(name,key),entry);
  return encodeMap(schema,name,map);
};
const failure = (run,code) => assert.throws(run,e => e instanceof VectorError && e.code === code);
const hash = (domain,key,input) => Buffer.from(evaluateDomain(schema,domain,{[key]:input}).output_hex,"hex");
const impactName="IssuerAuthorizationImpact";

test("v4.revocation_records.maxima: complete records include all immutable evidence", () => {
  assert.equal(bytes("revoked_certificate_maximum").length,1+3+34+9+9);
  assert.equal(bytes("revoked_lease_maximum").length,1+5+17+17+34+9+9);
  assert.equal(bytes("issuer_impact_maximum").length,1+4+34+19+9+9);
  for(const [name,id] of [["RevokedCertificateEntry","revoked_certificate_maximum"],["RevokedLeaseEntry","revoked_lease_maximum"],[impactName,"issuer_impact_maximum"]]) {
    failure(() => decodeMap(schema,name,Buffer.concat([bytes(id),Buffer.from([0])])),"map_size");
    for(const [key,f] of Object.entries(schema.frame_maps[name].fields)) {
      const changed=decodeMap(schema,name,bytes(id)); changed.delete(BigInt(key));
      failure(() => decodeMap(schema,name,encodeMap(schema,name,changed)),"missing_field");
      assert.ok(!f.optional);
    }
  }
});

test("v4.revocation_records.null_scope: only declared impact positions admit canonical null", () => {
  for(const id of ["issuer_impact_certificate","issuer_impact_connection"]) {
    const raw=bytes(id), map=decodeMap(schema,impactName,raw);
    assert.deepEqual(encodeMap(schema,impactName,map),raw);
    failure(() => encodeCBOR(map),"unsupported_type");
    failure(() => decodeCBOR(raw),"unsupported_type");
  }
  const map=decodeMap(schema,impactName,bytes("issuer_impact_fields"));
  function rawField(key,raw) {
    return Buffer.concat([cborHead(5,map.size), ...[...map].map(([k,v]) =>
      k===key ? Buffer.concat([encodeCBOR(k),raw]) : encodeMap(schema,impactName,new Map([[k,v]])).subarray(1))]);
  }
  for(const name of ["authorization_digest","signing_not_before_ms","signing_not_after_ms"]) {
    const k=field(impactName,name), changed=new Map(map); changed.set(k,null);
    failure(() => encodeMap(schema,impactName,changed),"unsupported_type");
    failure(() => decodeMap(schema,impactName,rawField(k,Buffer.from([0xf6]))),"unsupported_type");
  }
  const k=field(impactName,"max_affected_cohorts");
  // Entire-vector null, nested-array null and noncanonical simple-value null
  // cannot reuse the permission given to one exact uint64 position.
  for(const raw of [Buffer.from([0xf6]),Buffer.from([0x82,0x81,0xf6,0x09]),Buffer.from([0x82,0xf8,0x16,0x09])]) {
    failure(() => decodeMap(schema,impactName,rawField(k,raw)),"unsupported_type");
  }
  const head=decodeMap(schema,"FreshnessHead",bytes("freshness_head_fields"));
  head.set(field("FreshnessHead","credential_revocation_floors"),[null,0n]);
  failure(() => encodeMap(schema,"FreshnessHead",head),"unsupported_type");
  failure(() => decodeCBOR(Buffer.from([0xf6])),"unsupported_type");
});

test("v4.revocation_records.purposes: null never stands for missing or shorter authority", () => {
  const cert=bytes("issuer_impact_certificate"), conn=bytes("issuer_impact_connection"), both=bytes("issuer_impact_fields");
  checkIssuerImpactPurposesReference(schema,cert,true,false);
  checkIssuerImpactPurposesReference(schema,conn,false,true);
  checkIssuerImpactPurposesReference(schema,both,true,true);
  for(const args of [[cert,true,true],[cert,false,true],[conn,true,true],[both,true,false]]) {
    failure(() => checkIssuerImpactPurposesReference(schema,...args),"revocation_impact_purpose");
  }
  failure(() => checkIssuerImpactPurposesReference(schema,cert,true,undefined),"revocation_purpose_context");
  assert.deepEqual(joinIssuerImpactFrontiersReference(schema,cert,conn),[5n,9n]);
  const older=rewrite(impactName,both,{max_affected_cohorts:[50n,8n]});
  const newer=rewrite(impactName,both,{max_affected_cohorts:[4n,90n]});
  const joined=joinIssuerImpactFrontiersReference(schema,older,newer);
  assert.deepEqual(joined,[50n,90n]);
  assert.ok(Object.isFrozen(joined));
  assert.deepEqual(joinIssuerImpactFrontiersReference(schema,newer,older),joined);
  failure(() => joinIssuerImpactFrontiersReference(schema,older,new Proxy(Buffer.alloc(4),{})),"revocation_input_bytes");
});

test("v4.revocation_records.credential_evidence: full signed bytes and original coordinates stay bound", () => {
  const cert=bytes("certificate_fields"), c=decodeMap(schema,"IdentityCertificate",cert);
  const certEntry=encode("RevokedCertificateEntry",{
    certificate_digest:{$bytes:hash("certificate_digest","certificate",cert).toString("hex")},
    cohort:value("IdentityCertificate",c,"revocation_epoch"),expires_at_ms:value("IdentityCertificate",c,"expires_at_ms")
  });
  matchRevokedCertificateEvidenceReference(schema,certEntry,cert);
  const changed=rewrite("IdentityCertificate",cert,{signature:Buffer.alloc(64,7)});
  failure(() => matchRevokedCertificateEvidenceReference(schema,certEntry,changed),"revocation_evidence_digest");
  failure(() => matchRevokedCertificateEvidenceReference(schema,rewrite("RevokedCertificateEntry",certEntry,{cohort:value("IdentityCertificate",c,"revocation_epoch")+1n}),cert),"revocation_certificate_evidence");

  const artifact=bytes("artifact_transport_fields"), a=decodeMap(schema,"Artifact",artifact);
  const deadline=value("Artifact",a,"session_not_after_ms");
  const entry=encode("RevokedLeaseEntry",{
    issuer_key_id:{$bytes:value("Artifact",a,"issuer_key_id").toString("hex")},lease_id:{$bytes:value("Artifact",a,"lease_id").toString("hex")},
    artifact_digest:{$bytes:hash("artifact_digest","artifact",artifact).toString("hex")},cohort:value("Artifact",a,"revocation_epoch"),latest_impact_not_after_ms:deadline
  });
  matchRevokedLeaseEvidenceReference(schema,entry,artifact);
  for(const change of [{issuer_key_id:Buffer.alloc(16,9)},{lease_id:Buffer.alloc(16,9)},{cohort:value("Artifact",a,"revocation_epoch")+1n},{latest_impact_not_after_ms:deadline-1n}]) {
    failure(() => matchRevokedLeaseEvidenceReference(schema,rewrite("RevokedLeaseEntry",entry,change),artifact),"revocation_lease_evidence");
  }
  failure(() => matchRevokedLeaseEvidenceReference(schema,entry,rewrite("Artifact",artifact,{signature:Buffer.alloc(64,7)})),"revocation_evidence_digest");
});
