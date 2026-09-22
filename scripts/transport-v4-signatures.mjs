import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { strictHex } from "./transport-v4-codec.mjs";

// Actual Ed25519 operations over registry-generated inputs, using public RFC
// fixture secrets only. This is not issuer trust, certificate validation, Noise,
// independent cryptographic review or a production key-handling implementation.
const privatePrefix = Buffer.from("302e020100300506032b657004220420", "hex");
const publicPrefix = Buffer.from("302a300506032b6570032100", "hex");
const mutations = ["message_suffix","signature_bit","wrong_key","short_signature","long_signature","noncanonical_scalar","short_key","long_key"];
const order = (1n << 252n) + 27742317777372353535851937790883648493n;

export function verifySignaturePlan(schema) {
  const plan=schema.signature_vector_plan;
  assert.equal(plan.status,"public_fixture_keys_only");
  assert.deepEqual(plan.negative_mutations,mutations);
  for(const key of ["seed_hex","public_key_hex","wrong_public_key_hex"]) assert.equal(strictHex(plan[key]).length,32);
  assert.equal(strictHex(plan.known_answer.signature_hex).length,64);
  assert.notEqual(plan.public_key_hex,plan.wrong_public_key_hex);
  assert.match(plan.source,/RFC8032/u);
}

const publicKey = bytes => createPublicKey({key:Buffer.concat([publicPrefix,bytes]),format:"der",type:"spki"});
function accepts(vector) {
  const key=strictHex(vector.public_key_hex), signature=strictHex(vector.signature_hex);
  if(key.length!==32 || signature.length!==64) return false;
  return verify(null,strictHex(vector.message_hex),publicKey(key),signature);
}

export function buildSignatureCorpus(schema, domainCorpus) {
  verifySignaturePlan(schema);
  const plan=schema.signature_vector_plan, seed=strictHex(plan.seed_hex);
  const secret=createPrivateKey({key:Buffer.concat([privatePrefix,seed]),format:"der",type:"pkcs8"});
  const publicDER=createPublicKey(secret).export({format:"der",type:"spki"});
  assert.equal(publicDER.toString("hex"),publicPrefix.toString("hex")+plan.public_key_hex);
  const vectors=[];
  function add(id,domainVector,domain,messageHex,expectedSignature) {
    const signature=sign(null,strictHex(messageHex),secret);
    if(expectedSignature!==undefined) assert.equal(signature.toString("hex"),expectedSignature,"RFC8032 known answer mismatch");
    const original={id,domain_vector:domainVector,domain,message_hex:messageHex,public_key_hex:plan.public_key_hex,signature_hex:signature.toString("hex"),accept:true};
    assert.ok(accepts(original));vectors.push(original);
    for(const mutation of plan.negative_mutations) {
      const changed={...original,id:id+"_"+mutation,accept:false,mutation};
      if(mutation==="message_suffix") changed.message_hex+="00";
      else if(mutation==="wrong_key") changed.public_key_hex=plan.wrong_public_key_hex;
      else if(mutation==="short_key") changed.public_key_hex=changed.public_key_hex.slice(0,-2);
      else if(mutation==="long_key") changed.public_key_hex+="00";
      else if(mutation==="short_signature") changed.signature_hex=changed.signature_hex.slice(0,-2);
      else if(mutation==="long_signature") changed.signature_hex+="00";
      else if(mutation==="signature_bit") {const modified=Buffer.from(signature);modified[0]^=1;changed.signature_hex=modified.toString("hex");}
      else {
        const modified=Buffer.from(signature);
        let scalar=0n;for(let i=63;i>=32;i--)scalar=(scalar<<8n)+BigInt(modified[i]);
        scalar+=order;assert.ok(scalar<(1n<<256n));
        for(let i=32;i<64;i++){modified[i]=Number(scalar&255n);scalar>>=8n;}
        changed.signature_hex=modified.toString("hex");
      }
      assert.equal(accepts(changed),false,changed.id);
      vectors.push(changed);
    }
  }
  add(plan.known_answer.id,null,null,plan.known_answer.message_hex,plan.known_answer.signature_hex);
  const registered=new Set(schema.domains.filter(domain=>domain.operation==="ed25519").map(domain=>domain.name));
  for(const vector of domainCorpus.vectors) {
    if(!vector.expected_error && registered.has(vector.domain)) add("signature_"+vector.id,vector.id,vector.domain,vector.result.input_hex);
  }
  for(const domain of registered) assert.ok(vectors.some(vector=>vector.domain===domain && vector.accept),"uncovered signature domain "+domain);
  return {
    schema_revision:schema.schema_revision,design_sha256:schema.design_sha256,
    qualification:"actual_public_fixture_signatures_only",
    signing_seed_hex:plan.seed_hex,
    unverified:["Complete strict Pure Ed25519 acceptance, including A/R canonical point, nonidentity and prime-order subgroup predicates","Trusted issuer/delegation/certificate chains and embedded signer identity","Noise, KDF and AEAD composition","Independent cryptographic review","Runtime key ownership and provider/pairwise interoperability"],
    vectors
  };
}
