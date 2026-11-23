#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { digest, repositoryRoot } from "./transport-v4-files.mjs";
import { cborHead, encodeCBOR, encodeMap, decodeCBOR, decodeMap, mapFromNames, VectorError, strictHex } from "./transport-v4-codec.mjs";
import { evaluateDomain, verifyDomains } from "./transport-v4-domains.mjs";
import { buildTextCorpus } from "./transport-v4-text-vectors.mjs";
import { derivePoolSelection, verifyPoolSet } from "./transport-v4-pool.mjs";
import { composeTypedMetadata, verifyTypedMetadata } from "./transport-v4-metadata.mjs";
import { buildQueryCorpus } from "./transport-v4-contract-query-vectors.mjs";
import { buildFragmentCorpus, verifyFragmentCorpus } from "./transport-v4-fragments.mjs";
import { buildFragmentStateCorpus, verifyFragmentStateCorpus } from "./transport-v4-fragment-state-vectors.mjs";
import { buildStreamStateCorpus, verifyStreamStateCorpus } from "./transport-v4-stream-state-vectors.mjs";
import { buildApiCorpus } from "./transport-v4-api-results.mjs";
import { generateApiTypes } from "./transport-v4-api-types.mjs";
import { buildApplicationHeaderCorpus } from "./transport-v4-application-headers.mjs";
import { buildNotifyCorpus } from "./transport-v4-notify.mjs";
import { buildSignatureCorpus } from "./transport-v4-signatures.mjs";
import { buildStrictEd25519Corpus } from "./transport-v4-strict-ed25519.mjs";
import { buildDHCorpus } from "./transport-v4-dh.mjs";
import { buildNoiseCorpus } from "./transport-v4-noise.mjs";
import { buildRecordCorpus } from "./transport-v4-records.mjs";
import { buildReadyCorpus } from "./transport-v4-ready.mjs";
import { buildRekeyCorpus } from "./transport-v4-rekey.mjs";
import { buildResourceCompositionCorpus } from "./transport-v4-resource-vectors.mjs";
import { buildResourceCostCorpus } from "./transport-v4-resource-costs.mjs";
import { buildTimeArithmeticCorpus } from "./transport-v4-time.mjs";
import { buildCryptoUsageCorpus } from "./transport-v4-crypto-usage.mjs";
import { buildRekeyCreditCorpus } from "./transport-v4-rekey-credit.mjs";

export { digest, repositoryRoot };
const json = (value) => `${JSON.stringify(value, null, 2)}\n`;
const prefix = "testdata/transport_v4/";
const goNames = {NEGOTIATE:"Negotiate", ADMISSION:"Admission", ADMISSION_RESULT:"AdmissionResult", HANDSHAKE:"Handshake", READY:"Ready", REKEY:"Rekey", OPEN_STREAM:"OpenStream", STREAM_DATA:"StreamData", STREAM_ACK:"StreamAck", DATAGRAM:"Datagram", ERROR:"Error", CLOSE:"Close", GOAWAY:"GoAway", PING:"Ping", PONG:"Pong", HOP_AUTH:"HopAuth"};

function fixtureValue(schema, value, stack = []) {
  if (Array.isArray(value)) return value.map((item) => fixtureValue(schema, item, stack));
  if (!value || typeof value !== "object") return value;
  if (Object.hasOwn(value, "$repeat_bytes")) {
    const repeat = value.$repeat_bytes;
    if (Object.keys(value).length !== 1 || Object.keys(repeat).sort().join(",") !== "byte,count" || !/^[0-9a-f]{2}$/u.test(repeat.byte) || !Number.isInteger(repeat.count) || repeat.count < 0 || repeat.count > 1048577) throw new Error("invalid repeated-byte fixture");
    return {$bytes:repeat.byte.repeat(repeat.count)};
  }
  if (Object.hasOwn(value, "$fixture")) {
    const name = value.$fixture;
    if (Object.keys(value).length !== 1 || !Object.hasOwn(schema.vector_plan.fixtures ?? {}, name) || stack.includes(name)) throw new Error(`invalid fixture reference ${name}`);
    return fixtureValue(schema, schema.vector_plan.fixtures[name], [...stack, name]);
  }
  if (Object.hasOwn(value, "$encoded_map")) {
    const map=value.$encoded_map;
    if (Object.keys(value).length!==1 || !["schema,values","limits,schema,values"].includes(Object.keys(map).sort().join(","))) throw new Error("invalid encoded-map fixture");
    const bytes=encodeMap(schema,map.schema,mapFromNames(schema,map.schema,fixtureValue(schema,map.values,stack),map.limits),map.limits);
    decodeMap(schema,map.schema,bytes,map.limits);
    return {$bytes:bytes.toString("hex")};
  }
  if (Object.hasOwn(value, "$domain_output")) {
    const domain=value.$domain_output;
    if (Object.keys(value).length!==1 || !["inputs,name","context,inputs,name"].includes(Object.keys(domain).sort().join(","))) throw new Error("invalid domain-output fixture");
    const result=evaluateDomain(schema,domain.name,domainArguments(fixtureValue(schema,domain.inputs,stack)),domain.context);
    if (!result.output_hex) throw new Error("fixture domain has no primitive output");
    return {$bytes:result.output_hex};
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, fixtureValue(schema, item, stack)]));
}

function deriveOpenDigest(schema, map) {
  const field = Object.entries(schema.frame_maps.OPEN_STREAM.fields).find(([, v]) => v.name === "open_digest");
  const key = BigInt(field[0]);
  const domain = schema.domains.find((v) => v.name === "open_digest");
  const construction = new Map(map); construction.set(key,Buffer.alloc(field[1].length));
  const result = evaluateDomain(schema,"open_digest",{open:encodeCBOR(construction)});
  map.set(key,strictHex(result.output_hex));
  return {unsigned_cbor_hex:result.input_hex.slice(domain.label_bytes.length + 8), domain_hex:domain.label_bytes, digest_hex:result.output_hex};
}

export function malformed(schema, spec, seeds) {
  const seed = seeds.get(spec.source);
  if (!seed) throw new Error(`unknown vector source ${spec.source}`);
  let bytes = seed.bytes;
  if (spec.encoded_field) {
    if (spec.remove || spec.field || spec.replace || spec.mutation) throw new Error("ambiguous encoded-field mutation");
    const definition = schema.frame_maps[seed.plan.schema];
    const field = Object.entries(definition.fields).find(([,field]) => field.name === spec.encoded_field);
    if (!field) throw new Error("unknown encoded-field mutation target");
    const value = decodeMap(schema,seed.plan.schema,bytes,seed.plan.limits), key = BigInt(field[0]);
    if (!value.has(key)) throw new Error("encoded-field mutation target is absent");
    bytes = Buffer.concat([cborHead(5,value.size), ...[...value].map(([k,v]) => k === key
      ? Buffer.concat([encodeCBOR(k),strictHex(spec.value_hex)])
      : encodeMap(schema,seed.plan.schema,new Map([[k,v]]),seed.plan.limits).subarray(1))]);
  } else if (spec.remove) {
    if (!Array.isArray(spec.remove) || spec.remove.length === 0 || spec.field || spec.replace || spec.mutation) throw new Error("invalid field removal recipe");
    const value = decodeCBOR(bytes, {schema,name:seed.plan.schema,limits:seed.plan.limits});
    for (const name of spec.remove) {
      const field = Object.entries(schema.frame_maps[seed.plan.schema].fields).find(([,field]) => field.name === name);
      if (!field || !value.delete(BigInt(field[0]))) throw new Error(`unknown or repeated removed field ${name}`);
    }
    bytes = encodeMap(schema, seed.plan.schema, value,seed.plan.limits);
  } else if (spec.field || spec.replace) {
    const values = {...seed.plan.values, ...fixtureValue(schema, spec.replace)};
    if (spec.field) values[spec.field] = fixtureValue(schema, spec.value);
    const map = mapFromNames(schema, seed.plan.schema, values, seed.plan.limits);
    if (seed.plan.derive_open_digest && spec.field !== "open_digest" && !Object.hasOwn(spec.replace ?? {},"open_digest")) {
      const id = BigInt(Object.entries(schema.frame_maps.OPEN_STREAM.fields).find(([,v]) => v.name === "open_digest")[0]);
      map.set(id,decodeCBOR(seed.bytes).get(id));
    }
    if (seed.plan.derive_open_digest && spec.derive_open_digest !== false) {
      // A structural mutation must remain invalid; do not normalize it to get
      // a signing input. Its field error is checked before any digest check.
      try { decodeMap(schema,seed.plan.schema,encodeCBOR(map),seed.plan.limits); deriveOpenDigest(schema,map); }
      catch (err) { if (!(err instanceof VectorError)) throw err; }
    }
    bytes = encodeMap(schema, seed.plan.schema, map,seed.plan.limits);
  } else {
    const outer = decodeCBOR(bytes, {schema,name:seed.plan.schema,limits:seed.plan.limits});
    const nested = spec.map_field === undefined ? undefined : Object.entries(schema.frame_maps[seed.plan.schema].fields).find(([, field]) => field.name === spec.map_field);
    if (spec.map_field !== undefined && !nested) throw new Error("unknown nested mutation field");
    const value = nested ? outer.get(BigInt(nested[0])) : outer;
    if (!(value instanceof Map)) throw new Error("mutation target is not a map");
    const targetSchema = nested ? nested[1].schema_ref : seed.plan.schema;
    const encode = value => targetSchema ? encodeMap(schema,targetSchema,value,seed.plan.limits) : encodeCBOR(value);
    bytes = encode(value);
    const pairs = [...value].map(([k,v]) => encode(new Map([[k,v]])).subarray(1));
    const header = cborHead(5, value.size);
    const firstKey = encodeCBOR(value.keys().next().value);
    switch (spec.mutation) {
      case "drop_last_byte": bytes = bytes.subarray(0, -1); break;
      case "append_zero": bytes = Buffer.concat([bytes, Buffer.from([0])]); break;
      case "duplicate_first_pair": bytes = Buffer.concat([cborHead(5, pairs.length + 1), pairs[0], ...pairs]); break;
      case "duplicate_last_pair": bytes = Buffer.concat([cborHead(5, pairs.length + 1), ...pairs, pairs.at(-1)]); break;
      case "overlong_first_key": {
        const sizes = {1:2, 2:3, 3:5, 5:9}, n = value.keys().next().value;
        const length = sizes[firstKey.length];
        if (!length) throw new Error("no wider CBOR integer encoding");
        const wider = Buffer.alloc(length);
        wider[0] = ({2:24, 3:25, 5:26, 9:27})[length];
        if (length === 9) wider.writeBigUInt64BE(n, 1); else wider.writeUIntBE(Number(n), 1, length - 1);
        bytes = Buffer.concat([header, wider, bytes.subarray(header.length + firstKey.length)]); break;
      }
      case "text_first_key": bytes = Buffer.concat([header, encodeCBOR("0"), bytes.subarray(header.length + firstKey.length)]); break;
      case "add_unknown_field": value.set(65535n, 0n); bytes = encode(value); break;
      case "remove_first_field": value.delete(value.keys().next().value); bytes = encode(value); break;
      case "reverse_pairs": bytes = Buffer.concat([header, ...pairs.reverse()]); break;
      case "indefinite_map": bytes = Buffer.concat([Buffer.from([0xbf]), bytes.subarray(header.length), Buffer.from([0xff])]); break;
      case "false_instead_of_map": bytes = Buffer.from([0xf4]); break;
      case "null_instead_of_map": bytes = Buffer.from([0xf6]); break;
      default: throw new Error(`unknown mutation ${spec.mutation}`);
    }
    if (nested) bytes = Buffer.concat([cborHead(5, outer.size), ...[...outer].flatMap(([key, item]) => [encodeCBOR(key), key === BigInt(nested[0]) ? bytes : encodeCBOR(item)])]);
  }
  return {id:spec.id, kind:"malformed_cbor_fields", schema:seed.plan.schema, limits:seed.plan.limits, hex:bytes.toString("hex"), pool_derivation:seed.poolDerivation, expected_error:spec.error};
}

export function verifyCorpus(schema, corpus) {
  const typedPlans = new Map(schema.vector_plan.maps.filter(plan => plan.derive_typed_metadata).map(plan => [plan.id,plan.derive_typed_metadata]));
  for (const vector of corpus.vectors) {
    const typedPlan = typedPlans.get(vector.id);
    if (Boolean(typedPlan) !== Boolean(vector.typed_derivation)) throw new Error(`typed derivation presence drift: ${vector.id}`);
    if (typedPlan) {
      const definition = corpus.vectors.find(item => item.id === typedPlan.definition && item.schema === "MessageStreamDefinition" && !item.expected_error);
      const application = typedPlan.application === null ? {hex:""} : corpus.vectors.find(item => item.id === typedPlan.application && item.schema === "StreamMetadata" && !item.expected_error);
      if (!definition || !application || vector.typed_derivation.definition_hex !== definition.hex || vector.typed_derivation.application_hex !== application.hex || Object.keys(vector.typed_derivation).sort().join(",") !== "application_hex,definition_hex") throw new Error(`typed derivation source drift: ${vector.id}`);
    }
    const bytes = strictHex(vector.hex);
    let error;
    try {
      const value = vector.schema ? decodeMap(schema, vector.schema, bytes, vector.limits) : decodeCBOR(bytes);
      if (vector.decimal !== undefined && value !== BigInt(vector.decimal)) throw new Error(`integer differs: ${vector.id}`);
      if (!vector.expected_error && !(vector.schema ? encodeMap(schema,vector.schema,value,vector.limits) : encodeCBOR(value)).equals(bytes)) throw new Error(`noncanonical positive: ${vector.id}`);
      if (vector.pool_derivation) {
        if (vector.schema !== "PoolSelectionSet") throw new Error(`pool derivation schema differs: ${vector.id}`);
        verifyPoolSet(schema,strictHex(vector.pool_derivation.artifact_hex),vector.pool_derivation.indices,bytes);
      }
      if (vector.typed_derivation) {
        if (vector.schema !== "TypedMessageMetadata") throw new Error(`typed derivation schema differs: ${vector.id}`);
        const application = verifyTypedMetadata(schema,bytes,strictHex(vector.typed_derivation.definition_hex));
        if (application.toString("hex") !== vector.typed_derivation.application_hex) throw new Error(`typed application drift: ${vector.id}`);
      }
      if (vector.schema === "OPEN_STREAM") {
        const digestField = Object.entries(schema.frame_maps.OPEN_STREAM.fields).find(([,v]) => v.name === "open_digest");
        const suppliedDigest = value.get(BigInt(digestField[0]));
        const actual = deriveOpenDigest(schema, value);
        if (!suppliedDigest.equals(Buffer.from(actual.digest_hex, "hex"))) throw new VectorError("open_digest_mismatch");
        if (vector.derivation && JSON.stringify(actual) !== JSON.stringify(vector.derivation)) throw new Error(`digest differs: ${vector.id}`);
      }
    } catch (err) { error = err; }
    if (vector.expected_error) {
      if (!(error instanceof VectorError) || error.code !== vector.expected_error) throw new Error(`${vector.id}: expected ${vector.expected_error}, got ${error?.message ?? "accepted"}`);
    } else if (error) throw new Error(`${vector.id}: ${error.message}`);
  }
}

export function domainArguments(inputs) {
  return Object.fromEntries(Object.entries(inputs).map(([name,value]) => {
    if (value && typeof value === "object") {
      if (Object.keys(value).length === 1 && Object.hasOwn(value,"$bytes")) return [name,strictHex(value.$bytes)];
      if (Object.keys(value).length === 1 && typeof value.$uint === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value.$uint)) return [name,BigInt(value.$uint)];
      throw new Error(`invalid domain argument ${name}`);
    }
    return [name,value];
  }));
}

export function verifyDomainCorpus(schema, corpus) {
  const ids = new Set();
  for (const vector of corpus.vectors) {
    if (ids.has(vector.id)) throw new Error(`duplicate domain vector ${vector.id}`); ids.add(vector.id);
    let error, result;
    try { result = evaluateDomain(schema,vector.domain,domainArguments(vector.inputs),vector.context); }
    catch (err) { error = err; }
    if (vector.expected_error) {
      if (!(error instanceof VectorError) || error.code !== vector.expected_error) throw new Error(`${vector.id}: expected ${vector.expected_error}, got ${error?.message ?? "accepted"}`);
    } else {
      if (error) throw new Error(`${vector.id}: ${error.message}`);
      if (JSON.stringify(result) !== JSON.stringify(vector.result)) throw new Error(`domain vector drift: ${vector.id}`);
    }
  }
  for (const domain of schema.domains) if (!corpus.vectors.some((v) => v.domain === domain.name && !v.expected_error)) throw new Error(`uncovered domain ${domain.name}`);
}

export function verifyErrorCorpus(schema, corpus) {
  if (corpus.design_sha256 !== schema.design_sha256 || corpus.schema_revision !== schema.schema_revision) throw new Error("error corpus binding drift");
  const errorSchemas = new Set(["ERROR","CLOSE","GOAWAY","FSA4","OPEN_ACCEPT"]);
  const expected = new Map(schema.vector_plan.maps.filter(plan => errorSchemas.has(plan.schema)).map(plan => [plan.id,{schema:plan.schema}]));
  for (const group of schema.error_vector_plan) {
    const seed = expected.get(group.source);
    if (!seed) throw new Error(`invalid error vector source ${group.source}`);
    for (const name of Object.keys(schema[group.registry])) {
      if (!group.scope || schema[group.metadata][name].scope === group.scope) expected.set(`${group.id}_${name}`,seed);
    }
  }
  for (const plan of schema.vector_plan.malformed) {
    const seed = expected.get(plan.source);
    if (seed) expected.set(plan.id,{schema:seed.schema,expected_error:plan.error});
  }
  const ids = new Set();
  for (const vector of corpus.vectors) {
    if (ids.has(vector.id)) throw new Error(`duplicate error vector ${vector.id}`);
    ids.add(vector.id);
    const plan = expected.get(vector.id);
    if (!plan || vector.schema !== plan.schema || vector.expected_error !== plan.expected_error) throw new Error(`error vector plan drift ${vector.id}`);
  }
  if (ids.size !== expected.size) throw new Error("error vector coverage differs");
  verifyCorpus(schema, corpus);
  for (const group of schema.error_vector_plan) {
    for (const [name, code] of Object.entries(schema[group.registry])) {
      if (group.scope && schema[group.metadata][name].scope !== group.scope) continue;
      const vector = corpus.vectors.find(item => item.id === group.id + "_" + name && !item.expected_error);
      if (!vector) throw new Error(`uncovered error registry code ${group.registry}.${name}`);
      const field = Object.entries(schema.frame_maps[vector.schema].fields).find(([,item]) => item.name === group.field);
      if (!field || decodeCBOR(strictHex(vector.hex)).get(BigInt(field[0])) !== BigInt(code)) throw new Error(`error registry code drift ${vector.id}`);
    }
  }
}

function buildDomainCorpus(schema, cborCorpus) {
  const corpus = {schema_revision:schema.schema_revision, design_sha256:schema.design_sha256, schema_sha256:cborCorpus.schema_sha256, coverage:"draft_domain_inputs_and_primitives", unverified:["Ed25519 signatures and acceptance","Noise and DH completion","full handshake and rekey transactions","SDK interoperability","live TLS exporter providers"], vectors:[]};
  const resolve = (inputs) => Object.fromEntries(Object.entries(inputs).map(([name,value]) => {
    if (value?.$vector) {
      if (Object.keys(value).length !== 1) throw new Error("invalid domain vector reference");
      const vector = cborCorpus.vectors.find((item) => item.id === value.$vector);
      if (!vector) throw new Error(`missing CBOR vector ${value.$vector}`);
      return [name,{$bytes:vector.hex}];
    }
    return [name,value];
  }));
  for (const plan of schema.domain_vector_plan.positive) {
    const vector = {...plan,inputs:resolve(plan.inputs)};
    vector.result = evaluateDomain(schema,vector.domain,domainArguments(vector.inputs),vector.context);
    corpus.vectors.push(vector);
  }
  for (const plan of schema.domain_vector_plan.negative) {
    const original = corpus.vectors.find((v) => v.id === plan.source && !v.expected_error);
    if (!original) throw new Error(`missing positive domain seed ${plan.source}`);
    const vector = {...original,id:plan.id,inputs:{...original.inputs,...resolve(plan.replace ?? {})},expected_error:plan.error};
    for (const field of plan.remove ?? []) delete vector.inputs[field];
    delete vector.result;
    corpus.vectors.push(vector);
  }
  verifyDomainCorpus(schema,corpus);
  return corpus;
}

export function buildArtifacts(root = repositoryRoot) {
  const raw = fs.readFileSync(path.join(root, "stability/transport_v4_schema.json"));
  const schema = JSON.parse(raw), schemaSha = digest(raw), files = new Map(), seeds = new Map();
  for (const [key,expectedPath] of Object.entries({nfc_sources:"normalization_sources.json",nfc_data:"normalization_generated.json",idna_sources:"idna_sources.json",idna_data:"idna_generated.json"})) {
    const reference=schema.unicode[key];
    if (reference.path !== "testdata/unicode15_1/"+expectedPath) throw new Error("invalid Unicode reference path");
    if (digest(fs.readFileSync(path.join(root,reference.path))) !== reference.sha256) throw new Error(`Unicode input drift: ${reference.path}`);
  }
  verifyDomains(schema);
  // Runtime wire DNS validation uses the same pinned properties as the oracle.
  // Wire input is already ASCII: mapping targets are not an admission repair.
  const idnaData = JSON.parse(fs.readFileSync(path.join(root, schema.unicode.idna_data.path), "utf8"));
  const idnaWire = Object.fromEntries(["mapping", "classes", "categories", "bidi", "ccc", "joining", "scripts"].map(name => [name, idnaData[name].map(row => row.slice(0, 3))]));
  files.set("flowersec-go/internal/protocolv4/idna_properties_generated.go", `// Code generated by generate-transport-v4-vectors.mjs; DO NOT EDIT.\n\npackage protocolv4\n\nconst idnaWirePropertiesJSON = ${JSON.stringify(JSON.stringify(idnaWire))}\n`);
  const corpus = {schema_revision:schema.schema_revision, design_sha256:schema.design_sha256, schema_sha256:schemaSha, coverage:schema.vector_plan.coverage, unverified:schema.vector_plan.unverified, vectors:[]};
  for (const decimal of schema.vector_plan.unsigned_boundaries) corpus.vectors.push({id:`uint_${decimal}`, kind:"cbor_unsigned", decimal, hex:encodeCBOR(BigInt(decimal)).toString("hex")});
  for (const plan of schema.vector_plan.text) corpus.vectors.push({id:plan.id,kind:"cbor_text",hex:encodeCBOR(plan.value).toString("hex")});
  for (const plan of schema.vector_plan.raw_text) corpus.vectors.push({...plan,kind:"malformed_cbor_text"});
  for (const plan of schema.vector_plan.syntax) corpus.vectors.push({...plan,kind:"cbor_syntax"});
  for (const input of schema.vector_plan.maps) {
    const plan = {...input, values:fixtureValue(schema, input.values)};
    let poolDerivation, typedDerivation;
    if (plan.derive_bootstrap) {
      if (input.values !== undefined || plan.schema !== "OPEN_STREAM" || !plan.derive_open_digest) throw new Error(`invalid bootstrap prefix derivation: ${plan.id}`);
      const b = schema.stream_state_registry.bootstrap;
      plan.values = {stream_id:b.scope, direction:b.opener, scope:b.scope,
        epoch:plan.derive_bootstrap.epoch, sequence:schema.stream_state_registry.first_sequence,
        kind:b.kind, metadata:{$bytes:"00".repeat(b.metadata_bytes)},
        initial_receive_limit:b.initial_receive_limit, open_digest:{$bytes:""}};
    }
    if (plan.derive_typed_metadata) {
      if (input.values !== undefined || plan.schema !== "TypedMessageMetadata") throw new Error(`invalid typed metadata derivation: ${plan.id}`);
      const definition = seeds.get(plan.derive_typed_metadata.definition), application = plan.derive_typed_metadata.application === null ? Buffer.alloc(0) : seeds.get(plan.derive_typed_metadata.application)?.bytes;
      if (definition?.plan.schema !== "MessageStreamDefinition" || !application) throw new Error(`missing typed metadata inputs: ${plan.id}`);
      const bytes = composeTypedMetadata(schema,definition.bytes,application);
      typedDerivation = {definition_hex:definition.bytes.toString("hex"),application_hex:application.toString("hex")};
      const fields = Object.values(schema.frame_maps.TypedMessageMetadata.fields);
      plan.values = {namespace:fields.find(field => field.name === "namespace").const,version:fields.find(field => field.name === "version").const,values:{definition:{$bytes:evaluateDomain(schema,"typed_message_definition_digest",{definition:definition.bytes}).output_hex},application:{$bytes:application.toString("hex")}}};
      if (!encodeCBOR(mapFromNames(schema,plan.schema,plan.values)).equals(bytes)) throw new Error("typed metadata derivation drift");
    }
    if (plan.derive_pool_set) {
      if (input.values !== undefined || plan.schema !== "PoolSelectionSet") throw new Error(`invalid derived pool map: ${plan.id}`);
      const artifact = seeds.get(plan.derive_pool_set.artifact);
      if (!artifact || artifact.plan.schema !== "Artifact") throw new Error(`missing pool Artifact: ${plan.id}`);
      plan.values = derivePoolSelection(schema,artifact.bytes,plan.derive_pool_set.indices).values;
      poolDerivation = {artifact_hex:artifact.bytes.toString("hex"),indices:plan.derive_pool_set.indices};
    }
    const value = mapFromNames(schema, plan.schema, plan.values, plan.limits);
    const derivation = plan.derive_open_digest ? deriveOpenDigest(schema, value) : undefined;
    const bytes = encodeMap(schema,plan.schema,value,plan.limits);
    if (plan.expected_encoded_bytes !== undefined && bytes.length !== plan.expected_encoded_bytes) throw new Error(`encoded size differs: ${plan.id}`);
    corpus.vectors.push({id:plan.id, kind:"cbor_fields", schema:plan.schema, limits:plan.limits, hex:bytes.toString("hex"), derivation, pool_derivation:poolDerivation, typed_derivation:typedDerivation});
    seeds.set(plan.id, {bytes, plan, poolDerivation});
  }
  // Registry cases reuse a schema-owned positive seed and named replacements.
  // The generator never allocates codes or hard-codes field IDs.
  for (const group of schema.error_vector_plan) {
    const seed = seeds.get(group.source);
    if (!seed) throw new Error(`unknown error seed ${group.source}`);
    const registry = schema[group.registry];
    if (!registry || !Object.values(schema.frame_maps[seed.plan.schema].fields).some(field => field.name === group.field)) throw new Error("invalid error vector registry/field");
    for (const [name,code] of Object.entries(registry)) {
      if (group.scope && schema[group.metadata]?.[name]?.scope !== group.scope) continue;
      const id = group.id + "_" + name;
      if (seeds.has(id)) throw new Error(`duplicate error seed ${id}`);
      const plan = {...seed.plan,id,values:{...seed.plan.values,...fixtureValue(schema,group.replace ?? {}),[group.field]:code}};
      const bytes = encodeCBOR(mapFromNames(schema,plan.schema,plan.values,plan.limits));
      corpus.vectors.push({id,kind:"cbor_fields",schema:plan.schema,limits:plan.limits,hex:bytes.toString("hex")});
      seeds.set(id,{bytes,plan});
    }
  }
  for (const spec of schema.vector_plan.malformed) corpus.vectors.push(malformed(schema, spec, seeds));
  verifyCorpus(schema, corpus);
  files.set(`${prefix}corpus.json`, json(corpus));
  const domainCorpus = buildDomainCorpus(schema,corpus);
  files.set(`${prefix}domains.json`,json(domainCorpus));
  const signatureCorpus=buildSignatureCorpus(schema,domainCorpus);
  signatureCorpus.schema_sha256=schemaSha;
  files.set(`${prefix}signatures.json`,json(signatureCorpus));
  const strictSignatureCorpus = buildStrictEd25519Corpus(schema,signatureCorpus);
  strictSignatureCorpus.schema_sha256 = schemaSha;
  files.set(`${prefix}strict_signatures.json`,json(strictSignatureCorpus));
  const dhCorpus = buildDHCorpus(schema);
  dhCorpus.schema_sha256 = schemaSha;
  files.set(`${prefix}profile_dh.json`,json(dhCorpus));
  const noiseCorpus = buildNoiseCorpus(schema);
  noiseCorpus.schema_sha256 = schemaSha;
  files.set(`${prefix}noise.json`,json(noiseCorpus));
  const recordCorpus = buildRecordCorpus(schema);
  recordCorpus.schema_sha256 = schemaSha;
  files.set(`${prefix}records.json`, json(recordCorpus));
  const readyCorpus = buildReadyCorpus(schema);
  readyCorpus.schema_sha256 = schemaSha;
  files.set(`${prefix}ready.json`, json(readyCorpus));
  const rekeyCorpus = buildRekeyCorpus(schema);
  rekeyCorpus.schema_sha256 = schemaSha;
  files.set(`${prefix}rekey.json`, json(rekeyCorpus));
  const textCorpus=buildTextCorpus(schema,schemaSha);
  files.set(`${prefix}text.json`,json(textCorpus));
  const errorSchemas = new Set(["ERROR","CLOSE","GOAWAY","FSA4","OPEN_ACCEPT"]);
  const errorVectors = corpus.vectors.filter(vector => errorSchemas.has(vector.schema));
  const errorsCorpus = {
    schema_revision:schema.schema_revision, design_sha256:schema.design_sha256,
    schema_sha256:schemaSha, coverage:"draft_error_cbor_fields",
    unverified:["Authentication and trusted owner attribution","Ledger/commit/retry projections","Provider termination and SDK interoperability"],
    vectors:errorVectors
  };
  verifyErrorCorpus(schema, errorsCorpus);
  files.set(`${prefix}errors.json`,json(errorsCorpus));
  const queryCorpus=buildQueryCorpus(schema,corpus);
  files.set(`${prefix}queries.json`,json(queryCorpus));
  const fragmentCorpus = buildFragmentCorpus(schema.fragment_registry);
  fragmentCorpus.schema_revision = schema.schema_revision;
  fragmentCorpus.design_sha256 = schema.design_sha256;
  fragmentCorpus.schema_sha256 = schemaSha;
  verifyFragmentCorpus(schema.fragment_registry, fragmentCorpus);
  files.set(`${prefix}fragments.json`, json(fragmentCorpus));
  const fragmentStateCorpus = buildFragmentStateCorpus(schema);
  verifyFragmentStateCorpus(schema,fragmentStateCorpus);
  files.set(`${prefix}fragment_states.json`,json(fragmentStateCorpus));
  const streamStateCorpus = buildStreamStateCorpus(schema);
  verifyStreamStateCorpus(schema, streamStateCorpus);
  files.set(`${prefix}stream_states.json`,json(streamStateCorpus));
  const apiCorpus = buildApiCorpus(schema);
  files.set(`${prefix}api_results.json`, json(apiCorpus));
  const resourceCorpus = buildResourceCompositionCorpus(schema);
  files.set(`${prefix}resources.json`, json(resourceCorpus));
  const resourceCostCorpus = buildResourceCostCorpus(schema);
  files.set(`${prefix}resource_costs.json`, json(resourceCostCorpus));
  const timeCorpus = buildTimeArithmeticCorpus(schema);
  files.set(`${prefix}time_arithmetic.json`, json(timeCorpus));
  const cryptoUsageCorpus = buildCryptoUsageCorpus(schema);
  files.set(`${prefix}crypto_usage.json`, json(cryptoUsageCorpus));
  const rekeyCreditCorpus = buildRekeyCreditCorpus(schema);
  files.set(`${prefix}rekey_credit.json`, json(rekeyCreditCorpus));
  const rekeyCreditRegistry = { ...schema.rekey_credit_registry, envelope_fields: schema.frame_maps.RekeyEnvelope.fields };
  const applicationCorpus = buildApplicationHeaderCorpus(schema);
  files.set(`${prefix}application_headers.json`, json(applicationCorpus));
  const notifyCorpus = buildNotifyCorpus(schema);
  notifyCorpus.schema_sha256 = schemaSha;
  files.set(`${prefix}notify.json`, json(notifyCorpus));
  for (const [file, content] of generateApiTypes(schema, schemaSha)) files.set(file, content);
  const entries = Object.entries(schema.frame_types);
  const errorRegistryJSON = JSON.stringify({error_codes:schema.error_codes,error_code_metadata:schema.error_code_metadata,admission_rejection_codes:schema.admission_rejection_codes,admission_rejection_metadata:schema.admission_rejection_metadata,open_rejection_codes:schema.open_rejection_codes,open_rejection_metadata:schema.open_rejection_metadata,top_up_wire_result:schema.top_up_wire_result,error_registry_boundary:schema.error_registry_boundary,frame_maps:Object.fromEntries([...errorSchemas].map(name=>[name,schema.frame_maps[name]])),map_rules:Object.fromEntries([...errorSchemas].map(name=>[name,schema.map_rules[name] ?? []]))});
  // One declaration per line keeps the output gofmt-stable without a toolchain dependency.
  const go = `// Code generated by scripts/generate-transport-v4-vectors.mjs; DO NOT EDIT.\npackage protocolv4\n\nconst SchemaSHA256 = ${JSON.stringify(schemaSha)}\nconst EnvelopePrefixSize = ${schema.envelope.prefix_bytes}\nconst MaxPayloadLength = ${schema.envelope.layout[0].max}\n${entries.map(([name,n]) => `const Frame${goNames[name]} FrameType = ${n}`).join("\n")}\n`;
  files.set("flowersec-go/internal/protocolv4/registry_generated.go", go);
  files.set("flowersec-rust/src/protocol_v4_registry_generated.rs", `// Generated draft registry; not a qualified runtime.\npub(crate) const SCHEMA_SHA256: &str =\n    ${JSON.stringify(schemaSha)};\n${entries.map(([name,n])=>`pub(crate) const FRAME_${name}: u8 = ${n};`).join("\n")}\n`);
  files.set("flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift", `// Generated draft registry; not a qualified runtime.\nenum TransportV4Registry {\n    static let schemaSHA256 = ${JSON.stringify(schemaSha)}\n${entries.map(([name,n])=>`    static let frame${goNames[name]}: UInt8 = ${n}`).join("\n")}\n}\n`);
  files.set("flowersec-ts/src/generated/transportV4Registry.ts", `// Generated draft registry; not a qualified runtime.\nexport const transportV4Registry = {\n  schemaSHA256: ${JSON.stringify(schemaSha)},\n  frameTypes: ${JSON.stringify(schema.frame_types)},\n} as const;\n`);
  // Each SDK receives the same complete input definitions from the authority.
  // Runtime codec/crypto consumption remains a separate qualification gate.
  const domainsJSON = JSON.stringify(schema.domains);
  const resourceFormulaJSON = JSON.stringify({ ...schema.resource_formula_registry,
    max_frame_bytes: schema.resource_caps.max_payload_length,
    common_scope_ordinals: schema.stream_state_registry.client_ordinals,
    rpc_general_limit: Object.values(schema.frame_maps.SessionContract.fields).find(field => field.name === "rpc_max_general_outstanding"),
  });
  const management = {...schema.management_registry, methods:Object.fromEntries(Object.entries(schema.management_registry.methods).map(([name,method]) => {
    const contract = encodeMap(schema,"ServiceContract",mapFromNames(schema,"ServiceContract",fixtureValue(schema,{$fixture:method.contract_fixture})));
    const result = evaluateDomain(schema,"service_contract_digest",{contract});
    return [name,{...method,contract_hex:contract.toString("hex"),contract_digest_hex:result.output_hex}];
  }))};
  const applicationJSON = JSON.stringify({header:schema.frame_maps.ApplicationHeader,kinds:schema.application_message_kinds,policy:schema.application_headers,management,notify:schema.notify_registry,sdk_errors:schema.application_sdk_errors,sdk_error_codes:schema.application_sdk_error_codes,sdk_error_payload:schema.frame_maps[schema.application_sdk_errors.payload_schema]});
  const trustNames = ["NamespaceCapacity","HeadSignerDelegation","FreshnessHead","PublicationPolicy","CredentialRevocationPolicy","RevokedCertificateEntry","RevokedLeaseEntry","IssuerAuthorizationImpact","RevokedIssuerEntry","CohortPolicySegment","RevocationState"];
  const trustJSON = JSON.stringify({maps:Object.fromEntries(trustNames.map(name=>[name,schema.frame_maps[name]])),rules:Object.fromEntries(trustNames.map(name=>[name,schema.map_rules[name] ?? []])),validation_parameters:Object.fromEntries(Object.entries(schema.validation_parameters).filter(([,parameter])=>parameter.capacity_field!==undefined))});
  const fieldRegistryNames = new Set(["text_patterns","crypto_profiles","profile_revision"]);
  function collectFieldRegistries(value) {
    if (!value || typeof value !== "object") return;
    for (const [key,item] of Object.entries(value)) {
      if (["enum_ref","text_enum_ref","const_ref"].includes(key)) fieldRegistryNames.add(item);
      else if (key === "registry") fieldRegistryNames.add(item);
      else if (key === "registered") for (const name of Object.values(item)) fieldRegistryNames.add(name);
      else collectFieldRegistries(item);
    }
  }
  collectFieldRegistries(schema.frame_maps);
  const variantRules = Object.fromEntries(Object.entries(schema.map_rules).map(([name,rules])=>[name,rules.filter(rule=>["variant","context_variant","range"].includes(rule.op))]).filter(([,rules])=>rules.length));
  collectFieldRegistries(variantRules);
  const relationOps = new Set(["is_null","at_least_one","equal","equal_if_present","not_equal","less_than","less_or_equal","max_difference","allowed_pairs","allowed_tuples","bit_subset","feature_bit","profile_algorithm","error_scope","unique_by","ordinal_indices","increasing","increasing_tuple","increasing_bytes","increasing_cbor","increasing_scopes","exclusive_item","registry_tuple","map_digest"]);
  const relationRules = Object.fromEntries(Object.entries(schema.map_rules).map(([name,rules])=>[name,rules.filter(rule=>relationOps.has(rule.op))]).filter(([,rules])=>rules.length));
  collectFieldRegistries(relationRules);
  const textRules = Object.fromEntries(Object.entries(schema.map_rules).map(([name,rules])=>[name,rules.filter(rule=>["text_format","origin_endpoint"].includes(rule.op))]).filter(([,rules])=>rules.length));
  fieldRegistryNames.add("origin_schemes");
  for (const rules of Object.values(relationRules)) for (const rule of rules) {
    if (rule.op === "feature_bit") fieldRegistryNames.add("feature_registry");
    if (rule.op === "increasing_scopes") fieldRegistryNames.add("resource_caps");
    if (rule.op === "error_scope") for (const name of ["error_codes","error_code_metadata"]) fieldRegistryNames.add(name);
  }
  const fieldRegistries = Object.fromEntries([...fieldRegistryNames].sort().map(name=>[name,schema[name]]));
  const cborRegistryJSON = JSON.stringify({encoding:schema.encoding,frame_maps:schema.frame_maps,map_projections:schema.map_projections,unicode:schema.unicode,field_registries:fieldRegistries,variant_rules:variantRules,relation_rules:relationRules,text_rules:textRules});
  const declarations = [
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst RekeyCreditRegistryJSON = ${JSON.stringify(JSON.stringify(rekeyCreditRegistry))}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const REKEY_CREDIT_REGISTRY_JSON: &str = ${JSON.stringify(JSON.stringify(rekeyCreditRegistry))};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let rekeyCreditRegistryJSON = ${JSON.stringify(JSON.stringify(rekeyCreditRegistry))}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4RekeyCreditRegistry = ${JSON.stringify(rekeyCreditRegistry)} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst CryptoUsageRegistryJSON = ${JSON.stringify(JSON.stringify(schema.crypto_usage_registry))}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const CRYPTO_USAGE_REGISTRY_JSON: &str = ${JSON.stringify(JSON.stringify(schema.crypto_usage_registry))};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let cryptoUsageRegistryJSON = ${JSON.stringify(JSON.stringify(schema.crypto_usage_registry))}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4CryptoUsageRegistry = ${JSON.stringify(schema.crypto_usage_registry)} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst TimeArithmeticRegistryJSON = ${JSON.stringify(JSON.stringify(schema.time_arithmetic_registry))}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const TIME_ARITHMETIC_REGISTRY_JSON: &str = ${JSON.stringify(JSON.stringify(schema.time_arithmetic_registry))};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let timeArithmeticRegistryJSON = ${JSON.stringify(JSON.stringify(schema.time_arithmetic_registry))}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4TimeArithmeticRegistry = ${JSON.stringify(schema.time_arithmetic_registry)} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst ResourceCompositionRegistryJSON = ${JSON.stringify(JSON.stringify(schema.resource_composition_registry))}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const RESOURCE_COMPOSITION_REGISTRY_JSON: &str = ${JSON.stringify(JSON.stringify(schema.resource_composition_registry))};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let resourceCompositionRegistryJSON = ${JSON.stringify(JSON.stringify(schema.resource_composition_registry))}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4ResourceCompositionRegistry = ${JSON.stringify(schema.resource_composition_registry)} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst ResourceFormulaRegistryJSON = ${JSON.stringify(resourceFormulaJSON)}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const RESOURCE_FORMULA_REGISTRY_JSON: &str = ${JSON.stringify(resourceFormulaJSON)};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let resourceFormulaRegistryJSON = ${JSON.stringify(resourceFormulaJSON)}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4ResourceFormulaRegistry = ${resourceFormulaJSON} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst CBORSyntaxRegistryJSON = ${JSON.stringify(cborRegistryJSON)}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const CBOR_REGISTRY_JSON: &str = ${JSON.stringify(cborRegistryJSON)};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let cborRegistryJSON = ${JSON.stringify(cborRegistryJSON)}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4CBORRegistryJSON = ${JSON.stringify(cborRegistryJSON)};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let strictEd25519PublicKeyBytes = ${schema.strict_ed25519_policy.public_key_bytes}\n    static let strictEd25519SignatureBytes = ${schema.strict_ed25519_policy.signature_bytes}\n    static let strictEd25519PointBytes = ${schema.strict_ed25519_policy.point_bytes}\n    static let strictEd25519SigningFailure = ${JSON.stringify(schema.strict_ed25519_policy.signing_failure)}\n}\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst StrictEd25519PublicKeyBytes = ${schema.strict_ed25519_policy.public_key_bytes}\nconst StrictEd25519SignatureBytes = ${schema.strict_ed25519_policy.signature_bytes}\nconst StrictEd25519PointBytes = ${schema.strict_ed25519_policy.point_bytes}\nconst StrictEd25519SigningFailure = ${JSON.stringify(schema.strict_ed25519_policy.signing_failure)}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const STRICT_ED25519_PUBLIC_KEY_BYTES: usize = ${schema.strict_ed25519_policy.public_key_bytes};\npub(crate) const STRICT_ED25519_SIGNATURE_BYTES: usize = ${schema.strict_ed25519_policy.signature_bytes};\npub(crate) const STRICT_ED25519_POINT_BYTES: usize = ${schema.strict_ed25519_policy.point_bytes};\npub(crate) const STRICT_ED25519_SIGNING_FAILURE: &str = ${JSON.stringify(schema.strict_ed25519_policy.signing_failure)};\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst StrictEd25519PolicyJSON = ${JSON.stringify(JSON.stringify(schema.strict_ed25519_policy))}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const STRICT_ED25519_POLICY_JSON: &str = ${JSON.stringify(JSON.stringify(schema.strict_ed25519_policy))};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let strictEd25519PolicyJSON = ${JSON.stringify(JSON.stringify(schema.strict_ed25519_policy))}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4StrictEd25519Policy = ${JSON.stringify(schema.strict_ed25519_policy)} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst RevocationRegistryJSON = ${JSON.stringify(trustJSON)}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const REVOCATION_REGISTRY_JSON: &str = ${JSON.stringify(trustJSON)};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let revocationRegistryJSON = ${JSON.stringify(trustJSON)}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4RevocationRegistry = ${trustJSON} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst ApplicationHeaderRegistryJSON = ${JSON.stringify(applicationJSON)}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const APPLICATION_HEADER_REGISTRY_JSON: &str = ${JSON.stringify(applicationJSON)};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let applicationHeaderRegistryJSON = ${JSON.stringify(applicationJSON)}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4ApplicationHeaders = ${applicationJSON} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst DomainRegistryJSON = ${JSON.stringify(domainsJSON)}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const DOMAIN_REGISTRY_JSON: &str = ${JSON.stringify(domainsJSON)};\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const CRYPTO_PROFILES_JSON: &str = ${JSON.stringify(JSON.stringify(schema.crypto_profiles))};\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst CryptoProfilesJSON = ${JSON.stringify(JSON.stringify(schema.crypto_profiles))}\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let domainRegistryJSON = ${JSON.stringify(domainsJSON)}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4Domains = ${domainsJSON} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst FragmentRegistryJSON = ${JSON.stringify(JSON.stringify(schema.fragment_registry))}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const FRAGMENT_REGISTRY_JSON: &str = ${JSON.stringify(JSON.stringify(schema.fragment_registry))};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let fragmentRegistryJSON = ${JSON.stringify(JSON.stringify(schema.fragment_registry))}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4FragmentRegistry = ${JSON.stringify(schema.fragment_registry)} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst FragmentStateRegistryJSON = ${JSON.stringify(JSON.stringify(schema.fragment_state_registry))}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const FRAGMENT_STATE_REGISTRY_JSON: &str = ${JSON.stringify(JSON.stringify(schema.fragment_state_registry))};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let fragmentStateRegistryJSON = ${JSON.stringify(JSON.stringify(schema.fragment_state_registry))}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4FragmentStateRegistry = ${JSON.stringify(schema.fragment_state_registry)} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst StreamStateRegistryJSON = ${JSON.stringify(JSON.stringify(schema.stream_state_registry))}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const STREAM_STATE_REGISTRY_JSON: &str = ${JSON.stringify(JSON.stringify(schema.stream_state_registry))};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let streamStateRegistryJSON = ${JSON.stringify(JSON.stringify(schema.stream_state_registry))}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4StreamStateRegistry = ${JSON.stringify(schema.stream_state_registry)} as const;\n`],
    ["flowersec-go/internal/protocolv4/registry_generated.go",`\nconst ErrorCodeRegistryJSON = ${JSON.stringify(errorRegistryJSON)}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",`\npub(crate) const ERROR_CODE_REGISTRY_JSON: &str = ${JSON.stringify(errorRegistryJSON)};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",`\nextension TransportV4Registry {\n    static let errorCodeRegistryJSON = ${JSON.stringify(errorRegistryJSON)}\n}\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts",`\nexport const transportV4ErrorCodes = ${errorRegistryJSON} as const;\n`],
  ];
  const dh = schema.profile_dh_policy;
  const rekeyJSON = JSON.stringify(Object.fromEntries(["REKEY_INIT", "REKEY_REPLY", "REKEY_COMMIT", "REKEY_ACK", "RekeyBarrierEntry"].map(name => [name, schema.frame_maps[name]])));
  declarations.push(
    ["flowersec-go/internal/protocolv4/registry_generated.go", `\nconst RekeyRegistryJSON = ${JSON.stringify(rekeyJSON)}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs", `\npub(crate) const REKEY_REGISTRY_JSON: &str = ${JSON.stringify(rekeyJSON)};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift", `\nextension TransportV4Registry { static let rekeyRegistryJSON = ${JSON.stringify(rekeyJSON)} }\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts", `\nexport const transportV4RekeyRegistry = ${rekeyJSON} as const;\n`],
  );
  const readyJSON = JSON.stringify(Object.fromEntries(["ReadyProofInput", "ReadyMACInput", "READY"].map(name => [name, schema.frame_maps[name]])));
  declarations.push(
    ["flowersec-go/internal/protocolv4/registry_generated.go", `\nconst ReadyRegistryJSON = ${JSON.stringify(readyJSON)}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs", `\npub(crate) const READY_REGISTRY_JSON: &str = ${JSON.stringify(readyJSON)};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift", `\nextension TransportV4Registry { static let readyRegistryJSON = ${JSON.stringify(readyJSON)} }\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts", `\nexport const transportV4ReadyRegistry = ${readyJSON} as const;\n`],
  );
  const recordJSON = JSON.stringify({ envelope: schema.envelope, header: schema.record_header, nonce: schema.record_nonce, profiles: schema.crypto_profiles,
    frame_types: schema.frame_types, frame_classes: schema.frame_classes, resource_caps: schema.resource_caps });
  declarations.push(
    ["flowersec-go/internal/protocolv4/registry_generated.go", `\nconst RecordRegistryJSON = ${JSON.stringify(recordJSON)}\n`],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs", `\npub(crate) const RECORD_REGISTRY_JSON: &str = ${JSON.stringify(recordJSON)};\n`],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift", `\nextension TransportV4Registry { static let recordRegistryJSON = ${JSON.stringify(recordJSON)} }\n`],
    ["flowersec-ts/src/generated/transportV4Registry.ts", `\nexport const transportV4RecordRegistry = ${recordJSON} as const;\n`],
  );
  const dhConstants = {
    PrivateBytes: dh.private_bytes, SecretBytes: dh.secret_bytes, Failure: dh.failure,
    X25519PublicBytes: dh.x25519.public_bytes, P256PublicBytes: dh.p256.public_bytes,
    ProfileX25519: Object.keys(schema.crypto_profiles).find(name => schema.crypto_profiles[name].dh_algorithm === dh.x25519.algorithm),
    ProfileP256: Object.keys(schema.crypto_profiles).find(name => schema.crypto_profiles[name].dh_algorithm === dh.p256.algorithm),
    PolicyJSON: JSON.stringify(dh),
  };
  for (const [name, value] of Object.entries(dhConstants)) {
    const literal = JSON.stringify(value), rustName = name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toUpperCase();
    declarations.push(
      ["flowersec-go/internal/protocolv4/registry_generated.go", `\nconst DH${name} = ${literal}\n`],
      ["flowersec-rust/src/protocol_v4_registry_generated.rs", `\npub(crate) const DH_${rustName}: ${typeof value === "number" ? "usize" : "&str"} = ${literal};\n`],
      ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift", `\nextension TransportV4Registry { static let dh${name} = ${literal} }\n`],
    );
  }
  declarations.push(["flowersec-ts/src/generated/transportV4Registry.ts", `\nexport const transportV4DH = ${JSON.stringify(dhConstants)} as const;\n`]);
  for (const [file, declaration] of declarations) files.set(file,files.get(file) + declaration);
  const manifest = {status:"draft", design_sha256:schema.design_sha256, schema_revision:schema.schema_revision, schema_sha256:schemaSha, coverage:schema.vector_plan.coverage, vectors:corpus.vectors.map((v)=>({id:v.id, kind:v.kind, sha256:digest(Buffer.from(v.hex,"hex")), bytes:v.hex.length/2, expected_error:v.expected_error})), domain_vectors:domainCorpus.vectors.map((v)=>({id:v.id,domain:v.domain,sha256:digest(json(v)),expected_error:v.expected_error})), text_vectors:textCorpus.vectors.map((v)=>({id:v.id,operation:v.operation,sha256:digest(json(v)),expected_error:v.expected_error})), error_vectors:errorVectors.map((v)=>({id:v.id,schema:v.schema,sha256:digest(Buffer.from(v.hex,"hex")),bytes:v.hex.length/2,expected_error:v.expected_error})), files:[...files].map(([file,content])=>({file, sha256:digest(content)}))};
  manifest.query_vectors=queryCorpus.vectors.map(v=>({id:v.id,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.fragment_vectors=fragmentCorpus.vectors.map(v=>({id:v.id,sha256:digest(Buffer.from(v.hex,"hex")),bytes:v.hex.length/2,expected_error:v.expected_error}));
  manifest.fragment_state_vectors=fragmentStateCorpus.vectors.map(v=>({id:v.id,sha256:digest(json(v))}));
  manifest.stream_state_vectors=streamStateCorpus.vectors.map(v=>({id:v.id,sha256:digest(json(v))}));
  manifest.api_vectors=apiCorpus.vectors.map(v=>({id:v.id,type:v.type,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.resource_vectors=resourceCorpus.vectors.map(v=>({id:v.id,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.resource_cost_vectors=resourceCostCorpus.vectors.map(v=>({id:v.id,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.time_arithmetic_vectors=timeCorpus.vectors.map(v=>({id:v.id,operation:v.operation,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.crypto_usage_vectors=cryptoUsageCorpus.vectors.map(v=>({id:v.id,profile:v.profile,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.rekey_credit_vectors=rekeyCreditCorpus.vectors.map(v=>({id:v.id,profile:v.profile,operation:v.operation,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.application_header_vectors=applicationCorpus.vectors.map(v=>({id:v.id,kind:v.kind,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.notify_vectors=notifyCorpus.vectors.map(v=>({id:v.id,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.signature_vectors=signatureCorpus.vectors.map(v=>({id:v.id,domain:v.domain,sha256:digest(json(v)),accept:v.accept}));
  manifest.strict_signature_vectors=strictSignatureCorpus.vectors.map(v=>({id:v.id,domain:v.domain,sha256:digest(json(v)),accept:v.accept}));
  manifest.dh_vectors = [...dhCorpus.vectors, ...dhCorpus.keys].map(v => ({id:v.id,sha256:digest(json(v)),accept:v.accept}));
  manifest.noise_vectors = [...noiseCorpus.transcripts, ...noiseCorpus.negatives].map(v => ({id:v.id,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.record_vectors = [...recordCorpus.vectors, ...recordCorpus.negatives].map(v => ({id:v.id,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.ready_vectors = [...readyCorpus.vectors, ...readyCorpus.negatives].map(v => ({id:v.id,sha256:digest(json(v)),expected_error:v.expected_error}));
  manifest.rekey_vectors = [...rekeyCorpus.rounds, ...rekeyCorpus.negatives].map(v => ({id:v.id,sha256:digest(json(v)),expected_error:v.expected_error}));
  files.set(`${prefix}manifest.json`, json(manifest));
  return {files, schema, manifest};
}

export function checkArtifacts(root = repositoryRoot) {
  const {files, schema, manifest} = buildArtifacts(root);
  for (const [file, expected] of files) {
    const actualPath = path.join(root, file);
    if (!fs.existsSync(actualPath) || fs.readFileSync(actualPath, "utf8") !== expected) throw new Error(`generated artifact drift: ${file}`);
  }
  const allowed = new Set(["README.md", ...[...files.keys()].filter((p)=>p.startsWith(prefix)).map((p)=>p.slice(prefix.length))]);
  for (const name of fs.readdirSync(path.join(root, prefix))) if (!allowed.has(name)) throw new Error(`unexpected vector artifact: ${name}`);
  return {schema, manifest};
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length > 3 || (process.argv[2] && process.argv[2] !== "--check")) throw new Error("usage: generate-transport-v4-vectors.mjs [--check]");
  if (process.argv[2] === "--check") {
    const {manifest} = checkArtifacts();
    console.log(`Verified ${manifest.vectors.length} draft CBOR vectors and all generated files (read-only).`);
  } else {
    const {files, manifest} = buildArtifacts();
    for (const [file, content] of files) { const dest = path.join(repositoryRoot, file); fs.mkdirSync(path.dirname(dest), {recursive:true}); fs.writeFileSync(dest, content); }
    console.log(`Generated ${manifest.vectors.length} draft CBOR vectors; schema is not frozen.`);
  }
}
