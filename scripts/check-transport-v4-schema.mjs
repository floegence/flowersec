#!/usr/bin/env node
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkArtifacts } from "./generate-transport-v4-vectors.mjs";
import { verifyDomains } from "./transport-v4-domains.mjs";
import { textFormats } from "./transport-v4-codec.mjs";
import { verifyFragmentRegistry } from "./transport-v4-fragments.mjs";
import { verifyFragmentStateRegistry } from "./transport-v4-fragment-state.mjs";
import { verifyStreamStateRegistry } from "./transport-v4-stream-state.mjs";
import { verifyApiSchema } from "./transport-v4-api-results.mjs";
import { verifyApplicationHeaderSchema } from "./transport-v4-application-headers.mjs";
import { verifySignaturePlan } from "./transport-v4-signatures.mjs";
import { verifyStrictEd25519Plan } from "./transport-v4-strict-ed25519.mjs";
import { verifyDHPolicy } from "./transport-v4-dh.mjs";
import { verifyNoisePlan } from "./transport-v4-noise.mjs";
import { verifyRecordPlan } from "./transport-v4-records.mjs";
import { verifyReadyPlan } from "./transport-v4-ready.mjs";
import { verifyRekeyPlan } from "./transport-v4-rekey.mjs";
import { verifyResourceCompositionRegistry } from "./transport-v4-resources.mjs";
import { verifyResourceFormulaRegistry } from "./transport-v4-resource-costs.mjs";
import { verifyTimeArithmeticRegistry } from "./transport-v4-time.mjs";
import { verifyCryptoUsageRegistry } from "./transport-v4-crypto-usage.mjs";
import { verifyRekeyCreditRegistry } from "./transport-v4-rekey-credit.mjs";

export function verifySchema(schema) {
  verifyRekeyCreditRegistry(schema);
  verifyCryptoUsageRegistry(schema);
  verifyTimeArithmeticRegistry(schema);
  verifyResourceCompositionRegistry(schema.resource_composition_registry);
  verifyResourceFormulaRegistry(schema);
  assert.equal(schema.encoding.max_depth,8);
  assert.equal(schema.encoding.max_map_entries,128);
  assert.equal(schema.encoding.ordinary_array_items,1035);
  assert.equal(schema.encoding.max_field_id,65535);
  assert.ok(schema.vector_plan.syntax.length >= 50);
  for (const vector of schema.vector_plan.syntax) {
    assert.match(vector.id,/^syntax_[a-z0-9_]+$/u);
    assert.match(vector.hex,/^(?:[0-9a-f]{2})*$/u);
    assert.deepEqual(Object.keys(vector).sort(),(vector.expected_error ? ["expected_error","hex","id"] : ["hex","id"]));
  }
  verifyFragmentRegistry(schema.fragment_registry);
  verifyFragmentStateRegistry(schema.fragment_state_registry);
  verifyStreamStateRegistry(schema.stream_state_registry);
  verifyApiSchema(schema);
  verifyApplicationHeaderSchema(schema);
  verifySignaturePlan(schema);
  verifyStrictEd25519Plan(schema);
  verifyDHPolicy(schema);
  verifyNoisePlan(schema);
  verifyRecordPlan(schema);
  verifyReadyPlan(schema);
  verifyRekeyPlan(schema);
  verifyDomains(schema);
  assert.equal(new Set(schema.deferred_domains).size,schema.deferred_domains.length, "duplicate deferred domain");
  for (const name of schema.deferred_domains) assert.ok(!schema.domains.some(domain=>domain.name===name), "implemented domain is still deferred");
  assert.equal(schema.status, "draft");
  assert.equal(schema.wire_profile, "flowersec/4");
  assert.equal(schema.unicode.version,"15.1.0");
  assert.equal(schema.unicode.status,"reference_nfc_idna_conformance_only");
  assert.equal(schema.unicode.idna,"reference_conformance_only");
  assert.equal(schema.unicode.sdk_consumption,"not_qualified");
  assert.ok(schema.unresolved.length > 0);
  for (const [registryName, metadataName] of [["error_codes","error_code_metadata"],["admission_rejection_codes","admission_rejection_metadata"],["open_rejection_codes","open_rejection_metadata"]]) {
    const registry = schema[registryName], metadata = schema[metadataName];
    assert.ok(registry && metadata && typeof registry === "object" && typeof metadata === "object", `${registryName}: missing registry`);
    const codes = Object.values(registry);
    assert.ok(codes.length > 0 && new Set(codes).size === codes.length, `${registryName}: empty or duplicate codes`);
    for (const [name, code] of Object.entries(registry)) {
      assert.match(name, /^[a-z][a-z0-9_]*$/u);
      assert.ok(Number.isInteger(code) && code >= 0 && code <= 65535, `${registryName}: invalid code ${name}`);
      if (code === 0 || name === "normal") assert.ok(registryName === "error_codes" && name === "normal" && code === 0, "only normal may use code zero");
      const entry = metadata[name];
      assert.ok(entry, `${metadataName}: missing ${name}`);
      const fields = ["scope","action","retry","source",...(registryName === "error_codes" ? ["retryable"] : [])];
      assert.deepEqual(Object.keys(entry).sort(), fields.sort(), `${metadataName}: unexpected metadata ${name}`);
      assert.equal(entry.retry,"preserve_facts", `${metadataName}: retry is not authority`);
      assert.match(entry.source,/^\d+(?:\.\d+)*(?:,\d+(?:\.\d+)*)*$/u);
      const actions = registryName === "error_codes" ? {none:"none",session:"close_session",stream:"reset_stream"} : registryName === "admission_rejection_codes" ? {attempt:"end_attempt"} : {opening:"reject_open"};
      assert.ok(Object.hasOwn(actions,entry.scope), `${metadataName}: invalid scope ${name}`);
      assert.equal(entry.action,actions[entry.scope], `${metadataName}: action conflicts with scope`);
      if (registryName === "error_codes") {
        assert.equal(typeof entry.retryable,"boolean");
        assert.equal(entry.scope === "none", code === 0);
        if (code === 0) assert.equal(entry.retryable,false);
      }
    }
    assert.deepEqual(Object.keys(metadata).sort(), Object.keys(registry).sort(), `${metadataName}: registry mismatch`);
  }
  assert.equal(schema.error_codes.normal,0);
  assert.equal(schema.error_registry_boundary.status,"draft_subset");
  for (const key of ["allocation","retry","admission","locality","close"]) assert.ok(typeof schema.error_registry_boundary[key] === "string" && schema.error_registry_boundary[key].length > 0);
  const errorGroups = {error_codes:["ERROR","code","error_code_metadata"],admission_rejection_codes:["FSA4","code",null],open_rejection_codes:["OPEN_ACCEPT","reason",null]};
  const errorGroupIDs = new Set();
  const errorGroupCoverage = [];
  for (const group of schema.error_vector_plan) {
    assert.ok(!errorGroupIDs.has(group.id), "duplicate error vector group"); errorGroupIDs.add(group.id);
    assert.match(group.id,/^[a-z][a-z0-9_]*$/u);
    const expected = errorGroups[group.registry];
    assert.ok(expected,"unregistered error vector registry");
    assert.equal(group.field,expected[1]);
    const seed = schema.vector_plan.maps.find(plan => plan.id === group.source);
    assert.equal(seed?.schema,expected[0]);
    for (const key of Object.keys(group)) assert.ok(["id","source","registry","field","metadata","scope","replace"].includes(key), "unknown error vector attribute");
    if (expected[2]) {
      assert.equal(group.metadata,expected[2]);
      assert.ok(["session","stream"].includes(group.scope));
    } else {
      assert.equal(group.metadata,undefined); assert.equal(group.scope,undefined);
    }
    errorGroupCoverage.push(`${group.registry}:${group.scope ?? ""}`);
    for (const name of Object.keys(group.replace ?? {})) assert.ok(Object.values(schema.frame_maps[seed.schema].fields).some(field => field.name === name), "unknown error vector replacement");
  }
  assert.deepEqual(errorGroupCoverage.sort(),["admission_rejection_codes:","error_codes:session","error_codes:stream","open_rejection_codes:"], "error vector group coverage differs");
  function checkNumericRegistry(name, registry, field) {
    assert.ok(field.type.startsWith("uint"), `${name}: numeric registry requires unsigned field`);
    assert.ok(Object.hasOwn(schema,registry), `${name}: unresolved rule registry`);
    const entries = Object.values(schema[registry]);
    const codes = entries.map(entry => entry && typeof entry === "object" ? entry.code : entry);
    assert.ok(codes.length > 0 && new Set(codes).size === codes.length, `${name}: empty or duplicate numeric registry`);
    const maximum = (1n << BigInt(field.type.slice(4))) - 1n;
    for (const code of codes) assert.ok(Number.isSafeInteger(code) && code >= 0 && BigInt(code) <= maximum, `${name}: invalid numeric registry code`);
  }
  for (const [scheme, entry] of Object.entries(schema.origin_schemes)) {
    assert.match(scheme, /^[a-z][a-z0-9+.-]*$/u);
    assert.deepEqual(Object.keys(entry), ["default_port"]);
    assert.ok(Number.isInteger(entry.default_port) && entry.default_port >= 1 && entry.default_port <= 65535);
  }
  const fieldAttributes = {
    uint:["min","max","const","enum","enum_ref","bitmask","nullable"],
    text:["length","min_bytes","max_bytes","max_ref","const","const_ref","pattern_ref","text_enum_ref","text_format","forbidden_prefix"],
    bytes:["length","min_bytes","max_bytes","max_ref","nonzero","encoded_schema_ref","profile_public_key","allow_empty"],
    bool:["const"], map:["schema_ref"], "array<uint64>":["min_items","max_items"],
    text_map:["min_items","max_items","keys","values","entries"],
    array:["min_items","max_items","max_items_ref","items"], context_variant:["context","cases"],
  };
  for (const parameter of Object.values(schema.validation_parameters)) {
    if (parameter.capacity_field === undefined) continue;
    assert.equal(parameter.type,"uint64");
    assert.ok(Object.values(schema.frame_maps.NamespaceCapacity.fields).some(field => field.name === parameter.capacity_field && field.type === "uint64" && field.min === 1), "invalid capacity source");
    assert.ok(Number.isSafeInteger(parameter.divisor) && parameter.divisor > 0, "invalid capacity divisor");
    assert.ok(["bytes","items"].includes(parameter.unit), "invalid capacity unit");
    if (parameter.byte_capacity_field !== undefined || parameter.minimum_item_bytes !== undefined) {
      assert.equal(parameter.unit,"items", "byte intersection requires items");
      assert.equal(parameter.byte_capacity_field,"max_state_encoded_bytes", "count must intersect the complete State envelope");
      assert.ok(Number.isSafeInteger(parameter.minimum_item_bytes) && parameter.minimum_item_bytes > 0, "invalid minimum item size");
    }
  }
  const edges = new Map(), contextValues = new Map(), contextFields = [];
  for (const [context, labels] of Object.entries(schema.external_contexts)) {
    assert.match(context,/^[a-z][a-z0-9_]*$/u);
    assert.ok(Array.isArray(labels) && labels.length > 0 && new Set(labels).size === labels.length);
    for (const label of labels) assert.match(label,/^[a-z][a-z0-9_]*$/u);
    contextValues.set(context,[...labels].sort());
  }
  function checkField(name, field) {
    assert.ok(["uint8","uint16","uint32","uint64","text","bytes","bool","map","text_map","array<uint64>","array","context_variant"].includes(field.type), `${name}: unknown field type`);
    const attributes = new Set(["name","type","optional",...fieldAttributes[field.type.startsWith("uint") ? "uint" : field.type]]);
    for (const key of Object.keys(field)) assert.ok(attributes.has(key), `${name}: unknown field attribute ${key} for ${field.type}`);
    if (field.optional !== undefined) assert.equal(typeof field.optional,"boolean");
    if (field.nullable !== undefined) {
      assert.equal(field.type,"uint64", "null is only a declared uint64 impact sentinel");
      assert.equal(field.nullable,true);
    }
    if (field.type === "bool" && field.const !== undefined) assert.equal(typeof field.const,"boolean", `${name}: bool const must be boolean`);
    if (field.text_format !== undefined) assert.ok(Object.hasOwn(textFormats,field.text_format), `${name}: unknown text format`);
    for (const key of ["length","min_bytes","max_bytes"]) if (field[key] !== undefined) assert.ok(Number.isInteger(field[key]) && field[key] >= 0, `${name}: invalid ${key}`);
    if (field.min_bytes !== undefined && field.max_bytes !== undefined) assert.ok(field.min_bytes <= field.max_bytes);
    for (const key of ["nonzero","profile_public_key"]) if (field[key] !== undefined) assert.equal(typeof field[key],"boolean");
    for (const key of ["schema_ref","encoded_schema_ref"]) if (field[key]) {
      assert.ok(schema.frame_maps[field[key]], `${name}: dangling ${key}`);
      edges.get(name).add(field[key]);
    }
    if (field.type === "map") assert.ok(field.schema_ref, `${name}: missing schema_ref`);
    if (field.allow_empty !== undefined) {
      assert.equal(field.allow_empty,true);
      assert.ok(field.encoded_schema_ref, `${name}: empty sentinel requires an embedded schema`);
      assert.ok(field.min_bytes === undefined || field.min_bytes === 0, `${name}: empty sentinel conflicts with minimum`);
    }
    if (field.forbidden_prefix !== undefined) assert.ok(typeof field.forbidden_prefix === "string" && field.forbidden_prefix.length > 0);
    if (field.type === "text_map") {
      assert.equal(field.keys?.type,"text");
      checkField(name,field.keys);
      assert.ok(Number.isInteger(field.min_items) && field.min_items >= 0);
      assert.ok(Number.isInteger(field.max_items) && field.max_items >= field.min_items && field.max_items <= 64);
      assert.notEqual(field.values === undefined,field.entries === undefined, `${name}: text map requires one value schema`);
      if (field.values) checkField(name,field.values);
      if (field.entries) {
        assert.equal(Object.keys(field.entries).length,field.min_items);
        assert.equal(field.min_items,field.max_items);
        for (const [key,entry] of Object.entries(field.entries)) {
          assert.ok(key.length > 0 && Buffer.byteLength(key) <= 64);
          checkField(name,entry);
        }
      }
    }
    if (field.max_ref) assert.ok(schema.validation_parameters[field.max_ref], `${name}: dangling max_ref`);
    for (const key of ["enum_ref","text_enum_ref","const_ref"]) if (field[key]) assert.ok(Object.hasOwn(schema,field[key]), `${name}: dangling ${key}`);
    if (field.pattern_ref) {
      assert.equal(typeof schema.text_patterns[field.pattern_ref], "string", `${name}: dangling pattern_ref`);
      assert.doesNotThrow(() => new RegExp(schema.text_patterns[field.pattern_ref], "u"));
    }
    if (field.type.startsWith("uint")) {
      if (field.enum_ref !== undefined) checkNumericRegistry(name,field.enum_ref,field);
      const maximum = (1n << BigInt(field.type.slice(4))) - 1n;
      for (const key of ["min","max","const","bitmask"]) if (field[key] !== undefined) assert.ok(BigInt(field[key]) >= 0n && BigInt(field[key]) <= maximum, `${name}: ${key} exceeds type`);
      if (field.min !== undefined && field.max !== undefined) assert.ok(BigInt(field.min) <= BigInt(field.max));
      if (field.enum) {
        const codes = Object.values(field.enum);
        assert.equal(new Set(codes).size, codes.length, `${name}: duplicate enum value`);
        for (const code of codes) assert.ok(BigInt(code) >= 0n && BigInt(code) <= maximum);
      }
    }
    if (field.type.startsWith("array")) {
      assert.ok(Number.isInteger(field.min_items) && field.min_items >= 0);
      if (field.max_items_ref !== undefined) {
        assert.equal(field.max_items,undefined, `${name}: ambiguous array bound`);
        assert.equal(schema.validation_parameters[field.max_items_ref]?.type,"uint64", `${name}: unresolved capacity count`);
        assert.equal(schema.validation_parameters[field.max_items_ref]?.unit,"items", `${name}: capacity count requires items`);
      } else assert.ok(Number.isInteger(field.max_items) && field.max_items >= field.min_items && field.max_items <= 1035);
      if (field.type === "array") checkField(name, field.items);
    }
    if (field.type === "context_variant") {
      assert.equal(typeof field.context, "string");
      assert.ok(Object.keys(field.cases).length > 0);
      contextFields.push({name,field});
      for (const branch of Object.values(field.cases)) checkField(name, branch);
    }
  }
  for (const name of Object.keys(schema.frame_maps)) edges.set(name, new Set());
  for (const [name, definition] of Object.entries(schema.frame_maps)) {
    const attributes = new Set(["fields","required","max_encoded_bytes","max_encoded_bytes_ref","encoded_bytes","signature_field","mac_field","sender_role","index_origin","cryptographic_validation","deferred_constraints","context_fields"]);
    for (const key of Object.keys(definition)) assert.ok(attributes.has(key), `${name}: unknown map attribute ${key}`);
    if (definition.deferred_constraints) assert.ok(Array.isArray(definition.deferred_constraints) && definition.deferred_constraints.every((value) => typeof value === "string"));
    const names = new Set();
    for (const [id, field] of Object.entries(definition.fields)) {
      assert.match(id, /^(?:0|[1-9][0-9]*)$/u, `${name}: invalid field ID`);
      assert.ok(Number(id) <= 65535);
      assert.match(field.name, /^[a-z][a-z0-9_]*$/u);
      assert.ok(!names.has(field.name), `${name}: duplicate field name`); names.add(field.name);
      assert.equal(field.optional === true, !definition.required.includes(Number(id)), `${name}: inconsistent field presence ${id}`);
      checkField(name, field);
    }
    assert.equal(new Set(definition.required).size, definition.required.length, `${name}: duplicate required field`);
    for (const id of definition.required) assert.ok(definition.fields[id], `${name}: required field not defined`);
    for (const key of ["signature_field","mac_field"]) if (definition[key] !== undefined) {
      const field = definition.fields[definition[key]];
      assert.equal(field?.type,"bytes");
      assert.equal(field.length, key === "signature_field" ? 64 : 32);
      assert.ok(definition.required.includes(definition[key]));
    }
    for (const key of ["max_encoded_bytes","encoded_bytes"]) if (definition[key] !== undefined) assert.ok(Number.isInteger(definition[key]) && definition[key] > 0);
    if (definition.max_encoded_bytes_ref !== undefined) {
      assert.equal(definition.max_encoded_bytes,undefined, `${name}: ambiguous encoded bound`);
      assert.equal(definition.encoded_bytes,undefined, `${name}: fixed length conflicts with capacity`);
      assert.equal(schema.validation_parameters[definition.max_encoded_bytes_ref]?.type,"uint64", `${name}: unresolved capacity bytes`);
      assert.equal(schema.validation_parameters[definition.max_encoded_bytes_ref]?.unit,"bytes", `${name}: capacity bound requires bytes`);
    }
  }
  // Embedded CBOR also participates in the dependency graph. A cycle cannot
  // evade the bounded wire parser by resetting depth inside byte strings.
  function visit(name, active = new Set(), seen = new Set()) {
    assert.ok(!active.has(name), `recursive schema ${name}`);
    if (seen.has(name)) return;
    active.add(name);
    for (const child of edges.get(name)) visit(child, active, seen);
    active.delete(name); seen.add(name);
  }
  for (const name of edges.keys()) visit(name);
  for (const [name, definition] of Object.entries(schema.frame_maps)) {
    for (const [context, fieldName] of Object.entries(definition.context_fields ?? {})) {
      assert.match(context,/^[a-z][a-z0-9_]*$/u);
      const field = Object.entries(definition.fields).find(([,item]) => item.name === fieldName);
      assert.ok(field && field[1].enum && definition.required.includes(Number(field[0])), `${name}: context requires a required enum field`);
      const labels = Object.keys(field[1].enum).sort();
      if (contextValues.has(context)) assert.deepEqual(contextValues.get(context),labels, `${name}: context labels differ`);
      contextValues.set(context,labels);
    }
  }
  for (const {name,field} of contextFields) assert.deepEqual(Object.keys(field.cases).sort(),contextValues.get(field.context), `${name}: unregistered context or variant labels`);
  function checkPath(name, fieldPath) {
    assert.equal(typeof fieldPath,"string", `${name}: invalid rule path`);
    let fields = [{type:"map",schema_ref:name}];
    for (const part of fieldPath.split(".")) {
      const variants = fields.flatMap(field => field.type === "context_variant" ? Object.values(field.cases) : [field]);
      fields = variants.flatMap(field => {
        if (field.type === "array" || field.type === "array<uint64>") {
          assert.ok(/^(?:0|[1-9][0-9]*)$/u.test(part) && Number.isSafeInteger(Number(part)) && (field.max_items_ref !== undefined || Number(part) < field.max_items), `${name}: unresolved rule field ${fieldPath}`);
          return [field.items ?? {type:"uint64"}];
        }
        const map = schema.frame_maps[field.schema_ref ?? field.encoded_schema_ref];
        return Object.values(map?.fields ?? {}).filter(item => item.name === part);
      });
      assert.ok(fields.length > 0, `${name}: unresolved rule field ${fieldPath}`);
    }
    return fields;
  }
  function checkRule(name, rule, branch = false) {
    const branchAttributes = ["absent","required","nonzero","zero_bytes","constants","enum_values","byte_lengths","byte_prefixes","registered","equal","less_or_equal"];
    const ruleAttributes = {
      is_null:["field"],
      equal:["left","right"],equal_if_present:["left","right"],not_equal:["left","right"],less_or_equal:["left","right"],less_than:["left","right"],max_difference:["left","right","max"],
      ordinal_indices:["field","item_field_id"],at_least_one:["fields"],
      allowed_pairs:["left","right","pairs"],range:["field","min","max"],
      map_digest:["field","source","domain"],bit_subset:["left","right"],feature_bit:["field","feature","present"],
      increasing_tuple:["field","item_fields"],exclusive_item:["field","item_field","value"],error_scope:["code_field","target_scope_field","stream_id_field","retry_after_field"],
      allowed_tuples:["fields","rows"],registry_tuple:["registry","selectors","fields"],unique_by:["field","item_fields"],
      text_format:["field","format"],origin_endpoint:["host","port","origin","scheme"],
      profile_algorithm:["profile","algorithm"],increasing:["field","item_field_id"],increasing_bytes:["field","item_field_id"],increasing_cbor:["field"],increasing_scopes:["field"],
      variant:["discriminator","value",...branchAttributes],context_variant:["context","cases"],
    };
    if (!branch) assert.ok(Object.hasOwn(ruleAttributes,rule.op), `${name}: unknown rule`);
    const attributes = new Set(branch ? branchAttributes : ["op","when",...ruleAttributes[rule.op]]);
    for (const key of Object.keys(rule)) assert.ok(attributes.has(key), `${name}: unknown rule attribute ${key}`);
    for (const key of ["field","left","right","profile","algorithm","discriminator","host","port","origin","source","code_field","target_scope_field","stream_id_field","retry_after_field"]) if (rule[key]) checkPath(name,rule[key]);
    if (rule.op === "error_scope") {
      assert.equal(name, "ERROR");
      assert.equal(rule.when,undefined, "ERROR scope must be unconditional");
      assert.equal(rule.code_field, "code");
      assert.equal(rule.target_scope_field, "target_scope");
      assert.equal(rule.stream_id_field, "stream_id");
      assert.equal(rule.retry_after_field, "retry_after_ms");
      assert.ok(Object.keys(schema.error_code_metadata).every((key) => schema.error_codes[key] !== undefined));
    }
    if (rule.op === "is_null") {
      assert.ok(checkPath(name,rule.field).every(field => field.type === "uint64" && field.nullable === true), `${name}: null predicate requires a declared impact sentinel`);
    }
    if (rule.op === "at_least_one") {
      assert.ok(Array.isArray(rule.fields) && rule.fields.length > 0 && new Set(rule.fields).size === rule.fields.length, `${name}: presence fields must be distinct`);
      for (const path of rule.fields) {
        assert.ok(typeof path === "string" && !path.includes("."), `${name}: presence requires direct fields`);
        assert.ok(checkPath(name,path).every(field => field.optional === true), `${name}: presence requires optional fields`);
      }
    }
    if (rule.op === "equal_if_present") {
      const left=checkPath(name,rule.left),right=checkPath(name,rule.right);
      assert.ok(rule.left !== rule.right && left.length === 1 && right.length === 1, `${name}: equality requires distinct unambiguous fields`);
      assert.ok(left[0].type === "bytes" && right[0].type === "bytes" && Number.isInteger(left[0].length) && left[0].length > 0 && left[0].length === right[0].length, `${name}: optional equality requires equal fixed byte widths`);
      assert.ok(left[0].optional === true && right[0].optional === true, `${name}: optional equality requires optional fields`);
    }
    if (rule.op === "ordinal_indices") {
      assert.ok(Number.isInteger(rule.item_field_id) && rule.item_field_id >= 0, `${name}: invalid index field ID`);
      for (const field of checkPath(name,rule.field)) {
        assert.equal(field.type,"array"); assert.notEqual(field.optional,true);
        assert.equal(field.items.type,"map");
        const item=schema.frame_maps[field.items.schema_ref],index=item.fields[rule.item_field_id];
        assert.ok(item.required.includes(rule.item_field_id) && index?.type.startsWith("uint"), `${name}: index must be a required unsigned field`);
        assert.ok(index.min === undefined || index.min === 0, `${name}: ordinal index must start at zero`);
        assert.ok(BigInt(field.max_items-1) < (1n << BigInt(index.type.slice(4))) && (index.max === undefined || index.max >= field.max_items-1), `${name}: index must represent the entire array`);
      }
    }
    if (rule.op === "map_digest") {
      assert.ok(checkPath(name,rule.field).every(field => field.type === "bytes" && field.length === 32), `${name}: digest target requires bytes32`);
      const domain = schema.domains.find(item => item.name === rule.domain);
      assert.ok(domain?.operation === "sha256" && domain.input_schema.parts.length === 1, `${name}: digest requires one SHA-256 input`);
      const input = domain.input_schema.parts[0];
      assert.ok(input.encoding === "lp-map" && input.projection === "full" && input.schema_ref, `${name}: digest requires a complete map`);
      assert.ok(checkPath(name,rule.source).every(field => (field.type === "map" && field.schema_ref === input.schema_ref) || (field.type === "bytes" && field.encoded_schema_ref === input.schema_ref)), `${name}: digest map does not match its domain`);
    }
    function checkSelector(fieldPath, expected) {
      for (const field of checkPath(name,fieldPath)) {
        if (field.type === "bool") assert.equal(typeof expected,"boolean", `${name}: boolean condition requires a boolean`);
        else {
          assert.ok(field.type.startsWith("uint") && field.enum, `${name}: condition requires a numeric enum or boolean field`);
          assert.ok(Number.isSafeInteger(expected) && Object.values(field.enum).includes(expected), `${name}: condition value must be registered`);
        }
      }
    }
    if (rule.op === "variant") checkSelector(rule.discriminator,rule.value);
    if (rule.when) {
      const selector = Object.hasOwn(rule.when,"context") ? "context" : "field";
      assert.deepEqual(Object.keys(rule.when).sort(),[selector,"value"].sort(), `${name}: invalid rule condition`);
      if (selector === "context") assert.ok(contextValues.get(rule.when.context)?.includes(rule.when.value), `${name}: unknown conditional context`);
      else checkSelector(rule.when.field,rule.when.value);
    }
    if (rule.op === "bit_subset") for (const key of ["left","right"]) assert.ok(checkPath(name,rule[key]).every(field => field.type.startsWith("uint")), `${name}: feature subset requires unsigned fields`);
    if (rule.op === "feature_bit") {
      const bit = schema.feature_registry[rule.feature]?.bit;
      assert.ok(Number.isInteger(bit) && bit >= 0 && bit < 64, `${name}: unregistered feature bit`);
      assert.equal(typeof rule.present,"boolean", `${name}: feature presence requires a boolean`);
      assert.ok(checkPath(name,rule.field).every(field => field.type.startsWith("uint") && bit < Number(field.type.slice(4))), `${name}: feature bit must fit its unsigned field`);
    }
    if (rule.op === "increasing_tuple" || rule.op === "exclusive_item") {
      for (const field of checkPath(name,rule.field)) {
        assert.equal(field.type,"array", `${name}: item rule requires an array`);
        assert.equal(field.items.type,"map", `${name}: item rule requires maps`);
      }
      if (rule.op === "exclusive_item") checkSelector(`${rule.field}.0.${rule.item_field}`,rule.value);
      else {
        assert.ok(rule.item_fields.length > 0 && new Set(rule.item_fields).size === rule.item_fields.length, `${name}: tuple fields must be distinct`);
        for (const part of rule.item_fields) {
          assert.ok(typeof part === "string" && !part.includes("."), `${name}: tuple columns require direct item fields`);
          assert.ok(checkPath(name,`${rule.field}.0.${part}`).every(field => field.optional !== true && (field.type.startsWith("uint") || field.type === "bytes")), `${name}: tuple requires mandatory unsigned or byte fields`);
        }
      }
    }
    if (rule.op === "text_format") {
      assert.ok(Object.hasOwn(textFormats,rule.format), `${name}: unknown text format`);
      assert.ok(checkPath(name,rule.field).every(field => field.type === "text"));
    }
    if (rule.op === "origin_endpoint") {
      assert.ok(Object.hasOwn(schema.origin_schemes,rule.scheme));
      assert.ok(checkPath(name,rule.host).every(field => field.type === "text"));
      assert.ok(checkPath(name,rule.origin).every(field => field.type === "text"));
      assert.ok(checkPath(name,rule.port).every(field => field.type.startsWith("uint")));
    }
    if (rule.op === "allowed_tuples") {
      assert.ok(rule.fields.length > 0 && new Set(rule.fields).size === rule.fields.length);
      assert.ok(rule.rows.length > 0);
      const fields = rule.fields.map(field => checkPath(name,field));
      for (const row of rule.rows) {
        assert.equal(row.length,fields.length);
        for (const [index,code] of row.entries()) for (const field of fields[index]) {
          assert.ok(field.enum && Object.values(field.enum).includes(code), `${name}: tuple value is not registered`);
        }
      }
    }
    if (rule.op === "registry_tuple") {
      assert.ok(Object.hasOwn(schema,rule.registry), `${name}: unresolved tuple registry`);
      let tuples = [schema[rule.registry]];
      for (const selector of rule.selectors) {
        assert.equal(Object.keys(selector).length,1);
        let labels;
        if (selector.context) labels = contextValues.get(selector.context);
        else {
          assert.ok(typeof selector.field === "string" && !selector.field.includes("."), `${name}: tuple selector requires a root field`);
          const field = checkPath(name,selector.field)[0];
          assert.ok(field.enum, `${name}: tuple selector requires an enum`);
          labels = Object.keys(field.enum);
        }
        assert.ok(labels?.length > 0, `${name}: unresolved tuple selector`);
        tuples = tuples.flatMap(tuple => labels.map(label => {
          assert.ok(Object.hasOwn(tuple,label), `${name}: missing registry tuple`); return tuple[label];
        }));
      }
      assert.ok(rule.fields.length > 0 && new Set(rule.fields).size === rule.fields.length);
      for (const fieldName of rule.fields) {
        assert.ok(checkPath(name,fieldName).every(field => field.type === "text"));
        for (const tuple of tuples) assert.equal(typeof tuple[fieldName],"string", `${name}: missing tuple value`);
      }
    }
    if (rule.op === "unique_by") {
      assert.ok(typeof rule.field === "string" && !rule.field.includes("."), `${name}: identity array requires a root field`);
      assert.ok(rule.item_fields.length > 0 && new Set(rule.item_fields).size === rule.item_fields.length);
      for (const field of checkPath(name,rule.field)) {
        assert.equal(field.type,"array"); assert.equal(field.items.type,"map");
        for (const itemName of rule.item_fields) {
          const itemDefinition = schema.frame_maps[field.items.schema_ref];
          const item = Object.entries(itemDefinition.fields).find(([,entry]) => entry.name === itemName);
          assert.ok(item && itemDefinition.required.includes(Number(item[0])), `${name}: identity field must be required`);
        }
      }
    }
    if (rule.op === "increasing_cbor") for (const field of checkPath(name,rule.field)) assert.equal(field.type,"array", `${name}: canonical ordering requires an array`);
    if (rule.op === "max_difference") {
      assert.ok(typeof rule.max === "string" || Number.isSafeInteger(rule.max), `${name}: invalid duration bound`);
      assert.ok(BigInt(rule.max) >= 0n && BigInt(rule.max) < (1n << 64n), `${name}: invalid duration bound`);
      for (const key of ["left","right"]) assert.ok(checkPath(name,rule[key]).every(field => field.type.startsWith("uint")), `${name}: duration field must be unsigned`);
    }
    if (rule.op === "increasing_bytes") for (const field of checkPath(name,rule.field)) {
      assert.equal(field.type,"array", `${name}: byte ordering requires an array`);
      if (rule.item_field_id === undefined) assert.equal(field.items.type,"bytes", `${name}: byte ordering requires bytes`);
      else {
        assert.ok(Number.isInteger(rule.item_field_id) && rule.item_field_id >= 0 && rule.item_field_id <= 65535, `${name}: invalid ordered item field`);
        assert.equal(field.items.type,"map", `${name}: ordered item requires a map`);
        assert.equal(schema.frame_maps[field.items.schema_ref].fields[rule.item_field_id]?.type,"bytes", `${name}: ordered item field must be bytes`);
      }
    }
    for (const key of ["absent","required","nonzero","zero_bytes"]) for (const field of rule[key] ?? []) checkPath(name,field);
    for (const key of ["constants","enum_values","byte_lengths","byte_prefixes","registered"]) for (const field of Object.keys(rule[key] ?? {})) checkPath(name,field);
    for (const [field, registry] of Object.entries(rule.registered ?? {})) for (const definition of checkPath(name,field)) checkNumericRegistry(name,registry,definition);
    for (const key of ["equal","less_or_equal"]) for (const pair of rule[key] ?? []) for (const field of pair) checkPath(name,field);
    if (rule.op === "context_variant") {
      assert.deepEqual(Object.keys(rule.cases).sort(),contextValues.get(rule.context), `${name}: unregistered context or variant labels`);
      for (const item of Object.values(rule.cases)) checkRule(name,item,true);
    }
  }
  for (const [name, rules] of Object.entries(schema.map_rules)) {
    assert.ok(schema.frame_maps[name], `unknown rule schema ${name}`);
    for (const rule of rules) checkRule(name,rule);
  }
  assert.equal(schema.map_rules.ERROR?.filter(rule => rule.op === "error_scope").length,1, "ERROR requires exactly one scope rule");
  for (const [name, projection] of Object.entries(schema.map_projections ?? {})) {
    assert.deepEqual(Object.keys(projection).sort(),["fields","source","target"], `${name}: invalid projection`);
    const source=schema.frame_maps[projection.source], target=schema.frame_maps[projection.target];
    assert.ok(source && target, `${name}: unresolved projection map`);
    assert.equal(new Set(projection.fields).size,projection.fields.length, `${name}: duplicate projection field`);
    assert.deepEqual([...projection.fields].sort(),Object.values(target.fields).map(field=>field.name).sort(), `${name}: projection must cover the complete target`);
    for (const fieldName of projection.fields) {
      const from=Object.values(source.fields).find(field=>field.name===fieldName), to=Object.values(target.fields).find(field=>field.name===fieldName);
      assert.deepEqual(from,to, `${name}: incompatible projection field`);
    }
  }
  for (const id of schema.frame_maps.ReadyProofInput.required) assert.deepEqual(schema.frame_maps.ReadyProofInput.fields[id],schema.frame_maps.ReadyMACInput.fields[id], "READY common fields drift");
  return {maps:Object.keys(schema.frame_maps).length};
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const {schema, manifest} = checkArtifacts();
  verifySchema(schema);
  assert.equal(new Set(manifest.vectors.map((v) => v.id)).size, manifest.vectors.length);
  console.log(`Draft v4 artifact integrity, ${manifest.vectors.length} CBOR, ${manifest.domain_vectors.length} domain, ${manifest.text_vectors.length} text and ${manifest.query_vectors.length} query cases checked; schema freeze remains blocked.`);
}
