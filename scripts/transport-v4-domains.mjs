// Registry-driven reference inputs and primitive vectors, never SDK key handling.
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { decodeMap, encodeCBOR, encodeMap, strictHex, VectorError } from "./transport-v4-codec.mjs";

const fail = (code) => { throw new VectorError(code); };
const requireThat = (condition, code) => { if (!condition) fail(code); };
const sameBytes = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b);
const unsigned = (value, width) => {
  requireThat(typeof value === "bigint" || (typeof value === "number" && Number.isSafeInteger(value)), "domain_integer_type");
  const n = BigInt(value);
  requireThat(n >= 0n && n < (1n << BigInt(width * 8)), "domain_integer_range");
  const bytes = Buffer.alloc(width);
  if (width === 8) bytes.writeBigUInt64BE(n); else bytes.writeUIntBE(Number(n), 0, width);
  return bytes;
};
const lp = (bytes) => Buffer.concat([unsigned(bytes.length, 4), bytes]);
const widths = {u8:1, u32:4, u64:8};

function keys(value, allowed, required, description) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), `${description}: expected object`);
  for (const key of Object.keys(value)) assert.ok(allowed.includes(key), `${description}: unknown attribute ${key}`);
  for (const key of required) assert.ok(Object.hasOwn(value, key), `${description}: missing ${key}`);
}

export function verifyDomains(schema) {
  const names = new Set(), labels = new Set();
  for (const domain of schema.domains) {
    keys(domain, ["name","operation","label_bytes","input_schema","output_length","source","allocation"], ["name","operation","label_bytes","input_schema","output_length","source","allocation"], "domain");
    assert.match(domain.name, /^[a-z][a-z0-9_]*$/u);
    assert.ok(!names.has(domain.name), `duplicate domain name ${domain.name}`); names.add(domain.name);
    const operations = {sha256:32, "sha256-raw":32, ed25519:64, "hkdf-expand":32, "hkdf-extract":32, "hmac-sha256":32, "aead-aad":null, "noise-prologue":null, "tls-exporter":32};
    assert.equal(typeof domain.operation,"string");
    assert.ok(Object.hasOwn(operations,domain.operation), `unknown domain operation ${domain.operation}`);
    assert.equal(domain.output_length,operations[domain.operation]);
    assert.ok(["design_fixed","registry_allocation","external_standard"].includes(domain.allocation));
    assert.equal(typeof domain.source,"string");
    assert.ok(domain.source.length > 0);
    const label = strictHex(domain.label_bytes);
    assert.equal(domain.label_bytes,label.toString("hex"), "domain label must use lowercase hex");
    // Raw domains intentionally have no label and may therefore share the
    // empty label; only non-empty domain labels participate in uniqueness.
    if (domain.label_bytes.length > 0) {
      assert.ok(!labels.has(domain.label_bytes), `duplicate domain label ${domain.name}`); labels.add(domain.label_bytes);
    }
    if (domain.operation === "hkdf-extract" || domain.operation === "sha256-raw") assert.equal(label.length,0, "raw domain has no label");
    else if (domain.operation === "tls-exporter") assert.ok(["EXPORTER-flowersec-v4","EXPORTER-WebTransport"].includes(label.toString("ascii")) && label.every((n) => n > 0 && n < 128), "invalid external exporter label");
    else assert.equal(/^flowersec\/v[46]\/[a-z0-9/_-]+\x00$/u.exec(label.toString("latin1"))?.[0],label.toString("latin1"), "custom label requires ASCII and one NUL");
    const keyed = ["hkdf-expand","hmac-sha256"].includes(domain.operation);
    keys(domain.input_schema,["parts","key","salt","ikm","relations"], ["parts",...(keyed ? ["key"] : []),...(domain.operation === "hkdf-extract" ? ["salt","ikm"] : [])], domain.name);
    assert.equal(Object.hasOwn(domain.input_schema,"key"),keyed);
    for (const name of ["salt","ikm"]) assert.equal(Object.hasOwn(domain.input_schema,name),domain.operation === "hkdf-extract");
    assert.ok(Array.isArray(domain.input_schema.parts));
    assert.equal(domain.input_schema.parts.length === 0, domain.operation === "hkdf-extract");
    const inputs = new Map();
    for (const [index, part] of [...domain.input_schema.parts, ...["key","salt","ikm"].filter((name) => Object.hasOwn(domain.input_schema,name)).map((name) => domain.input_schema[name])].entries()) {
      assert.ok(part && typeof part === "object" && !Array.isArray(part),`${domain.name}: invalid input part`);
      const attributes = {
        u8:["enum","const","min","max","multiple_of"],u32:["min","max","multiple_of"],u64:["min","max","multiple_of"],hex:["hex"],
        "lp-ascii":["text_enum_ref","const_ref"],
        raw:["length","max_length","nonzero"],"lp-bytes":["length","max_length","nonzero"],
        "lp-map":["schema_ref","schema_cases","selector","projection","fields","bindings","one_of_bindings"],
      };
      assert.equal(typeof part.encoding,"string");
      assert.ok(Object.hasOwn(attributes,part.encoding), `${domain.name}: unknown input encoding`);
      const literal = part.encoding === "hex" || part.const !== undefined || part.const_ref !== undefined;
      keys(part,["encoding",...(literal ? [] : ["name"]),...attributes[part.encoding]],["encoding",...(!literal ? ["name"] : [])],`${domain.name}/${index}`);
      if (!literal) {
        assert.match(part.name,/^[a-z][a-z0-9_]*$/u);
        assert.ok(!inputs.has(part.name), `${domain.name}: duplicate input ${part.name}`); inputs.set(part.name,part);
      }
      if (part.encoding === "hex") strictHex(part.hex);
      if (part.encoding === "raw" || part.encoding === "lp-bytes") {
        assert.ok((Number.isSafeInteger(part.length) && part.length > 0 && part.length <= 65536) || (Number.isSafeInteger(part.max_length) && part.max_length > 0 && part.max_length <= schema.resource_caps.max_payload_length));
        if (part.nonzero !== undefined) assert.equal(typeof part.nonzero,"boolean");
      }
      if (part.encoding === "lp-ascii") {
        assert.equal(Number(part.text_enum_ref !== undefined) + Number(part.const_ref !== undefined),1);
        if (Object.hasOwn(part,"const_ref")) {
          assert.ok(typeof part.const_ref === "string" && part.const_ref.length > 0);
          assert.ok(typeof schema[part.const_ref] === "string" && /^[\x00-\x7f]+$/u.test(schema[part.const_ref]));
        }
        if (Object.hasOwn(part,"text_enum_ref")) {
          assert.ok(typeof part.text_enum_ref === "string" && part.text_enum_ref.length > 0);
          assert.ok(schema[part.text_enum_ref] && typeof schema[part.text_enum_ref] === "object" && !Array.isArray(schema[part.text_enum_ref]));
          assert.ok(Object.keys(schema[part.text_enum_ref]).length > 0);
        }
      }
      if (Object.hasOwn(part,"enum")) {
        assert.ok(Array.isArray(part.enum) && part.enum.length > 0 && new Set(part.enum).size === part.enum.length);
        for (const value of part.enum) unsigned(value,widths[part.encoding]);
      }
      if (part.const !== undefined) unsigned(part.const,widths[part.encoding]);
      for (const attribute of ["min","max","multiple_of"]) if (Object.hasOwn(part,attribute)) {
        assert.ok(typeof part[attribute] === "number" ? Number.isSafeInteger(part[attribute]) : typeof part[attribute] === "string" && /^(?:0|[1-9][0-9]*)$/u.test(part[attribute]));
        unsigned(BigInt(part[attribute]),widths[part.encoding]);
      }
      if (part.multiple_of !== undefined) assert.ok(BigInt(part.multiple_of) > 0n);
      if (part.min !== undefined && part.max !== undefined) assert.ok(BigInt(part.min) <= BigInt(part.max));
      if (part.encoding === "lp-map") {
        assert.equal(Number(part.schema_ref !== undefined) + Number(part.schema_cases !== undefined),1);
        assert.equal(part.selector !== undefined,part.schema_cases !== undefined);
        if (Object.hasOwn(part,"schema_ref")) assert.ok(typeof part.schema_ref === "string" && part.schema_ref.length > 0);
        if (Object.hasOwn(part,"schema_cases")) {
          assert.ok(part.schema_cases && typeof part.schema_cases === "object" && !Array.isArray(part.schema_cases) && Object.keys(part.schema_cases).length > 0);
          assert.ok(Object.values(part.schema_cases).every((name) => typeof name === "string" && name.length > 0));
          assert.ok(typeof part.selector === "string" && part.selector.length > 0);
        }
        if (Object.hasOwn(part,"bindings")) assert.ok(part.bindings && typeof part.bindings === "object" && !Array.isArray(part.bindings) && Object.keys(part.bindings).length > 0 && Object.values(part.bindings).every((input) => typeof input === "string" && input.length > 0));
        if (Object.hasOwn(part,"one_of_bindings")) {
          assert.ok(part.one_of_bindings && typeof part.one_of_bindings === "object" && !Array.isArray(part.one_of_bindings) && Object.keys(part.one_of_bindings).length > 0);
          for (const fields of Object.values(part.one_of_bindings)) assert.ok(Array.isArray(fields) && fields.length > 0 && fields.every((field) => typeof field === "string" && field.length > 0));
        }
        assert.ok(["full","without_signature","without_mac","without_open_digest","without_fields","without_fields_raw"].includes(part.projection));
        if (["without_fields","without_fields_raw"].includes(part.projection)) assert.ok(Array.isArray(part.fields) && part.fields.length > 0 && new Set(part.fields).size === part.fields.length && part.fields.every((field) => typeof field === "string"));
        for (const name of part.schema_ref ? [part.schema_ref] : Object.values(part.schema_cases)) {
          assert.ok(Object.hasOwn(schema.frame_maps,name), `${domain.name}: dangling map ${name}`);
          const map = schema.frame_maps[name];
          if (part.projection === "without_signature") assert.ok(Number.isInteger(map.signature_field));
          if (part.projection === "without_mac") assert.ok(Number.isInteger(map.mac_field));
          if (part.projection === "without_open_digest") assert.equal(Object.values(map.fields).filter((field) => field.name === "open_digest" && field.type === "bytes" && field.length === 32).length,1);
          if (["without_fields","without_fields_raw"].includes(part.projection)) for (const name of part.fields) assert.ok(Object.values(map.fields).some((field) => field.name === name), `${domain.name}: missing projected field`);
          for (const field of Object.keys(part.bindings ?? {})) assert.ok(Object.values(map.fields).some((item) => item.name === field), `${domain.name}: missing map binding field`);
          for (const field of Object.values(part.one_of_bindings ?? {}).flat()) assert.ok(Object.values(map.fields).some((item) => item.name === field), `${domain.name}: missing map binding field`);
        }
      }
    }
    for (const part of domain.input_schema.parts) {
      if (part.schema_cases) {
        assert.ok(inputs.get(part.selector)?.enum, `${domain.name}: missing selector enum`);
        assert.deepEqual(Object.keys(part.schema_cases).sort(),inputs.get(part.selector).enum.map(String).sort());
      }
      for (const input of Object.values(part.bindings ?? {})) assert.ok(inputs.has(input), `${domain.name}: dangling input binding`);
      for (const input of Object.keys(part.one_of_bindings ?? {})) assert.ok(inputs.has(input), `${domain.name}: dangling input binding`);
    }
    for (const name of ["key","salt","ikm"]) if (Object.hasOwn(domain.input_schema,name)) {
      assert.equal(domain.input_schema[name].encoding,"raw"); assert.equal(domain.input_schema[name].length,32);
    }
    if (Object.hasOwn(domain.input_schema,"relations")) assert.ok(Array.isArray(domain.input_schema.relations) && domain.input_schema.relations.length > 0);
    for (const rule of domain.input_schema.relations ?? []) {
      keys(rule,["op","left","right","pairs"],["op","left","right"],domain.name);
      assert.ok(["successor","allowed_pairs"].includes(rule.op));
      assert.ok(widths[inputs.get(rule.left)?.encoding] && widths[inputs.get(rule.right)?.encoding]);
      assert.equal(Object.hasOwn(rule,"pairs"),rule.op === "allowed_pairs");
      if (Object.hasOwn(rule,"pairs")) {
        assert.ok(Array.isArray(rule.pairs) && rule.pairs.length > 0);
        for (const pair of rule.pairs) {
          assert.ok(Array.isArray(pair) && pair.length === 2);
          pair.forEach((value,i) => unsigned(value,widths[inputs.get(i ? rule.right : rule.left).encoding]));
        }
      }
    }
  }
  return names.size;
}

function partBytes(schema, part, args, context) {
  if (part.encoding === "hex") return strictHex(part.hex);
  const value = part.const_ref ? schema[part.const_ref] : part.const ?? args[part.name];
  if (widths[part.encoding]) {
    const bytes = unsigned(value,widths[part.encoding]);
    if (part.enum) requireThat(part.enum.some((n) => BigInt(n) === BigInt(value)),"domain_enum");
    if (part.min !== undefined) requireThat(BigInt(value) >= BigInt(part.min),"domain_integer_range");
    if (part.max !== undefined) requireThat(BigInt(value) <= BigInt(part.max),"domain_integer_range");
    if (part.multiple_of !== undefined) requireThat(BigInt(value) % BigInt(part.multiple_of) === 0n,"domain_integer_multiple");
    return bytes;
  }
  if (part.encoding === "lp-ascii") {
    requireThat(typeof value === "string" && /^[\x00-\x7f]+$/u.test(value), "domain_ascii");
    if (part.text_enum_ref) requireThat(Object.hasOwn(schema[part.text_enum_ref],value),"domain_enum");
    return lp(Buffer.from(value,"ascii"));
  }
  requireThat(Buffer.isBuffer(value),"domain_bytes_type");
  if (part.encoding === "lp-map") {
    const name = part.schema_ref ?? part.schema_cases[String(args[part.selector])];
    requireThat(Boolean(name),"domain_variant");
    const map = decodeMap(schema,name,value,context), definition = schema.frame_maps[name];
    for (const [field, input] of Object.entries(part.bindings ?? {})) {
      const id = Object.entries(definition.fields).find(([,item]) => item.name === field)[0];
      const actual = map.get(BigInt(id)), expected = args[input];
      requireThat(actual === expected || sameBytes(actual,expected) || (typeof actual === "bigint" && typeof expected === "number" && Number.isSafeInteger(expected) && actual === BigInt(expected)),"domain_binding");
    }
    for (const [input, fields] of Object.entries(part.one_of_bindings ?? {})) {
      const expected = args[input];
      requireThat(fields.some((field) => {
        const id = Object.entries(definition.fields).find(([,item]) => item.name === field)[0], actual = map.get(BigInt(id));
        return actual === expected || sameBytes(actual,expected) || (typeof actual === "bigint" && typeof expected === "number" && Number.isSafeInteger(expected) && actual === BigInt(expected));
      }),"domain_binding");
    }
    if (part.projection === "full") return lp(value); // Bind original bytes, including signatures/MACs.
    if (["without_fields","without_fields_raw"].includes(part.projection)) {
      for (const name of part.fields) {
        const id = Object.entries(definition.fields).find(([,field]) => field.name === name)?.[0];
        requireThat(id !== undefined && map.delete(BigInt(id)),"domain_projection");
      }
      const encoded = encodeMap(schema,name,map,context);
      return part.projection === "without_fields_raw" ? encoded : lp(encoded);
    }
    let id = definition[part.projection === "without_signature" ? "signature_field" : "mac_field"];
    if (part.projection === "without_open_digest") id = Object.entries(definition.fields).find(([,field]) => field.name === "open_digest")[0];
    requireThat(map.delete(BigInt(id)),"domain_projection");
    return lp(encodeMap(schema,name,map,context)); // Surviving integer field IDs never move.
  }
  requireThat(part.length === undefined ? value.length <= part.max_length : value.length === part.length,"domain_bytes_length");
  if (part.nonzero) requireThat(value.some((n) => n !== 0),"domain_zero_secret");
  return part.encoding === "raw" ? value : lp(value);
}

export function evaluateDomain(schema, name, args, context = {}) {
  const domain = schema.domains.find((item) => item.name === name);
  requireThat(Boolean(domain),"domain_unknown");
  const spec = domain.input_schema;
  const fields = [...spec.parts,...["key","salt","ikm"].filter((key) => spec[key]).map((key) => spec[key])];
  const expected = fields.filter((part) => part.name).map((part) => part.name);
  requireThat(args && typeof args === "object" && Object.keys(args).length === expected.length && expected.every((key) => Object.hasOwn(args,key)),"domain_arguments");
  if (args.profile !== undefined) {
    requireThat(context.crypto_profile_id === undefined || context.crypto_profile_id === args.profile,"domain_context");
    context = {...context,crypto_profile_id:args.profile};
  }
  const label = strictHex(domain.label_bytes);
  const content = Buffer.concat(spec.parts.map((part) => partBytes(schema,part,args,context)));
  for (const rule of spec.relations ?? []) {
    const left = BigInt(args[rule.left]), right = BigInt(args[rule.right]);
    requireThat(rule.op === "successor" ? left + 1n === right : rule.pairs.some(([a,b]) => BigInt(a) === left && BigInt(b) === right),"domain_relation");
  }
  const input = ["tls-exporter","sha256-raw"].includes(domain.operation) ? content : Buffer.concat([label,content]);
  const result = {label_hex:label.toString("hex"),input_hex:input.toString("hex")};
  let output;
  if (domain.operation === "sha256" || domain.operation === "sha256-raw") output = createHash("sha256").update(input).digest();
  if (domain.operation === "hmac-sha256" || domain.operation === "hkdf-expand") {
    const key = partBytes(schema,spec.key,args,context);
    // All registered Expand outputs are exactly one SHA-256 block. This is
    // RFC 5869 Expand(PRK, info, 32), with no extra Extract and no prior T.
    output = createHmac("sha256",key).update(input);
    if (domain.operation === "hkdf-expand") output.update(Buffer.from([1]));
    output = output.digest();
  }
  if (domain.operation === "hkdf-extract") {
    const salt = partBytes(schema,spec.salt,args,context), ikm = partBytes(schema,spec.ikm,args,context);
    result.salt_hex = salt.toString("hex"); result.ikm_hex = ikm.toString("hex");
    output = createHmac("sha256",salt).update(ikm).digest();
  }
  if (output) result.output_hex = output.toString("hex");
  // Ed25519 emits only exact signing inputs. Exporter emits only the final
  // label/context/length. Neither is a signature or live TLS qualification.
  if (domain.operation === "tls-exporter") result.output_length = domain.output_length;
  return result;
}
