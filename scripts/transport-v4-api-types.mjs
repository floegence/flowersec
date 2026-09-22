import { apiEnumValues, validateApiResult, verifyApiSchema } from "./transport-v4-api-results.mjs";

const pascal = value => value.split("_").map(part => part[0].toUpperCase() + part.slice(1)).join("");
const camel = value => { const name = pascal(value); return name[0].toLowerCase() + name.slice(1); };

// These internal declarations have no public package wiring or runtime methods.
// Only the single API schema defines field names, optionality and enum values.
// Private validation context is tooling input and is not emitted into SDK types.
export function generateApiTypes(schema, schemaSHA) {
  verifyApiSchema(schema);
  const header = "// Generated draft native API types; DO NOT EDIT. Not a qualified SDK runtime.\n";
  let go = header + `package protocolv4\n\nconst APIResultsSchemaSHA256 = "${schemaSHA}"\n`;
  let rust = header + `pub(crate) const API_RESULTS_SCHEMA_SHA256: &str = "${schemaSHA}";\n`;
  let swift = header + `enum TransportV4APIResults { static let schemaSHA256 = "${schemaSHA}" }\n`;
  let ts = header + `export const transportV4APIResultsSchemaSHA256 = "${schemaSHA}" as const;\n`;
  const primitive = {
    go: {uint64:"uint64", bytes:"[]byte", bool:"bool"},
    rust: {uint64:"u64", bytes:"Vec<u8>", bool:"bool"},
    swift: {uint64:"UInt64", bytes:"[UInt8]", bool:"Bool"},
    ts: {uint64:"bigint", bytes:"Uint8Array", bool:"boolean"},
  };
  const type = (language, field) => {
    const base = primitive[language][field.type] ?? `V4${field.type}`;
    if (!field.optional) return base;
    return {go:`*${base}`, rust:`Option<${base}>`, swift:`${base}?`, ts:base}[language];
  };
  for (const [name, definition] of Object.entries(schema.api_schema.types)) {
    const native = `V4${name}`;
    if (!definition.fields) {
      const values = apiEnumValues(schema, definition);
      go += `\ntype ${native} string\n\n` + values.map(value => `const ${native}${pascal(value)} ${native} = "${value}"\n`).join("");
      rust += `\n#[derive(Clone, PartialEq, Eq)]\npub(crate) enum ${native} {\n` + values.map(value => `    ${pascal(value)},\n`).join("") + "}\n";
      swift += `\nenum ${native}: String {\n` + values.map(value => `    case ${camel(value)} = "${value}"\n`).join("") + "}\n";
      ts += `\nexport type ${native} = ${values.map(value => JSON.stringify(value)).join(" | ")};\n`;
      continue;
    }
    const fields = Object.entries(definition.fields);
    const width = Math.max(...fields.map(([field]) => pascal(field).length));
    go += `\ntype ${native} struct {\n` + fields.map(([field, descriptor]) => {
      const label = pascal(field);
      return `\t${label.padEnd(width + 1, " ")}${type("go", descriptor)}\n`;
    }).join("") + "}\n";
    rust += `\n#[derive(Clone, PartialEq, Eq)]\npub(crate) struct ${native} {\n` + fields.map(([field, descriptor]) => `    pub(crate) ${field}: ${type("rust", descriptor)},\n`).join("") + "}\n";
    swift += `\nstruct ${native} {\n` + fields.map(([field, descriptor]) => `    let ${camel(field)}: ${type("swift", descriptor)}\n`).join("") + "}\n";
    ts += `\nexport interface ${native} {\n` + fields.map(([field, descriptor]) => `  readonly ${field}${descriptor.optional ? "?" : ""}: ${type("ts", descriptor)};\n`).join("") + "}\n";
  }
  // Provider classes are private inputs, never Session.Info fields. Each
  // native implementation selects a class from its original observations.
  const entries = Object.entries(schema.connection_assurance_registry.entries);
  go += "\nfunc ConnectionAssurance(class string) (V4ConnectionGuarantees, bool) {\n\tswitch class {\n";
  rust += "\npub(crate) fn connection_assurance(class: &str) -> Option<V4ConnectionGuarantees> {\n    match class {\n";
  swift += "\nfunc connectionAssurance(_ value: String) -> V4ConnectionGuarantees? {\n    switch value {\n";
  ts += "\nexport function connectionAssurance(value: string): V4ConnectionGuarantees | undefined {\n  switch (value) {\n";
  for (const [name, value] of entries) {
    if (!/^[a-z][a-z0-9_]*$/u.test(name)) throw new Error("invalid connection assurance class");
    validateApiResult(schema, "ConnectionGuarantees", value);
    const fields = Object.entries(value);
    const native = (language, field, item) => {
      if (typeof item === "boolean") return String(item);
      const type = schema.api_schema.types.ConnectionGuarantees.fields[field].type;
      return language === "go" ? `V4${type}${pascal(item)}` : language === "rust" ? `V4${type}::${pascal(item)}` : `.${camel(item)}`;
    };
    go += `\tcase "${name}":\n\t\treturn V4ConnectionGuarantees{` + fields.map(([f,v]) => `${pascal(f)}: ${native("go",f,v)}`).join(", ") + "}, true\n";
    rust += `        "${name}" => Some(V4ConnectionGuarantees { ` + fields.map(([f,v]) => `${f}: ${native("rust",f,v)}`).join(", ") + " }),\n";
    swift += `    case "${name}": return V4ConnectionGuarantees(` + fields.map(([f,v]) => `${camel(f)}: ${native("swift",f,v)}`).join(", ") + ")\n";
    ts += `    case "${name}": return Object.freeze(${JSON.stringify(value)});\n`;
  }
  go += "\tdefault:\n\t\treturn V4ConnectionGuarantees{}, false\n\t}\n}\n";
  rust += "        _ => None,\n    }\n}\n";
  swift += "    default: return nil\n    }\n}\n";
  ts += "    default: return undefined;\n  }\n}\n";
  return new Map([
    ["flowersec-go/internal/protocolv4/api_results_generated.go", go],
    ["flowersec-rust/src/api_results_v4_generated.rs", rust],
    ["flowersec-swift/Sources/Flowersec/TransportV4APIResults.generated.swift", swift],
    ["flowersec-ts/src/generated/transportV4APIResults.ts", ts],
  ]);
}
