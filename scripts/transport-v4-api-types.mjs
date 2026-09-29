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
  // Error projection is generated from one registry. This validates the
  // mapping only; the runtime must independently prove a terminal commit.
  go += "\nfunc TopUpErrorProjection(code V4TopUpErrorCode, action V4TopUpWriteAction) (V4TopUpError, bool) {\n\tswitch code {\n";
  rust += "\npub(crate) fn top_up_error_projection(code: V4TopUpErrorCode, action: V4TopUpWriteAction) -> Option<V4TopUpError> {\n    match code {\n";
  swift += "\nfunc topUpErrorProjection(_ code: V4TopUpErrorCode, _ action: V4TopUpWriteAction) -> V4TopUpError? {\n    switch code {\n";
  ts += "\nexport function topUpErrorProjection(code: V4TopUpErrorCode, action: V4TopUpWriteAction): V4TopUpError | undefined {\n  switch (code) {\n";
  for (const [code, entry] of Object.entries(schema.top_up_error_metadata)) {
    const actions = entry.write_actions;
    go += `\tcase V4TopUpErrorCode${pascal(code)}:\n\t\tif ${actions.map(action => `action == V4TopUpWriteAction${pascal(action)}`).join(" || ")} {\n\t\t\treturn V4TopUpError{Code: code, Scope: V4TopUpErrorScope${pascal(entry.scope)}, WriteAction: action}, true\n\t\t}\n`;
    rust += `        V4TopUpErrorCode::${pascal(code)} => { if ${actions.map(action => `action == V4TopUpWriteAction::${pascal(action)}`).join(" || ")} { Some(V4TopUpError { code, scope: V4TopUpErrorScope::${pascal(entry.scope)}, write_action: action }) } else { None } },\n`;
    swift += `    case .${camel(code)}: return (${actions.map(action => `action == .${camel(action)}`).join(" || ")}) ? V4TopUpError(code: code, scope: .${camel(entry.scope)}, writeAction: action) : nil\n`;
    ts += `    case "${code}": return (${actions.map(action => `action === "${action}"`).join(" || ")}) ? Object.freeze({code, scope: "${entry.scope}", write_action: action}) : undefined;\n`;
  }
  go += "\t}\n\treturn V4TopUpError{}, false\n}\n";
  rust += "    }\n}\n";
  swift += "    }\n}\n";
  ts += "  }\n}\n";
  // Pure local result validation does not establish lifecycle or cleanup facts.
  // Native closed enums reject unknown values structurally; Go and TS also
  // check their string representations against the original schema.
  const enumCheck = (language, name, field) => apiEnumValues(schema, schema.api_schema.types[name]).map(value =>
    language === "go" ? `${field} == V4${name}${pascal(value)}` : `${field} === "${value}"`).join(" || ");
  go += `
func ValidLifecycleResult(value V4LifecycleResult) bool {
\tcleanup := value.CleanupStatus
\treturn (${enumCheck("go", "LifecycleObjectKind", "value.ObjectKind")}) &&
\t\t(${enumCheck("go", "LifecycleState", "value.LifecycleState")}) &&
\t\t(${enumCheck("go", "LifecycleReason", "value.Reason")}) &&
\t\t(${enumCheck("go", "CleanupState", "cleanup.Status")}) &&
\t\t(${enumCheck("go", "CoreCleanup", "cleanup.CoreCleanup")}) &&
\t\t(cleanup.Status == V4CleanupStateComplete) == (cleanup.CoreCleanup == V4CoreCleanupComplete && cleanup.PendingCallbacks == 0) &&
\t\t(value.LifecycleState != V4LifecycleStateSessionAborted || value.ObjectKind == V4LifecycleObjectKindSession) &&
\t\t(cleanup.Status != V4CleanupStateComplete || value.LifecycleState == V4LifecycleStateClosed || value.LifecycleState == V4LifecycleStateSessionAborted)
}
`;
  rust += `
pub(crate) fn valid_lifecycle_result(value: &V4LifecycleResult) -> bool {
    let cleanup = &value.cleanup_status;
    (cleanup.status == V4CleanupState::Complete) == (cleanup.core_cleanup == V4CoreCleanup::Complete && cleanup.pending_callbacks == 0)
        && (value.lifecycle_state != V4LifecycleState::SessionAborted || value.object_kind == V4LifecycleObjectKind::Session)
        && (cleanup.status != V4CleanupState::Complete || matches!(value.lifecycle_state, V4LifecycleState::Closed | V4LifecycleState::SessionAborted))
}
`;
  swift += `
func validLifecycleResult(_ value: V4LifecycleResult) -> Bool {
    let cleanup = value.cleanupStatus
    return (cleanup.status == .complete) == (cleanup.coreCleanup == .complete && cleanup.pendingCallbacks == 0)
        && (value.lifecycleState != .sessionAborted || value.objectKind == .session)
        && (cleanup.status != .complete || value.lifecycleState == .closed || value.lifecycleState == .sessionAborted)
}
`;
  ts += `
export function validLifecycleResult(value: V4LifecycleResult): boolean {
  const cleanup = value.cleanup_status;
  return (${enumCheck("ts", "LifecycleObjectKind", "value.object_kind")}) &&
    (${enumCheck("ts", "LifecycleState", "value.lifecycle_state")}) &&
    (${enumCheck("ts", "LifecycleReason", "value.reason")}) &&
    (${enumCheck("ts", "CleanupState", "cleanup.status")}) &&
    (${enumCheck("ts", "CoreCleanup", "cleanup.core_cleanup")}) &&
    typeof cleanup.pending_callbacks === "bigint" && cleanup.pending_callbacks >= 0n && cleanup.pending_callbacks <= 0xffffffffffffffffn &&
    (cleanup.status === "complete") === (cleanup.core_cleanup === "complete" && cleanup.pending_callbacks === 0n) &&
    (value.lifecycle_state !== "session_aborted" || value.object_kind === "session") &&
    (cleanup.status !== "complete" || value.lifecycle_state === "closed" || value.lifecycle_state === "session_aborted");
}
`;
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
