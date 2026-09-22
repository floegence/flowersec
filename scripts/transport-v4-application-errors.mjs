import { decodeMap, encodeMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { captureApplicationBytes, verifyApplicationResponse } from "./transport-v4-application-headers.mjs";

// Reference byte/metadata relations only. Trusted immutable local schema
// registration, method binding, application codec execution and original
// response ownership remain external; a remote catalog cannot install a codec.
const requireThat = (condition,code) => { if (!condition) throw new VectorError(code); };
const hash = (schema,name,args) => Buffer.from(evaluateDomain(schema,name,args).output_hex,"hex");
const fieldID = (schema,name,field) => BigInt(Object.entries(schema.frame_maps[name].fields).find(([,entry])=>entry.name===field)[0]);
const decoded = (schema,name,input) => decodeMap(schema,name,captureApplicationBytes(input,schema.frame_maps[name].max_encoded_bytes));

export function matchApplicationErrorSchemaReference(schema, definitionBytes, registeredCanonicalSchemaBytes) {
  const definition=decoded(schema,"ErrorDefinition",definitionBytes);
  const domain=schema.domains.find(entry=>entry.name==="business_error_schema_digest");
  const bytes=captureApplicationBytes(registeredCanonicalSchemaBytes,domain.input_schema.parts[0].max_length);
  // These are the exact pre-registered canonical bytes. This hash neither
  // interprets application schema syntax nor normalizes or downloads a schema.
  requireThat(definition.get(fieldID(schema,"ErrorDefinition","schema_digest")).equals(hash(schema,domain.name,{error_schema:bytes})),"application_error_schema_mismatch");
}

export function matchApplicationErrorCatalogReference(schema, contractBytes, registeredDefinitions) {
  const contract=decoded(schema,"ServiceContract",contractBytes);
  const field=schema.frame_maps.ServiceContract.fields[fieldID(schema,"ServiceContract","application_error_catalog")];
  requireThat(Array.isArray(registeredDefinitions) && registeredDefinitions.length<=field.max_items,"application_error_catalog_size");
  const catalog=contract.get(fieldID(schema,"ServiceContract","application_error_catalog"));
  requireThat(catalog.length===registeredDefinitions.length,"application_error_catalog_mismatch");
  for (let index=0; index<catalog.length; index++) {
    const local=decoded(schema,"ErrorDefinition",registeredDefinitions[index]);
    requireThat(encodeMap(schema,"ErrorDefinition",catalog[index]).equals(encodeMap(schema,"ErrorDefinition",local)),"application_error_catalog_mismatch");
  }
}

export function classifyApplicationErrorReference(schema, originalRequest, responseHeader, contractBytes, payload) {
  const response=verifyApplicationResponse(schema,originalRequest,responseHeader);
  const variant=schema.application_message_kinds[response.kind];
  requireThat(variant.application_error===true,"application_error_kind");
  const contractOwned=captureApplicationBytes(contractBytes,schema.frame_maps.ServiceContract.max_encoded_bytes);
  const contract=decodeMap(schema,"ServiceContract",contractOwned);
  requireThat(response.map.get(6n).equals(hash(schema,"service_contract_digest",{contract:contractOwned})) && response.map.get(2n)===contract.get(1n),"application_contract_binding");
  for (const [id,value] of Object.entries(schema.application_headers.contract_variants[variant.request])) {
    requireThat(contract.get(BigInt(id))===BigInt(value),"application_contract_variant");
  }
  const bytes=captureApplicationBytes(payload,Number(response.map.get(3n)));
  requireThat(BigInt(bytes.length)===response.map.get(3n),"application_payload_length");
  const code=response.map.get(fieldID(schema,"ApplicationHeader","application_error_code"));
  const catalog=contract.get(fieldID(schema,"ServiceContract","application_error_catalog"));
  const definition=catalog.find(entry=>entry.get(fieldID(schema,"ErrorDefinition","code"))===code);
  const classification=definition===undefined ? "unknown_application_error"
    : BigInt(bytes.length)>definition.get(fieldID(schema,"ErrorDefinition","max_payload_bytes")) ? "application_result_decode_failed" : "known_application_error";
  // Metadata decision only, not a typed value or application-codec result.
  // Unknown payload and execution/reference facts stay with the original owner;
  // no branch closes a Session, grants a retry or re-executes the operation.
  return Object.freeze({classification,code});
}
