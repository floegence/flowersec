// Stateless schema/vector reference only. This does not admit an OPEN, invoke
// application code, claim I/O ownership or qualify SDK resource accounting.
import { decodeCBOR, decodeMap, encodeCBOR, mapFromNames, validateMap, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";

const owned = bytes => { const result = Buffer.allocUnsafeSlow(bytes.length); bytes.copy(result); return result; };

export function decodeStreamMetadata(schema, bytes) {
  if (!Buffer.isBuffer(bytes)) throw new VectorError("field_type");
  if (bytes.length === 0) return {schema:undefined, value:undefined};
  if (bytes.length > schema.frame_maps.StreamMetadata.max_encoded_bytes) throw new VectorError("map_size");
  // Both registered shells share the fixed IDs and text-key values grammar.
  // Parse once, then select the exact schema from the original namespace.
  const value = decodeCBOR(bytes, {schema,name:"StreamMetadata"});
  if (!(value instanceof Map)) throw new VectorError("map_type");
  const namespaceID = BigInt(Object.entries(schema.frame_maps.StreamMetadata.fields).find(([,field]) => field.name === "namespace")[0]);
  const typedNamespace = Object.values(schema.frame_maps.TypedMessageMetadata.fields).find(field => field.name === "namespace").const;
  const name = value.get(namespaceID) === typedNamespace ? "TypedMessageMetadata" : "StreamMetadata";
  validateMap(schema,name,value);
  return {schema:name,value};
}

export function composeTypedMetadata(schema, definition, application) {
  const result = evaluateDomain(schema,"typed_message_definition_digest",{definition});
  if (!Buffer.isBuffer(application)) throw new VectorError("field_type");
  if (application.length > 0) decodeMap(schema,"StreamMetadata",application);
  const fields = Object.values(schema.frame_maps.TypedMessageMetadata.fields);
  const value = mapFromNames(schema,"TypedMessageMetadata",{
    namespace:fields.find(field => field.name === "namespace").const,
    version:fields.find(field => field.name === "version").const,
    values:{definition:{$bytes:result.output_hex},application:{$bytes:application.toString("hex")}},
  });
  const bytes = encodeCBOR(value);
  decodeMap(schema,"TypedMessageMetadata",bytes);
  return owned(bytes);
}

export function verifyTypedMetadata(schema, bytes, expectedDefinition) {
  const expected = evaluateDomain(schema,"typed_message_definition_digest",{definition:expectedDefinition});
  const decoded = decodeStreamMetadata(schema,bytes);
  if (decoded.schema !== "TypedMessageMetadata") throw new VectorError("typed_metadata_required");
  const valuesID = BigInt(Object.entries(schema.frame_maps.TypedMessageMetadata.fields).find(([,field]) => field.name === "values")[0]);
  const values = decoded.value.get(valuesID);
  if (!values.get("definition").equals(Buffer.from(expected.output_hex,"hex"))) throw new VectorError("typed_definition_mismatch");
  return owned(values.get("application"));
}
