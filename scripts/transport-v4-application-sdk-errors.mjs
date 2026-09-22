import {decodeMap, VectorError} from "./transport-v4-codec.mjs";
import {captureApplicationBytes, verifyApplicationResponse} from "./transport-v4-application-headers.mjs";

// Authenticated original channel/reply ownership and message-stop eligibility
// are external gates. This reference only validates exact bytes and bindings.
export function verifyApplicationSDKErrorReference(schema, originalRequest, responseHeader, payload) {
  const response = verifyApplicationResponse(schema, originalRequest, responseHeader);
  if (!schema.application_message_kinds[response.kind].sdk_error) throw new VectorError("application_sdk_error_kind");
  const name = schema.application_sdk_errors.payload_schema;
  const bytes = captureApplicationBytes(payload, schema.frame_maps[name].max_encoded_bytes);
  if (BigInt(bytes.length) !== response.map.get(3n)) throw new VectorError("application_payload_length");
  const map = decodeMap(schema, name, bytes);
  const id = BigInt(Object.entries(schema.frame_maps[name].fields).find(([,field]) => field.name === "code")[0]);
  const code = Object.entries(schema.application_sdk_error_codes).find(([,value]) => BigInt(value) === map.get(id))?.[0];
  if (code === undefined) throw new VectorError("application_sdk_error_code");
  const stream = ["execution_stream_sdk_error", "transient_stream_sdk_error"].includes(response.kind);
  if (stream && ["request_message_aborted", "response_output_stopped"].includes(code)) throw new VectorError("streaming_sdk_error_code");
  if (!stream && schema.application_sdk_errors.stream_only_codes.includes(code)) throw new VectorError("application_sdk_error_code");
  // In particular, an aborted execution request echoes its declared digest;
  // the missing request suffix has not been checked against that digest.
  // No executed/not-executed, admission, retry or result-delivery fact is emitted.
  return Object.freeze({code});
}
