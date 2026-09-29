import { describe, expect, test } from "vitest";
import { applyRawStreamMetadataContract, captureRawStreamMetadataContract, createStreamMetadataEnvelope, StreamMetadataError } from "./streamMetadata.js";

describe("RawStreamMetadataContract", () => {
  test("projects fixed JSON fields while retaining the original bytes", () => {
    const metadata = createStreamMetadataEnvelope("code/http_v1", 1, { method: new TextEncoder().encode(JSON.stringify("GET")), secure: new TextEncoder().encode("true") });
    const contract = captureRawStreamMetadataContract({ contractID: "http-v1", namespace: "code/http_v1", version: 1, codec: "application/json",
      fields: [{ name: "method", type: "string", required: true }, { name: "secure", type: "boolean", required: true }] });
    const projected = applyRawStreamMetadataContract(metadata, contract!);
    expect(projected.descriptorValues()).toEqual({ method: "GET", secure: true });
    expect(projected.encoded()).toEqual(metadata.encoded());
  });

  test("rejects unknown or incorrectly typed fields", () => {
    const metadata = createStreamMetadataEnvelope("code/http_v1", 1, { method: new TextEncoder().encode(JSON.stringify(7)) });
    const contract = captureRawStreamMetadataContract({ contractID: "http-v1", namespace: "code/http_v1", version: 1, codec: "application/json",
      fields: [{ name: "method", type: "string", required: true }] });
    expect(() => applyRawStreamMetadataContract(metadata, contract!)).toThrow(StreamMetadataError);
  });

  test("counts decoded strings by UTF-8 bytes", () => {
    const metadata = createStreamMetadataEnvelope("code/http_v1", 1, { value: new TextEncoder().encode(JSON.stringify("😀")) });
    const contract = captureRawStreamMetadataContract({ contractID: "http-v1", namespace: "code/http_v1", version: 1, codec: "application/json",
      fields: [{ name: "value", type: "string", required: true }], maxDecodedBytes: 3 });
    expect(() => applyRawStreamMetadataContract(metadata, contract!)).toThrow(StreamMetadataError);
  });

  test("counts projection field names and primitive widths", () => {
    const metadata = createStreamMetadataEnvelope("code/http_v1", 1, {
      method: new TextEncoder().encode(JSON.stringify("GET")),
      secure: new TextEncoder().encode("true"),
    });
    const contract = captureRawStreamMetadataContract({ contractID: "http-v1", namespace: "code/http_v1", version: 1, codec: "application/json",
      fields: [{ name: "method", type: "string", required: true }, { name: "secure", type: "boolean", required: true }], maxDecodedBytes: 10 });
    // method (6 bytes) + GET (3) + secure (6) + boolean (1) exceeds 10.
    expect(() => applyRawStreamMetadataContract(metadata, contract!)).toThrow(StreamMetadataError);
  });
});
