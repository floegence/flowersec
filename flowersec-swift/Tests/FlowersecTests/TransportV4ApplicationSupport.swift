import Foundation
@testable import Flowersec

// Independent test-only byte relations. Real authentication, channel/serial
// owners, admission, codec execution and publication remain external gates.
struct V4ApplicationHeader: Sendable {
  let kind: String, value: V4CBORValue, bytes: Data
}
struct V4ApplicationBusinessResult: Equatable, Sendable {
  let classification: String, code: UInt64
}
struct V4ApplicationSDKResult: Equatable, Sendable { let code: String }

struct V4ApplicationReference: Sendable {
  static let registry = try! JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.applicationHeaderRegistryJSON.utf8))
  let text: V4TextReference
  init() throws { text = try V4TextReference() }
  var kinds: [String: V4JSON] { Self.registry["kinds"].object! }

  private func bound(_ name: String) throws -> UInt64 { try v4RuleInteger(text.shape.descriptor(name)["max_encoded_bytes"]) }
  private func capture(_ input: Data, cap: UInt64) throws -> Data {
    guard UInt64(input.count) <= cap else { throw V4CBORFailure("application_input_size") }
    // Copy exact bytes after the cap; external mutable backing cannot escape.
    return input.withUnsafeBytes { Data($0) }
  }
  private func map(_ name: String, _ input: Data) throws -> V4CBORValue {
    try text.wireMap(capture(input, cap: bound(name)), schema: name, cap: bound(name))
  }
  func field(_ name: String, _ value: V4CBORValue, _ key: String) throws -> V4CBORValue { try text.shape.requiredValue(name, value, key) }
  private func uint(_ value: V4CBORValue) throws -> UInt64 {
    guard case .uint(let n) = value else { throw V4CBORFailure("integer_type") }; return n
  }
  private func same(_ left: V4CBORValue?, _ right: V4CBORValue?) -> Bool { left?.encoded() == right?.encoded() }
  func hash(_ name: String, args: [String: V4DomainArgument]) throws -> Data {
    guard let output = try text.evaluateDomain(name, args: args, cap: bound("ServiceContract")).output else { throw V4CBORFailure("registry_unresolved") }; return output
  }
  func header(_ input: Data) throws -> V4ApplicationHeader {
    let bytes = try capture(input, cap: bound("ApplicationHeader")), value = try text.wireMap(bytes, schema: "ApplicationHeader", cap: bound("ApplicationHeader"))
    let code = try uint(field("ApplicationHeader", value, "message_kind"))
    guard let (kind, variant) = kinds.first(where: { $0.value["code"].uint == code }) else { throw V4CBORFailure("application_kind") }
    guard let fields = variant["fields"].array, case .map(let pairs) = value else { throw V4CBORFailure("registry_unresolved") }
    guard pairs.count == fields.count, try fields.allSatisfy({ try value.field(v4RuleInteger($0)) != nil }) else { throw V4CBORFailure("application_fields") }
    for (key, expected) in variant["constants"].object ?? [:] {
      guard let id = UInt64(key), let actual = value.field(id), try uint(actual) == v4RuleInteger(expected) else { throw V4CBORFailure("application_constant") }
    }
    if variant["sdk_error"].bool == true {
      guard let name = Self.registry["sdk_errors"]["payload_schema"].text else { throw V4CBORFailure("registry_unresolved") }
      guard try uint(field("ApplicationHeader", value, "payload_length")) <= bound(name) else { throw V4CBORFailure("application_sdk_error_limit") }
    }
    return .init(kind: kind, value: value, bytes: bytes)
  }
  func response(_ original: Data, _ input: Data) throws -> V4ApplicationHeader {
    let request = try header(original), result = try header(input), variant = kinds[result.kind]!
    guard variant["request"].text == request.kind else { throw V4CBORFailure("application_response_kind") }
    for key in ["operation_id", "type_id", "request_digest", "service_contract_digest", "control_serial"] {
      guard try same(text.shape.namedValue("ApplicationHeader", request.value, key), text.shape.namedValue("ApplicationHeader", result.value, key)) else { throw V4CBORFailure("application_response_binding") }
    }
    if let limit = try text.shape.namedValue("ApplicationHeader", request.value, "response_limit_bytes"), variant["sdk_error"].bool != true {
      guard try uint(field("ApplicationHeader", result.value, "payload_length")) <= uint(limit) else { throw V4CBORFailure("application_response_limit") }
    }
    return result
  }
  private func contract(_ header: V4ApplicationHeader, requestKind: String, input: Data) throws -> (Data, V4CBORValue) {
    let bytes = try capture(input, cap: bound("ServiceContract")), value = try map("ServiceContract", bytes)
    guard try same(field("ApplicationHeader", header.value, "service_contract_digest"), .bytes(hash("service_contract_digest", args: ["contract": .bytes(bytes)]))),
          try same(field("ApplicationHeader", header.value, "type_id"), field("ServiceContract", value, "type_id")) else { throw V4CBORFailure("application_contract_binding") }
    guard let expected = Self.registry["policy"]["contract_variants"][requestKind].object else { throw V4CBORFailure("application_contract_variant") }
    for (key, expected) in expected {
      guard let id = UInt64(key), try same(value.field(id), .uint(v4RuleInteger(expected))) else { throw V4CBORFailure("application_contract_variant") }
    }
    return (bytes, value)
  }
  func executionDigest(_ input: Data, contract contractInput: Data, payload payloadInput: Data) throws -> Data {
    let header = try header(input)
    guard Self.registry["policy"]["execution_requests"].array?.contains(where: { $0.text == header.kind }) == true else { throw V4CBORFailure("application_execution_request") }
    let (contract, value) = try contract(header, requestKind: header.kind, input: contractInput)
    let payload = try capture(payloadInput, cap: v4RuleInteger(text.shape.namedField("ApplicationHeader", "payload_length").1["max"]))
    guard try UInt64(payload.count) == uint(field("ApplicationHeader", header.value, "payload_length")) else { throw V4CBORFailure("application_payload_length") }
    guard try UInt64(payload.count) <= uint(field("ServiceContract", value, "request_max_bytes")) else { throw V4CBORFailure("application_request_limit") }
    let limit = try uint(field("ApplicationHeader", header.value, "response_limit_bytes"))
    guard try limit >= uint(field("ServiceContract", value, "min_response_limit_bytes")),
          try limit <= uint(field("ServiceContract", value, "max_response_bytes")) else { throw V4CBORFailure("application_response_limit") }
    var args: [String: V4DomainArgument] = ["contract": .bytes(contract), "payload": .bytes(payload)]
    for key in ["message_kind", "operation_id", "type_id", "deadline_at_ms", "admission_mode", "response_limit_bytes"] {
      switch try field("ApplicationHeader", header.value, key) {
      case .uint(let n): args[key] = .uint(n)
      case .bytes(let bytes): args[key] = .bytes(bytes)
      default: throw V4CBORFailure("field_type")
      }
    }
    return try hash("execution_request_digest", args: args)
  }
  func verifyExecution(_ input: Data, contract: Data, payload: Data) throws {
    let header = try header(input), expected = try executionDigest(header.bytes, contract: contract, payload: payload)
    guard try same(field("ApplicationHeader", header.value, "request_digest"), .bytes(expected)) else { throw V4CBORFailure("application_request_digest") }
  }
  func matchErrorSchema(_ definition: Data, registered: Data) throws {
    let value = try map("ErrorDefinition", definition)
    guard let domain = V4Domains.registry.first(where: { $0["name"].text == "business_error_schema_digest" }), let part = domain["input_schema"]["parts"].array?.first else { throw V4CBORFailure("registry_unresolved") }
    let bytes = try capture(registered, cap: v4RuleInteger(part["max_length"]))
    guard try same(field("ErrorDefinition", value, "schema_digest"), .bytes(hash("business_error_schema_digest", args: ["error_schema": .bytes(bytes)]))) else { throw V4CBORFailure("application_error_schema_mismatch") }
  }
  func matchErrorCatalog(_ input: Data, definitions: [Data]) throws {
    let value = try map("ServiceContract", input)
    guard try UInt64(definitions.count) <= v4RuleInteger(text.shape.namedField("ServiceContract", "application_error_catalog").1["max_items"]) else { throw V4CBORFailure("application_error_catalog_size") }
    guard case .array(let catalog) = try field("ServiceContract", value, "application_error_catalog") else { throw V4CBORFailure("field_type") }
    guard catalog.count == definitions.count else { throw V4CBORFailure("application_error_catalog_mismatch") }
    for (entry, definition) in zip(catalog, definitions) {
      guard try entry.encoded() == map("ErrorDefinition", definition).encoded() else { throw V4CBORFailure("application_error_catalog_mismatch") }
    }
  }
  func businessError(_ original: Data, response input: Data, contract contractInput: Data, payload payloadInput: Data) throws -> V4ApplicationBusinessResult {
    let header = try response(original, input), variant = kinds[header.kind]!
    guard variant["application_error"].bool == true, let kind = variant["request"].text else { throw V4CBORFailure("application_error_kind") }
    let (_, value) = try contract(header, requestKind: kind, input: contractInput), length = try uint(field("ApplicationHeader", header.value, "payload_length"))
    let payload = try capture(payloadInput, cap: length)
    guard UInt64(payload.count) == length else { throw V4CBORFailure("application_payload_length") }
    let code = try uint(field("ApplicationHeader", header.value, "application_error_code"))
    guard case .array(let catalog) = try field("ServiceContract", value, "application_error_catalog") else { throw V4CBORFailure("field_type") }
    var classification = "unknown_application_error"
    if let definition = try catalog.first(where: { try uint(field("ErrorDefinition", $0, "code")) == code }) {
      classification = try UInt64(payload.count) > uint(field("ErrorDefinition", definition, "max_payload_bytes")) ? "application_result_decode_failed" : "known_application_error"
    }
    return .init(classification: classification, code: code)
  }
  func sdkError(_ original: Data, response input: Data, payload payloadInput: Data) throws -> V4ApplicationSDKResult {
    let header = try response(original, input)
    guard kinds[header.kind]!["sdk_error"].bool == true else { throw V4CBORFailure("application_sdk_error_kind") }
    guard let name = Self.registry["sdk_errors"]["payload_schema"].text else { throw V4CBORFailure("registry_unresolved") }
    let payload = try capture(payloadInput, cap: bound(name))
    guard try UInt64(payload.count) == uint(field("ApplicationHeader", header.value, "payload_length")) else { throw V4CBORFailure("application_payload_length") }
    let value = try map(name, payload), code = try uint(field(name, value, "code"))
    guard let label = Self.registry["sdk_error_codes"].object?.first(where: { $0.value.uint == code })?.key else { throw V4CBORFailure("application_sdk_error_code") }
    let stream = ["execution_stream_sdk_error", "transient_stream_sdk_error"].contains(header.kind)
    if stream && ["request_message_aborted", "response_output_stopped"].contains(label) { throw V4CBORFailure("streaming_sdk_error_code") }
    if !stream && label == "source_overflow" { throw V4CBORFailure("application_sdk_error_code") }
    // Incomplete execution input only echoes its declared digest; no retry fact.
    return .init(code: label)
  }
}
