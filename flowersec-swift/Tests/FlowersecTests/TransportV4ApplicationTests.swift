import Foundation
import XCTest
@testable import Flowersec

final class TransportV4ApplicationTests: XCTestCase {
  private static let reference = try! V4ApplicationReference()
  private static let corpus = try! JSONDecoder().decode(V4JSON.self, from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/application_headers.json")))
  private static let maps = try! JSONDecoder().decode(V4JSON.self, from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json")))
  private var r: V4ApplicationReference { Self.reference }
  private func seed(_ id: String) throws -> Data { try v4RuleHex(XCTUnwrap(Self.maps["vectors"].array!.first { $0["id"].text == id }?["hex"].text)) }
  private func maximum(_ kind: String) throws -> Data { try v4RuleHex(XCTUnwrap(Self.corpus["vectors"].array!.first { $0["accept"].bool == true && $0["kind"].text == kind }?["hex"].text)) }
  private func read(_ name: String, _ bytes: Data) throws -> V4CBORValue { try r.text.wireMap(bytes, schema: name, cap: 8192) }
  private func replace(_ name: String, _ bytes: Data, _ key: String, _ value: V4CBORValue) throws -> Data {
    let id = try r.text.shape.namedField(name, key).0
    guard case .map(var pairs) = try read(name, bytes) else { throw V4CBORFailure("fixture_map") }
    pairs.removeAll { if case .uint(let key) = $0.key { return key == id }; return false }; pairs.append(.init(key: .uint(id), value: value))
    pairs.sort { if case .uint(let a) = $0.key, case .uint(let b) = $1.key { return a < b }; return false }
    return V4CBORValue.map(pairs).encoded()
  }
  private func hset(_ bytes: Data, _ key: String, _ value: V4CBORValue) throws -> Data { try replace("ApplicationHeader", bytes, key, value) }
  private func hash(_ name: String, _ key: String, _ bytes: Data) throws -> Data { try r.hash(name, args: [key: .bytes(bytes)]) }
  private func pair(_ requestKind: String, _ responseKind: String, length: UInt64 = 0, limit: UInt64 = 0) throws -> (Data, Data) {
    var request = try maximum(requestKind)
    if try r.text.shape.namedValue("ApplicationHeader", read("ApplicationHeader", request), "response_limit_bytes") != nil { request = try hset(request, "response_limit_bytes", .uint(limit)) }
    return try (request, hset(maximum(responseKind), "payload_length", .uint(length)))
  }
  private func execution(_ kind: String, payload: Data = Data([1, 2, 3])) throws -> (Data, Data) {
    let suffix = kind == "execution_notify" ? "notify_execution" : kind == "execution_stream_request" ? "stream_execution" : "unary_execution"
    let contract = try seed("service_" + suffix), definition = try read("ServiceContract", contract)
    var header = try maximum(kind)
    header = try hset(header, "type_id", r.field("ServiceContract", definition, "type_id"))
    header = try hset(header, "response_limit_bytes", r.field("ServiceContract", definition, "max_response_bytes"))
    header = try hset(header, "payload_length", .uint(UInt64(payload.count)))
    header = try hset(header, "service_contract_digest", .bytes(hash("service_contract_digest", "contract", contract)))
    header = try hset(header, "request_digest", .bytes(r.executionDigest(header, contract: contract, payload: payload)))
    return (header, contract)
  }
  private func rejects(_ code: String? = nil, file: StaticString = #filePath, line: UInt = #line, _ operation: () throws -> Void) {
    XCTAssertThrowsError(try operation(), file: file, line: line) { error in
      XCTAssertTrue(error is V4CBORFailure, "unexpected failure \(error)", file: file, line: line)
      if let code { XCTAssertEqual((error as? V4CBORFailure)?.code, code, file: file, line: line) }
    }
  }

  // v4.swift_application.corpus
  func testCompleteHeaderCorpus() throws {
    XCTAssertEqual(Self.maps["schema_sha256"].text, TransportV4Registry.schemaSHA256)
    XCTAssertEqual(Self.corpus["schema_revision"].text, Self.maps["schema_revision"].text)
    let vectors = Self.corpus["vectors"].array!; XCTAssertEqual(vectors.count, 589)
    var kinds = Set<String>(), negative = 0
    for vector in vectors {
      let bytes = try v4RuleHex(XCTUnwrap(vector["hex"].text))
      if vector["accept"].bool == true {
        let header = try r.header(bytes); kinds.insert(header.kind)
        XCTAssertEqual(header.kind, vector["kind"].text); XCTAssertEqual(header.value.encoded(), bytes)
        XCTAssertEqual(UInt64(bytes.count), r.kinds[header.kind]!["max_encoded_bytes"].uint)
      } else {
        negative += 1; let expected = vector["expected_error"].text!
        rejects(expected.hasPrefix("application_") ? expected : nil) { _ = try r.header(bytes) }
      }
    }
    XCTAssertEqual(negative, 558); XCTAssertEqual(kinds, Set(r.kinds.keys))
    rejects("application_constant") { _ = try r.header(hset(maximum("execution_notify"), "response_limit_bytes", .uint(1))) }
  }

  // v4.swift_application.response_binding
  func testOriginalResponseBindings() throws {
    for (kind, variant) in r.kinds {
      guard let requestKind = variant["request"].text else { continue }
      let (request, response) = try pair(requestKind, kind); _ = try r.response(request, response)
      for key in ["operation_id", "type_id", "request_digest", "service_contract_digest", "control_serial"] {
        guard let value = try r.text.shape.namedValue("ApplicationHeader", read("ApplicationHeader", response), key) else { continue }
        let replacement: V4CBORValue
        if case .uint(let n) = value { replacement = .uint(n - 1) } else { replacement = .bytes(Data(repeating: 7, count: 32)) }
        rejects("application_response_binding") { _ = try r.response(request, hset(response, key, replacement)) }
      }
      for key in ["deadline_at_ms", "admission_mode", "response_limit_bytes"] { for n: UInt64 in [0, 1] { rejects("application_fields") { _ = try r.response(request, hset(response, key, .uint(n))) } } }
      for (other, v) in r.kinds where v["request"].text == nil && other != requestKind { rejects("application_response_kind") { _ = try r.response(maximum(other), response) } }
    }
  }

  // v4.swift_application.execution_digest
  func testCompleteExecutionAndLimits() throws {
    let payload = Data([1, 2, 3])
    for kind in V4ApplicationReference.registry["policy"]["execution_requests"].array!.map({ $0.text! }) {
      let (header, contract) = try execution(kind); try r.verifyExecution(header, contract: contract, payload: payload)
      for (key, value): (String, V4CBORValue) in [("deadline_at_ms", .uint(17)), ("admission_mode", .uint(0)), ("operation_id", .bytes(Data(repeating: 0, count: 32)))] {
        rejects("application_request_digest") { try r.verifyExecution(hset(header, key, value), contract: contract, payload: payload) }
      }
      rejects("application_request_digest") { try r.verifyExecution(header, contract: contract, payload: Data([1, 2, 4])) }
      rejects("application_payload_length") { try r.verifyExecution(header, contract: contract, payload: Data()) }
      rejects("application_contract_binding") { _ = try r.executionDigest(hset(header, "type_id", .uint(900)), contract: contract, payload: payload) }
      let changed = try replace("ServiceContract", contract, "request_schema_revision", .text("changed"))
      rejects("application_contract_binding") { try r.verifyExecution(header, contract: changed, payload: payload) }
      let rebound = try hset(header, "service_contract_digest", .bytes(hash("service_contract_digest", "contract", changed)))
      rejects("application_request_digest") { try r.verifyExecution(rebound, contract: changed, payload: payload) }
    }
    let (header, contract) = try execution("execution_unary_request")
    rejects("application_contract_variant") { _ = try r.executionDigest(hset(header, "message_kind", .uint(r.kinds["execution_stream_request"]!["code"].uint!)), contract: contract, payload: payload) }
    for kind in r.kinds.keys where V4ApplicationReference.registry["policy"]["execution_requests"].array!.allSatisfy({ $0.text != kind }) { rejects("application_execution_request") { _ = try r.executionDigest(maximum(kind), contract: contract, payload: payload) } }
    let small = try replace("ServiceContract", contract, "request_max_bytes", .uint(2))
    rejects("application_request_limit") { _ = try r.executionDigest(hset(header, "service_contract_digest", .bytes(hash("service_contract_digest", "contract", small))), contract: small, payload: payload) }
    let limited = try replace("ServiceContract", replace("ServiceContract", contract, "max_response_bytes", .uint(2)), "min_response_limit_bytes", .uint(1))
    let rebound = try hset(header, "service_contract_digest", .bytes(hash("service_contract_digest", "contract", limited)))
    for n: UInt64 in [0, 3] { rejects("application_response_limit") { _ = try r.executionDigest(hset(rebound, "response_limit_bytes", .uint(n)), contract: limited, payload: payload) } }
    for length in [0, 1048576] { let payload = Data(repeating: 0, count: length), (header, contract) = try execution("execution_unary_request", payload: payload); try r.verifyExecution(header, contract: contract, payload: payload) }
  }

  // v4.swift_application.sdk_stop
  func testSDKStopHasOnlyBoundedCode() throws {
    for (kind, variant) in r.kinds where variant["sdk_error"].bool == true {
      for (label, code) in V4ApplicationReference.registry["sdk_error_codes"].object! {
        let body = try r.text.shape.namedMap(V4ApplicationReference.registry["sdk_errors"]["payload_schema"].text!, [("code", .uint(code.uint!))]).encoded()
        let (request, response) = try pair(variant["request"].text!, kind, length: UInt64(body.count))
        let stream = ["execution_stream_sdk_error", "transient_stream_sdk_error"].contains(kind)
        if stream && ["request_message_aborted", "response_output_stopped"].contains(label) {
          rejects("streaming_sdk_error_code") { _ = try r.sdkError(request, response: response, payload: body) }; continue
        }
        if !stream && label == "source_overflow" {
          rejects("application_sdk_error_code") { _ = try r.sdkError(request, response: response, payload: body) }; continue
        }
        let result = try r.sdkError(request, response: response, payload: body)
        XCTAssertEqual(result, .init(code: label)); XCTAssertEqual(Mirror(reflecting: result).children.count, 1)
        for n: UInt64 in [0, 1, 255, 256] { _ = try r.response(request, hset(response, "payload_length", .uint(n))) }
        rejects("application_sdk_error_limit") { _ = try r.response(request, hset(response, "payload_length", .uint(257))) }
        rejects("application_input_size") { _ = try r.sdkError(request, response: response, payload: Data(repeating: 0, count: 257)) }
        rejects("application_payload_length") { _ = try r.sdkError(request, response: response, payload: body.dropLast()) }
        for invalid in ["a10000", "a10019ffff", "a0", "a200010100", "a200010001", "a1180001", "a1000100", "a100"] {
          let raw = try v4RuleHex(invalid); rejects { _ = try r.sdkError(request, response: hset(response, "payload_length", .uint(UInt64(raw.count))), payload: raw) }
        }
        if try r.text.shape.namedValue("ApplicationHeader", read("ApplicationHeader", request), "response_limit_bytes") != nil {
          for (other, v) in r.kinds where v["request"].text == variant["request"].text && v["sdk_error"].bool != true {
            let (req, res) = try pair(variant["request"].text!, other, length: 1); rejects("application_response_limit") { _ = try r.response(req, res) }
          }
        }
      }
    }
    let (request, response) = try pair("transient_unary_request", "transient_unary_response")
    rejects("application_sdk_error_kind") { _ = try r.sdkError(request, response: response, payload: Data()) }
  }

  // v4.swift_application.business_errors
  func testExactBusinessSchemaCatalogAndLimits() throws {
    let schema = try v4RuleHex("a10001"), digest = try hash("business_error_schema_digest", "error_schema", schema)
    let definition = try r.text.shape.namedMap("ErrorDefinition", [("code", .uint(12345)), ("schema_revision", .text("error-1")), ("max_payload_bytes", .uint(2)), ("schema_digest", .bytes(digest))]).encoded()
    try r.matchErrorSchema(definition, registered: schema)
    rejects("application_error_schema_mismatch") { try r.matchErrorSchema(definition, registered: v4RuleHex("a0")) }
    rejects("application_input_size") { try r.matchErrorSchema(definition, registered: Data(repeating: 0, count: 8193)) }
    for semantics in ["execution", "transient"] { for shape in ["unary", "stream"] {
      let contract = try replace("ServiceContract", seed("service_\(shape)_\(semantics)"), "application_error_catalog", .array([read("ErrorDefinition", definition)]))
      try r.matchErrorCatalog(contract, definitions: [definition])
      rejects("application_error_catalog_mismatch") { try r.matchErrorCatalog(contract, definitions: []) }
      rejects("application_error_catalog_size") { try r.matchErrorCatalog(contract, definitions: Array(repeating: definition, count: 65)) }
      for (key, value): (String, V4CBORValue) in [("code", .uint(12346)), ("schema_revision", .text("error-2")), ("max_payload_bytes", .uint(3)), ("schema_digest", .bytes(Data(repeating: 0, count: 32)))] {
        rejects("application_error_catalog_mismatch") { try r.matchErrorCatalog(contract, definitions: [replace("ErrorDefinition", definition, key, value)]) }
      }
      var (request, response) = try pair("\(semantics)_\(shape)_request", "\(semantics)_\(shape)_application_error", length: 2, limit: 4)
      let contractDigest = try hash("service_contract_digest", "contract", contract), type = try r.field("ServiceContract", read("ServiceContract", contract), "type_id")
      request = try hset(hset(request, "service_contract_digest", .bytes(contractDigest)), "type_id", type)
      response = try hset(hset(response, "service_contract_digest", .bytes(contractDigest)), "type_id", type)
      func classify(_ request: Data, _ length: Int, _ code: UInt64) throws -> V4ApplicationBusinessResult {
        try r.businessError(request, response: hset(hset(response, "payload_length", .uint(UInt64(length))), "application_error_code", .uint(code)), contract: contract, payload: Data(repeating: 0, count: length))
      }
      for (length, code, classification): (Int, UInt64, String) in [(2, 12345, "known_application_error"), (3, 12345, "application_result_decode_failed"), (3, 0xffffffff, "unknown_application_error")] { XCTAssertEqual(try classify(request, length, code), .init(classification: classification, code: code)) }
      let valid = try hset(response, "application_error_code", .uint(12345))
      rejects("application_payload_length") { _ = try r.businessError(request, response: valid, contract: contract, payload: Data([0])) }
      rejects("application_input_size") { _ = try r.businessError(request, response: valid, contract: contract, payload: Data(repeating: 0, count: 3)) }
      rejects("application_response_limit") { _ = try classify(request, 5, 12345) }
      let zero = try hset(request, "response_limit_bytes", .uint(0)); _ = try classify(zero, 0, 12345)
      rejects("application_response_limit") { _ = try classify(zero, 1, 12345) }
    } }
  }

  // v4.swift_application.ownership
  func testCapsAndDetachedOutputs() throws {
    let (header, contract) = try execution("execution_unary_request"), payload = Data([1, 2, 3])
    let source = NSMutableData(data: header), decoded = try r.header(Data(referencing: source))
    source.resetBytes(in: NSRange(location: 0, length: source.length)); XCTAssertEqual(decoded.value.encoded(), header); XCTAssertEqual(decoded.bytes, header)
    var returned = decoded.bytes; returned.resetBytes(in: 0..<returned.count); XCTAssertEqual(decoded.value.encoded(), header)
    rejects("application_input_size") { _ = try r.header(Data(repeating: 0, count: 513)) }
    rejects("application_input_size") { _ = try r.executionDigest(header, contract: Data(repeating: 0, count: 8193), payload: payload) }
    rejects("application_input_size") { _ = try r.executionDigest(header, contract: contract, payload: Data(repeating: 0, count: 1048577)) }
  }

  // v4.swift_application.properties
  func test4096HeaderMutations() throws {
    let positives = Self.corpus["vectors"].array!.filter { $0["accept"].bool == true }; var state: UInt32 = 0x235ba919
    func next() -> UInt32 { state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state }
    for _ in 0..<4096 {
      var raw = try v4RuleHex(positives[Int(next()) % positives.count]["hex"].text!)
      let index = raw.startIndex + Int(next()) % raw.count; raw[index] ^= 1 << UInt8(next() % 8); let before = raw
      func attempt() throws -> String {
        do { let header = try r.header(raw); XCTAssertEqual(header.value.encoded(), before); return header.kind }
        catch let failure as V4CBORFailure { return "error:" + failure.code }
      }
      XCTAssertEqual(try attempt(), try attempt()); XCTAssertEqual(raw, before)
    }
  }
}
