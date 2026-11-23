import Crypto
import Foundation
import XCTest
@testable import Flowersec

final class TransportV4DomainTests: XCTestCase {
  private static let reference = try! V4TextReference()
  private static let corpus = try! JSONDecoder().decode(V4JSON.self, from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/domains.json")))
  private let cap: UInt64 = 1 << 20
  private func hex(_ value: V4JSON) throws -> Data { try v4RuleHex(XCTUnwrap(value.text)) }
  private func seed(_ name: String) -> V4JSON { Self.corpus["vectors"].array!.first { $0["domain"].text == name && $0["expected_error"].text == nil }! }
  private func args(_ vector: V4JSON) throws -> [String: V4DomainArgument] {
    try vector["inputs"].object!.mapValues { value in
      if value["$bytes"].text != nil { return try .bytes(hex(value["$bytes"])) }
      if let text = value["$uint"].text {
        guard !text.isEmpty, text.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return .invalid }
        return UInt64(text).map(V4DomainArgument.uint) ?? .overflow
      }
      if case .text(let text) = value { return .text(text) }
      if case .uint(let n) = value, n <= 9_007_199_254_740_991 { return .uint(n) }
      return .invalid
    }
  }
  private func context(_ vector: V4JSON) -> V4CBORContext {
    var result = V4CBORContext()
    for (name, value) in vector["context"].object ?? [:] {
      if case .uint(let n) = value { result.limits[name] = n }
      if case .text(let text) = value { result.selectors[name] = text }
    }
    return result
  }
  private func expected(_ vector: V4JSON) throws -> V4DomainOutput {
    let value = vector["result"]
    return try V4DomainOutput(label: hex(value["label_hex"]), input: hex(value["input_hex"]), output: value.object?["output_hex"].map(hex), salt: value.object?["salt_hex"].map(hex), ikm: value.object?["ikm_hex"].map(hex), outputLength: value["output_length"].uint)
  }
  private func rejects(_ code: String? = nil, file: StaticString = #filePath, line: UInt = #line, _ operation: () throws -> Void) {
    XCTAssertThrowsError(try operation(), file: file, line: line) { error in
      XCTAssertTrue(error is V4CBORFailure, "unexpected failure \(error)", file: file, line: line)
      if let code { XCTAssertEqual((error as? V4CBORFailure)?.code, code, file: file, line: line) }
    }
  }

  // v4.swift_domains.corpus
  func testCompleteDomainCorpus() throws {
    let r = Self.reference
    XCTAssertEqual(Self.corpus["schema_sha256"].text, TransportV4Registry.schemaSHA256)
    var positive = 0, negative = 0, covered = Set<String>()
    for vector in Self.corpus["vectors"].array! {
      let input = try args(vector), context = context(vector), saved = input, originalContext = context, name = vector["domain"].text!
      if let error = vector["expected_error"].text {
        negative += 1
        rejects(error.hasPrefix("domain_") ? error : nil) { _ = try r.evaluateDomain(name, args: input, context: context, cap: cap) }
      } else {
        positive += 1; covered.insert(name)
        XCTAssertEqual(try r.evaluateDomain(name, args: input, context: context, cap: cap), try expected(vector), vector["id"].text!)
      }
      XCTAssertEqual(input, saved); XCTAssertEqual(context, originalContext)
    }
    XCTAssertEqual(positive, 107); XCTAssertEqual(negative, 52); XCTAssertEqual(covered.count, 58)
    for domain in V4Domains.registry { XCTAssertTrue(covered.contains(domain["name"].text!)) }
  }

  // v4.swift_domains.signing_inputs
  func testRebuiltSigningInputsAndRealSignatures() throws {
    let r = Self.reference, signatures = try JSONDecoder().decode(V4JSON.self, from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/signatures.json")))
    let key = try Curve25519.Signing.PrivateKey(rawRepresentation: hex(signatures["signing_seed_hex"]))
    var covered = Set<String>()
    for vector in signatures["vectors"].array! where vector["accept"].bool == true && vector["domain_vector"].text != nil {
      let fixture = Self.corpus["vectors"].array!.first { $0["id"].text == vector["domain_vector"].text }!, name = vector["domain"].text!
      let result = try r.evaluateDomain(name, args: args(fixture), context: context(fixture), cap: cap)
      XCTAssertEqual(result.input, try hex(vector["message_hex"])); XCTAssertNil(result.output)
      let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: hex(vector["public_key_hex"]))
      XCTAssertTrue(try publicKey.isValidSignature(hex(vector["signature_hex"]), for: result.input))
      // CryptoKit may randomize newly generated signatures. Input bytes remain exact.
      let generated = try key.signature(for: result.input)
      XCTAssertTrue(publicKey.isValidSignature(generated, for: result.input)); covered.insert(name)
    }
    for domain in V4Domains.registry where domain["operation"].text == "ed25519" { XCTAssertTrue(covered.contains(domain["name"].text!)) }
  }

  // v4.swift_domains.arguments
  func testClosedArgumentsAndContext() throws {
    let r = Self.reference
    rejects("domain_unknown") { _ = try r.evaluateDomain("unknown", args: [:], cap: cap) }
    for domain in V4Domains.registry {
      let name = domain["name"].text!, fixture = seed(name), input = try args(fixture), context = context(fixture), originalContext = context
      var extra = input; extra["extra"] = .invalid
      for invalid in [[:], extra] { rejects("domain_arguments") { _ = try r.evaluateDomain(name, args: invalid, context: context, cap: cap) } }
      for key in input.keys {
        var invalid = input; invalid.removeValue(forKey: key)
        rejects("domain_arguments") { _ = try r.evaluateDomain(name, args: invalid, context: context, cap: cap) }
        invalid[key] = .invalid
        rejects { _ = try r.evaluateDomain(name, args: invalid, context: context, cap: cap) }
      }
      XCTAssertEqual(context, originalContext)
    }
  }

  // v4.swift_domains.projections
  func testExactProjectionsAndOwnedOutputs() throws {
    let r = Self.reference
    var full = 0, excluded = 0, raw = 0
    for vector in Self.corpus["vectors"].array! where vector["expected_error"].text == nil {
      let name = vector["domain"].text!, input = try args(vector), context = context(vector)
      let original = try r.evaluateDomain(name, args: input, context: context, cap: cap)
      let domain = V4Domains.registry.first { $0["name"].text == name }!
      for part in domain["input_schema"]["parts"].array! where part["encoding"].text == "lp-map" {
        let argument = part["name"].text!, schema: String
        if let exact = part["schema_ref"].text { schema = exact }
        else {
          guard case .uint(let selector) = input[part["selector"].text!] else { return XCTFail("selector fixture") }
          schema = part["schema_cases"][String(selector)].text!
        }
        let descriptor = try r.shape.descriptor(schema)
        guard let id = descriptor[part["projection"].text == "without_mac" ? "mac_field" : "signature_field"].uint else { continue }
        guard case .bytes(let bytes) = input[argument], case .map(var pairs) = try r.wireMap(bytes, schema: schema, context: context, cap: cap),
              let at = pairs.firstIndex(where: { if case .uint(let key) = $0.key { return key == id }; return false }),
              case .bytes(var changed) = pairs[at].value else { return XCTFail("projection fixture") }
        changed[changed.startIndex] ^= 1; pairs[at].value = .bytes(changed)
        var mutation = input; mutation[argument] = .bytes(V4CBORValue.map(pairs).encoded())
        let result = try r.evaluateDomain(name, args: mutation, context: context, cap: cap)
        if part["projection"].text == "full" { full += 1; XCTAssertNotEqual(result.input, original.input) }
        else { excluded += 1; XCTAssertEqual(result, original) }
      }
      if ["topup_request_digest", "topup_response_digest"].contains(name) {
        raw += 1; XCTAssertTrue(original.label.isEmpty)
        _ = try r.shape.syntax.decode(original.input, cap: cap).0.get()
      }
      var source = input
      let output = try r.evaluateDomain(name, args: source, context: context, cap: cap)
      for key in Array(source.keys) { if case .bytes(var bytes) = source[key] { bytes.resetBytes(in: 0..<bytes.count); source[key] = .bytes(bytes) } }
      XCTAssertEqual(output, original)
    }
    XCTAssertGreaterThan(full, 0); XCTAssertGreaterThan(excluded, 0); XCTAssertEqual(raw, 2)
  }

  // v4.swift_domains.widths_and_exporters
  func testUInt64AndExactExporterBoundaries() throws {
    let r = Self.reference
    XCTAssertEqual(try v4DomainUnsigned(.uint(UInt64.max), width: 8), Data(repeating: 255, count: 8))
    for width in [1, 4, 8] {
      rejects("domain_integer_range") { _ = try v4DomainUnsigned(.overflow, width: width) }
      rejects("domain_integer_type") { _ = try v4DomainUnsigned(.invalid, width: width) }
      if width < 8 { rejects("domain_integer_range") { _ = try v4DomainUnsigned(.uint(UInt64(1) << (width * 8)), width: width) } }
    }
    for name in ["tls_exporter_raw", "tls_exporter_wt"] {
      let vector = seed(name), context = context(vector); var input = try args(vector)
      let result = try r.evaluateDomain(name, args: input, context: context, cap: cap)
      XCTAssertNil(result.output); XCTAssertEqual(result.outputLength, 32)
      if name == "tls_exporter_raw" { XCTAssertEqual(result.label, Data("EXPORTER-flowersec-v4".utf8)); XCTAssertEqual(result.input.count, 32) }
      else {
        XCTAssertEqual(result.label, Data("EXPORTER-WebTransport".utf8)); XCTAssertEqual(result.input.count, 63)
        XCTAssertEqual(result.input.subdata(in: 8..<31), Data([21]) + Data("EXPORTER-flowersec-v4".utf8) + Data([32]))
        input["connect_stream_id"] = .uint((UInt64(1) << 62) - 4)
        XCTAssertEqual(try r.evaluateDomain(name, args: input, context: context, cap: cap).input.prefix(8), try v4RuleHex("3ffffffffffffffc"))
        for id: UInt64 in [1, (UInt64(1) << 62) - 1, UInt64(1) << 62] {
          input["connect_stream_id"] = .uint(id); rejects { _ = try r.evaluateDomain(name, args: input, context: context, cap: cap) }
        }
      }
    }
  }

  // v4.swift_domains.properties
  func test4096InputMutationProperties() throws {
    let r = Self.reference, positives = Self.corpus["vectors"].array!.filter { $0["expected_error"].text == nil }
    var state: UInt64 = 0x41d041d041d041d0
    func next() -> UInt64 { state = state &* 6364136223846793005 &+ 1442695040888963407; return state ^ (state >> 31) }
    for _ in 0..<4096 {
      let vector = positives[Int(next() % UInt64(positives.count))], context = context(vector), beforeContext = context, name = vector["domain"].text!
      var input = try args(vector); let keys = input.keys.sorted(), key = keys[Int(next() % UInt64(keys.count))]
      switch input[key]! {
      case .bytes(var data) where !data.isEmpty: let at = Int(next() % UInt64(data.count)); data[at] ^= UInt8(truncatingIfNeeded: next()); input[key] = .bytes(data)
      case .uint(let n): input[key] = .uint(n ^ next())
      case .text(let value): input[key] = .text(value + "x")
      default: break
      }
      let before = input
      var output: V4DomainOutput?
      do { output = try r.evaluateDomain(name, args: input, context: context, cap: cap) }
      catch { XCTAssertTrue(error is V4CBORFailure) }
      XCTAssertEqual(input, before); XCTAssertEqual(context, beforeContext)
      if let output {
        XCTAssertEqual(try r.evaluateDomain(name, args: input, context: context, cap: cap), output)
        let snapshot = output
        for key in Array(input.keys) { if case .bytes(var bytes) = input[key] { bytes.resetBytes(in: 0..<bytes.count); input[key] = .bytes(bytes) } }
        XCTAssertEqual(output, snapshot)
      }
    }
  }
}
