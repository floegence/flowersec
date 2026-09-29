import Foundation
import XCTest
@testable import Flowersec

final class TransportV4ContractAcceptanceTests: XCTestCase {
  private func seed(_ id: String) throws -> Data {
    let corpus = try JSONDecoder().decode(V4JSON.self, from: Data(contentsOf: packageRoot().appendingPathComponent("testdata/transport_v4/corpus.json")))
    return try v4RuleHex(XCTUnwrap(corpus["vectors"].array!.first { $0["id"].text == id }?["hex"].text))
  }
  private func change(_ raw: Data, _ id: UInt64, _ replacement: V4CBORValue) throws -> Data {
    let reference = try V4ApplicationReference()
    guard case .map(let fields) = try reference.text.wireMap(raw, schema: "ServiceContract", cap: 8192) else { throw V4CBORFailure("fixture") }
    return V4CBORValue.map(fields.map { pair in
      if case .uint(let key) = pair.key, key == id { return .init(key: pair.key, value: replacement) }
      return pair
    }).encoded()
  }
  func testCanonicalAcceptanceChecksCompleteVariantAndUnlistedFields() throws {
    let registry = try V4NamespaceRegistry()
    func parse(_ raw: Data) throws -> V4NamespaceValue {
      try V4NamespaceDocument(raw, schema: "ServiceContract", bytes: 8192, nodes: 4096, registry: registry).root
    }
    XCTAssertLessThanOrEqual(MemoryLayout<V4ContractAcceptance>.stride, 256)
    let raw = try seed("service_unary_execution"), old = try parse(raw)
    let policy = try V4ContractAcceptance.bounded([.init(field: .historyRetentionMS, lower: 1, upper: UInt64.max)])
    try policy.check(candidate: parse(change(raw, 14, .uint(123456))), current: old)
    let changes: [(UInt64, V4CBORValue)] = [(23, .uint(777)), (13, .uint(0)), (6, .text("other"))]
    for (id, value) in changes {
      XCTAssertThrowsError(try policy.check(candidate: parse(change(raw, id, value)), current: old, explicitUpdate: true))
    }
    XCTAssertThrowsError(try policy.check(candidate: parse(seed("service_unary_transient")), current: nil))
    let updated = try parse(change(raw, 14, .uint(123456)))
    XCTAssertThrowsError(try V4ContractAcceptance.exact.check(candidate: updated, current: old))
    try V4ContractAcceptance.exact.check(candidate: updated, current: old, explicitUpdate: true)
  }
  func testFixedResponseRequiresEqualBoundsAndUnchangedMode() throws {
    let registry = try V4NamespaceRegistry()
    func parse(_ raw: Data) throws -> V4NamespaceValue {
      try V4NamespaceDocument(raw, schema: "ServiceContract", bytes: 8192, nodes: 4096, registry: registry).root
    }
    let raw = try seed("service_unary_fixed_empty"), old = try parse(raw)
    let policy = try V4ContractAcceptance.bounded([
      .init(field: .minResponseLimitBytes, lower: 0, upper: 1024),
      .init(field: .maxResponseBytes, lower: 0, upper: 1024)
    ])
    XCTAssertThrowsError(try policy.check(candidate: parse(change(raw, 10, .uint(1))), current: old))
    let changedMode = try change(change(raw, 8, .uint(1)), 10, .uint(1))
    XCTAssertThrowsError(try policy.check(candidate: parse(changedMode), current: old, explicitUpdate: true))
  }
  func testClosedPolicySchemaRejectsDuplicatesAndInvalidBounds() throws {
    XCTAssertThrowsError(try V4ContractAcceptance.bounded([]))
    let field = V4ContractRange(field: .maxResponseBytes, lower: 0, upper: 100)
    XCTAssertThrowsError(try V4ContractAcceptance.bounded([field, field]))
    XCTAssertThrowsError(try V4ContractAcceptance.bounded([.init(field: .historyRetentionMS, lower: 0, upper: 10)]))
    XCTAssertThrowsError(try V4ContractAcceptance.bounded([.init(field: .maxResponseBytes, lower: 0, upper: 1048577)]))
  }
}
