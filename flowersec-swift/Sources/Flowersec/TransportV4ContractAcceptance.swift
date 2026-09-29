import Foundation

public enum V4ContractRangeField: String, Sendable {
  case historyRetentionMS = "history_retention_ms"
  case resultRetentionMS = "result_retention_ms"
  case minResponseLimitBytes = "min_response_limit_bytes"
  case maxResponseBytes = "max_response_bytes"

  fileprivate var id: Int {
    switch self {
    case .historyRetentionMS: return 14
    case .resultRetentionMS: return 15
    case .minResponseLimitBytes: return 9
    case .maxResponseBytes: return 10
    }
  }
}

public struct V4ContractRange: Sendable, Equatable {
  public let field: V4ContractRangeField
  public let lower: UInt64
  public let upper: UInt64
  public init(field: V4ContractRangeField, lower: UInt64, upper: UInt64) {
    self.field = field
    self.lower = lower
    self.upper = upper
  }
}

public enum V4ContractPolicyFailure: Error, Sendable { case contractPolicyRejected }

// Immutable local declaration; the original binding charges its metadata. A
// fixed tuple avoids retaining a caller's array or a second contract body.
public struct V4ContractAcceptance: Sendable {
  private let ranges: (V4ContractRange?, V4ContractRange?, V4ContractRange?, V4ContractRange?)
  private let count: Int
  private init(_ ranges: (V4ContractRange?, V4ContractRange?, V4ContractRange?, V4ContractRange?), count: Int) {
    self.ranges = ranges
    self.count = count
  }
  public static let exact = V4ContractAcceptance((nil, nil, nil, nil), count: 0)
  public static func bounded(_ ranges: [V4ContractRange]) throws -> Self {
    guard (1...4).contains(ranges.count) else { throw V4ContractPolicyFailure.contractPolicyRejected }
    for (j, range) in ranges.enumerated() {
      let minimum: UInt64 = range.field.id >= 14 ? 1 : 0
      let maximum: UInt64 = range.field.id >= 14 ? UInt64.max : 1 << 20
      guard range.lower >= minimum, range.lower <= range.upper, range.upper <= maximum,
        !ranges[..<j].contains(where: { $0.field == range.field })
      else { throw V4ContractPolicyFailure.contractPolicyRejected }
    }
    return Self((ranges[0], ranges.count > 1 ? ranges[1] : nil,
      ranges.count > 2 ? ranges[2] : nil, ranges.count > 3 ? ranges[3] : nil), count: ranges.count)
  }
  private func range(_ index: Int) -> V4ContractRange? {
    switch index { case 0: return ranges.0; case 1: return ranges.1; case 2: return ranges.2; default: return ranges.3 }
  }

  // Internal composition borrows already admitted, fully validated documents.
  // Authentication, Offer, resources and the actual installation fence remain
  // responsibilities of the original Session binding.
  func check(candidate: V4NamespaceValue, current: V4NamespaceValue?, explicitUpdate: Bool = false) throws {
    guard candidate.schema == "ServiceContract", current == nil || current?.schema == "ServiceContract" else {
      throw V4ContractPolicyFailure.contractPolicyRejected
    }
    let shape = try candidate.u("call_shape")
    for index in 0..<count {
      let range = range(index)!
      guard !([9, 10].contains(range.field.id) && shape == 2),
        let value = try candidate.optional(range.field.rawValue),
        try value.uint() >= range.lower, try value.uint() <= range.upper
      else { throw V4ContractPolicyFailure.contractPolicyRejected }
      if let current {
        guard let value = try current.optional(range.field.rawValue),
          try value.uint() >= range.lower, try value.uint() <= range.upper
        else { throw V4ContractPolicyFailure.contractPolicyRejected }
      }
    }
    guard let current else { return }
    for id in 0..<29 {
      if count == 0 && explicitUpdate && !(0...7).contains(id) && !(20...22).contains(id) && id != 27 { continue }
      var permitted = false
      for index in 0..<count where range(index)!.field.id == id { permitted = true }
      if permitted { continue }
      let old = current.optionalID(id), next = candidate.optionalID(id)
      if let old, let next {
        guard old.raw.elementsEqual(next.raw) else { throw V4ContractPolicyFailure.contractPolicyRejected }
      } else if (old == nil) != (next == nil) { throw V4ContractPolicyFailure.contractPolicyRejected }
    }
  }
}
