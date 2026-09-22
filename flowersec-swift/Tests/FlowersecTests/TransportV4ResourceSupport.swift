import Foundation
@testable import Flowersec

// Independent test-only arithmetic over trusted complete declarations. This
// does not reserve resources, register transfers, or establish provider limits.
struct V4ResourceReference {
  let keys, bindings, boundaries, dimensions, components, features: [String]
  let maximum: UInt64

  init() throws {
    let spec = try JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.resourceCompositionRegistryJSON.utf8))
    let cbor = try JSONDecoder().decode(V4JSON.self, from: Data(TransportV4Registry.cborRegistryJSON.utf8))
    func names(_ field: String) -> [String] { spec[field].array!.map { $0.text! } }
    keys = names("owner_key_fields"); bindings = names("binding_fields")
    boundaries = names("control_boundaries"); dimensions = names("dimensions"); components = names("base_components")
    features = cbor["field_registries"]["feature_registry"].object!.keys.sorted()
    maximum = UInt64(spec["quantity_max"].text!)!
  }

  private struct Charge {
    let key, binding: Data
    let boundary: String
    let vector: [String: UInt64]
  }
  private func object(_ input: V4JSON, _ allowed: [String], _ required: [String]) throws -> [String: V4JSON] {
    guard let value = input.object else { throw V4CBORFailure("resource_object") }
    guard value.keys.allSatisfy({ allowed.contains($0) }) else { throw V4CBORFailure("resource_field") }
    guard required.allSatisfy({ value[$0] != nil }) else { throw V4CBORFailure("resource_missing_field") }
    return value
  }
  private func array(_ input: V4JSON, _ limit: UInt64) throws -> [V4JSON] {
    guard let values = input.array else { throw V4CBORFailure("resource_array") }
    guard UInt64(values.count) <= limit else { throw V4CBORFailure("resource_reference_limit") }
    return values
  }
  // Swift String equality normalizes canonical equivalents. Real owner keys
  // must use the exact original UTF-8 tuple, including each component length.
  private func tuple(_ parts: [String]) -> Data {
    var result = Data()
    for part in parts {
      let bytes = Data(part.utf8), length = UInt64(bytes.count)
      for shift in stride(from: 56, through: 0, by: -8) { result.append(UInt8(truncatingIfNeeded: length >> shift)) }
      result.append(bytes)
    }
    return result
  }
  private func charge(_ input: V4JSON) throws -> Charge {
    let fields = keys + bindings + ["control_boundary", "vector"]
    let value = try object(input, fields, fields)
    func identity(_ fields: [String]) throws -> [String] {
      try fields.map { name in
        guard let text = value[name]?.text, !text.isEmpty, text.utf16.count <= 256 else { throw V4CBORFailure("resource_identity") }
        return text
      }
    }
    let key = try tuple(identity(keys))
    var binding = try identity(bindings)
    guard let boundary = value["control_boundary"]?.text, boundaries.contains(boundary) else { throw V4CBORFailure("resource_control_boundary") }
    binding.append(boundary)
    let vector = try object(value["vector"]!, dimensions, dimensions)
    var amounts: [String: UInt64] = [:]
    for dimension in dimensions {
      guard let text = vector[dimension]?.text, !text.isEmpty, text.utf8.count <= 20,
            text.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }), text == "0" || text.first != "0",
            let n = UInt64(text), n <= maximum else { throw V4CBORFailure("resource_quantity") }
      amounts[dimension] = n; binding.append(text)
    }
    return Charge(key: key, binding: tuple(binding), boundary: boundary, vector: amounts)
  }
  private func zero() -> [String: [String: UInt64]] {
    Dictionary(uniqueKeysWithValues: boundaries.map { ($0, Dictionary(uniqueKeysWithValues: dimensions.map { ($0, 0) })) })
  }
  func minimum(_ input: V4JSON) throws -> [String: [String: String]] {
    let fields = ["reference_limit", "base", "features", "legal_selections"]
    let plan = try object(input, fields, fields)
    guard case .uint(let limit) = plan["reference_limit"], limit > 0, limit <= 9_007_199_254_740_991 else { throw V4CBORFailure("resource_reference_limit") }
    let base = try object(plan["base"]!, components, components)
    let featureInputs = try object(plan["features"]!, features, [])
    guard features.count <= 16 else { throw V4CBORFailure("resource_feature_registry") }
    let alternatives = try array(plan["legal_selections"]!, UInt64(1) << features.count)
    guard !alternatives.isEmpty else { throw V4CBORFailure("resource_legal_selections_missing") }
    var seen = Set<[String]>(), selections: [[String]] = []
    for alternative in alternatives {
      var selected: [String] = []
      for value in try array(alternative, UInt64(features.count)) {
        guard let name = value.text, features.contains(name) else { throw V4CBORFailure("resource_feature_unknown") }
        guard !selected.contains(name) else { throw V4CBORFailure("resource_feature_duplicate") }
        selected.append(name)
      }
      selected.sort()
      guard seen.insert(selected).inserted else { throw V4CBORFailure("resource_selection_duplicate") }
      guard selected.allSatisfy({ featureInputs[$0] != nil }) else { throw V4CBORFailure("resource_feature_missing") }
      selections.append(selected)
    }
    var remaining = limit, registered: [Data: Data] = [:]
    func capture(_ input: V4JSON) throws -> [Charge] {
      let values = try array(input, remaining); remaining -= UInt64(values.count)
      return try values.map { value in
        let item = try charge(value)
        guard registered[item.key] == nil || registered[item.key] == item.binding else { throw V4CBORFailure("resource_owner_conflict") }
        registered[item.key] = item.binding; return item
      }
    }
    var common: [Charge] = [], featureCharges: [String: [Charge]] = [:]
    for component in components { common.append(contentsOf: try capture(base[component]!)) }
    for feature in features { if let values = featureInputs[feature] { featureCharges[feature] = try capture(values) } }
    var maximums = zero()
    for selected in selections {
      var union: [Data: Charge] = [:]
      for item in common { union[item.key] = item }
      for feature in selected { for item in featureCharges[feature]! { union[item.key] = item } }
      var totals = zero()
      for item in union.values { for dimension in dimensions {
        let (sum, overflow) = totals[item.boundary]![dimension]!.addingReportingOverflow(item.vector[dimension]!)
        guard !overflow, sum <= maximum else { throw V4CBORFailure("resource_sum_overflow") }
        totals[item.boundary]![dimension] = sum
      } }
      for boundary in boundaries { for dimension in dimensions {
        maximums[boundary]![dimension] = max(maximums[boundary]![dimension]!, totals[boundary]![dimension]!)
      } }
    }
    return maximums.mapValues { $0.mapValues(String.init) }
  }
}
