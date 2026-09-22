import CoreFoundation
import Foundation
@testable import Flowersec

// Independent test-only costs. Actual owners, complete admission and physical
// memory remain separate. JSON numbers preserve negative/fractional negatives.
struct V4ResourceCostReference {
  private let spec: [String: Any]
  init() throws {
    spec = try JSONSerialization.jsonObject(with: Data(TransportV4Registry.resourceFormulaRegistryJSON.utf8)) as! [String: Any]
  }
  func costs(_ input: Any) throws -> [String: Any] {
    guard let c = input as? [String: Any] else { throw V4CBORFailure("resource_object") }
    let fields = ["max_frame_bytes", "small_auth_slots", "application_profile", "rpc_max_general_outstanding"]
    guard c.keys.allSatisfy({ fields.contains($0) }) else { throw V4CBORFailure("resource_field") }
    guard fields.prefix(3).allSatisfy({ c[$0] != nil }) else { throw V4CBORFailure("resource_missing_field") }
    let codec = spec["codec"] as! [String: Any], app = spec["application"] as! [String: Any], bitmap = spec["bitmap"] as! [String: Any]
    func n(_ object: [String: Any], _ key: String) -> UInt64 { (object[key] as! NSNumber).uint64Value }
    func integer(_ value: Any?, _ min: UInt64, _ max: UInt64, _ error: String) throws -> UInt64 {
      guard let value = value as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID() else { throw V4CBORFailure(error) }
      let d = value.doubleValue
      guard d.isFinite, d.rounded(.towardZero) == d, d >= Double(min), d <= Double(max) else { throw V4CBORFailure(error) }
      return value.uint64Value
    }
    let frame = try integer(c["max_frame_bytes"], 1, n(spec, "max_frame_bytes"), "resource_frame_limit")
    let slots = try integer(c["small_auth_slots"], 0, n(codec, "small_slots_max"), "resource_auth_slots")
    guard let name = c["application_profile"] as? String,
          let p = (app["profiles"] as! [String: Any])[name] as? [String: Any] else { throw V4CBORFailure("resource_application_profile") }
    let rpc = n(p, "rpc_channels"), management = n(p, "management_channels")
    guard (c["rpc_max_general_outstanding"] != nil) == (rpc > 0) else { throw V4CBORFailure("resource_rpc_limit_presence") }
    let limit = spec["rpc_general_limit"] as! [String: Any]
    let k = try rpc > 0 ? integer(c["rpc_max_general_outstanding"], n(limit, "min"), n(limit, "max"), "resource_rpc_limit") : 0
    func mul(_ values: UInt64...) throws -> UInt64 {
      try values.reduce(1) { result, value in
        let (next, overflow) = result.multipliedReportingOverflow(by: value)
        guard !overflow else { throw V4CBORFailure("resource_cost_overflow") }; return next
      }
    }
    func add(_ values: [UInt64]) throws -> UInt64 {
      try values.reduce(0) { result, value in
        let (next, overflow) = result.addingReportingOverflow(value)
        guard !overflow else { throw V4CBORFailure("resource_cost_overflow") }; return next
      }
    }
    let full = try mul(n(codec, "full_body_slots"), n(codec, "buffers_per_slot"), frame)
    let small = try mul(slots, n(codec, "buffers_per_slot"), min(frame, n(codec, "small_body_ceiling_bytes")))
    let bits = try mul(n(spec, "common_scope_ordinals"), n(bitmap, "roles"), n(bitmap, "bits_per_scope"))
    let internalCount = try add([rpc, n(p, "notify_channels")])
    let reply = try rpc > 0 ? add([k, n(app, "query_slots")]) : 0
    let associations = try rpc > 0 ? mul(k, n(app, "fragment_associations_per_general")) : 0
    let promise = try mul(add([internalCount, management]), n(app, "channel_direction_bytes"))
    let amounts: [String: UInt64] = [
      "reply_slots": try mul(reply, n(app, "reply_slot_bytes")),
      "fragment_associations": try mul(associations, n(app, "fragment_association_bytes")),
      "query_reserve": rpc > 0 ? n(app, "query_reserve_bytes") : 0,
      "rpc_error_output": try mul(rpc, n(app, "rpc_error_output_bytes_per_channel")),
      "internal_receive": promise, "internal_send": promise,
    ]
    var bytes = amounts.mapValues(String.init)
    bytes["total"] = try String(add(Array(amounts.values)))
    return [
      "codec_body_bytes": ["full_slots": String(full), "small_slots": String(small), "total": try String(add([full, small]))],
      "permanent_bitmap_bytes": String(bits / n(bitmap, "bits_per_byte")),
      "application_counts": ["internal_active": internalCount, "management_active": management, "reply_slots": reply, "fragment_associations": associations],
      "application_bytes": bytes,
    ]
  }
}
