import Flowersec
import Testing
@testable import FlowersecSwiftClientExample

@Test func capabilityOutputUsesCanonicalAppleDescriptor() throws {
  let descriptor = RuntimeCapabilitiesV2.apple
  #expect(descriptor.tuples.isEmpty)
  #expect(
    try renderRuntimeCapabilityV2() == """
      descriptor=\(String(decoding: descriptor.canonicalJSON(), as: UTF8.self))
      tuple_count=0
      digest=\(descriptor.digestHex())

      """)
}
