import Testing

@testable import FlowersecSwiftClientExample

@Test func exampleDescribesTheOpaqueV2Contract() {
  #expect(
    renderPublicContractV2() == """
      transport=v2
      session_api=opaque

      """)
}
