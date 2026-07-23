import Flowersec
import Foundation

func renderRuntimeCapabilityV2() throws -> String {
  let descriptor = RuntimeCapabilitiesV2.apple
  return """
    descriptor=\(String(decoding: try descriptor.canonicalJSON(), as: UTF8.self))
    tuple_count=\(descriptor.tuples.count)
    digest=\(try descriptor.digestHex())

    """
}

@main
private enum FlowersecSwiftClientExample {
  static func main() async throws {
    print(try renderRuntimeCapabilityV2(), terminator: "")
    guard let artifactPath = ProcessInfo.processInfo.environment["FSEC_ARTIFACT_V2_PATH"] else {
      return
    }
    let artifact = try parseArtifactV2(Data(contentsOf: URL(fileURLWithPath: artifactPath)))
    let lease = ArtifactLeaseV2(artifact: artifact, commitSpend: {})
    let session = try await ConnectorV2(lease: lease).connect()
    await session.close()
  }
}
