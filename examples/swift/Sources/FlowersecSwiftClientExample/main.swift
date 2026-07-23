import Flowersec
import Foundation

func renderPublicContractV2() -> String {
  return """
    transport=v2
    session_api=opaque

    """
}

@main
private enum FlowersecSwiftClientExample {
  static func main() async throws {
    print(renderPublicContractV2(), terminator: "")
    guard let artifactPath = ProcessInfo.processInfo.environment["FSEC_ARTIFACT_V2_PATH"] else {
      return
    }
    let artifact = try parseArtifactV2(Data(contentsOf: URL(fileURLWithPath: artifactPath)))
    let lease = ArtifactLeaseV2(artifact: artifact, commitSpend: {})
    let session = try await ConnectorV2(lease: lease).connect()
    await session.close()
  }
}
