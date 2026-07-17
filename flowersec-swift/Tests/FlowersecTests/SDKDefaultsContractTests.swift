import Foundation
import Testing
@testable import Flowersec

struct SDKDefaultsContractTests {
  @Test func defaultsMatchSharedStabilityManifest() throws {
    let root = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let data = try Data(contentsOf: root.appending(path: "stability/sdk_defaults.json"))
    let document = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])

    #expect(milliseconds(FlowersecSDKDefaults.Transport.connectTimeout) == number(document, "transport", "connect_timeout_ms"))
    #expect(milliseconds(FlowersecSDKDefaults.Transport.handshakeTimeout) == number(document, "transport", "handshake_timeout_ms"))
    #expect(FlowersecSDKDefaults.E2EE.maxRecordBytes == number(document, "e2ee", "max_record_bytes"))
    #expect(FlowersecSDKDefaults.Yamux.maxActiveStreams == number(document, "yamux", "max_active_streams"))
    #expect(FlowersecSDKDefaults.Yamux.maxStreamWriteQueueBytes == number(document, "yamux", "max_stream_write_queue_bytes"))
    #expect(FlowersecSDKDefaults.RPC.maxConcurrentRequests == number(document, "rpc", "max_concurrent_requests"))
    #expect(FlowersecSDKDefaults.Controlplane.maxResponseBodyBytes == number(document, "controlplane", "max_response_body_bytes"))
    #expect(FlowersecSDKDefaults.Proxy.maxBodyBytes == number(document, "proxy", "max_body_bytes"))
    #expect(FlowersecSDKDefaults.Reconnect.maxAttempts == number(document, "reconnect", "max_attempts"))
  }

  private func number(_ document: [String: Any], _ section: String, _ key: String) -> Int {
    let values = document[section] as! [String: Any]
    return values[key] as! Int
  }

  private func milliseconds(_ duration: Duration) -> Int {
    let components = duration.components
    return Int(components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000)
  }
}
