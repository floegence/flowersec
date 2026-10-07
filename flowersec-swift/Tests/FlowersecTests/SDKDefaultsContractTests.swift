import Foundation
import Testing

@testable import Flowersec

struct SDKDefaultsContractTests {
  @Test func publicProxyLimitsUseSharedDefaults() throws {
    let limits = try ProxyClientLimits()
    #expect(limits.maximumMetadataBytes == FlowersecSDKDefaults.Proxy.maximumMetadataBytes)
    #expect(limits.maximumChunkBytes == FlowersecSDKDefaults.Proxy.maximumChunkBytes)
    #expect(limits.maximumBodyBytes == FlowersecSDKDefaults.Proxy.maximumBodyBytes)
    #expect(limits.maximumWebSocketFrameBytes == FlowersecSDKDefaults.Proxy.maximumWebSocketFrameBytes)
  }

  @Test func currentRuntimeDefaultsMatchSharedManifest() throws {
    let root = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent()
    let data = try Data(contentsOf: root.appending(path: "stability/sdk_defaults.json"))
    let document = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    let actual: [String: Double] = [
      "transport.connect_timeout_ms": Double(FlowersecSDKDefaults.Transport.connectTimeoutMilliseconds),
      "transport.handshake_timeout_ms": Double(FlowersecSDKDefaults.Transport.handshakeTimeoutMilliseconds),
      "proxy.max_metadata_bytes": Double(FlowersecSDKDefaults.Proxy.maximumMetadataBytes),
      "proxy.max_concurrent_streams": Double(FlowersecSDKDefaults.Proxy.maximumConcurrentStreams),
      "proxy.max_chunk_bytes": Double(FlowersecSDKDefaults.Proxy.maximumChunkBytes),
      "proxy.max_body_bytes": Double(FlowersecSDKDefaults.Proxy.maximumBodyBytes),
      "proxy.max_ws_frame_bytes": Double(FlowersecSDKDefaults.Proxy.maximumWebSocketFrameBytes),
      "proxy.default_timeout_ms": Double(FlowersecSDKDefaults.Proxy.defaultTimeoutMilliseconds),
      "proxy.max_timeout_ms": Double(FlowersecSDKDefaults.Proxy.maximumTimeoutMilliseconds),
      "connection_controller.initial_delay_ms": Double(milliseconds(FlowersecSDKDefaults.ConnectionController.initialDelay)),
      "connection_controller.max_delay_ms": Double(milliseconds(FlowersecSDKDefaults.ConnectionController.maximumDelay)),
      "connection_controller.factor": Double(FlowersecSDKDefaults.ConnectionController.multiplier),
      "connection_controller.jitter_ratio": 0,
    ]
    // Each SDK checks the defaults consumed by its current runtime. Signed
    // credits, stream counts and RPC admission limits have no fallback here.
    for (name, value) in actual {
      let components = name.split(separator: ".")
      let section = try #require(document[String(components[0])] as? [String: Any])
      let expected = try #require(section[String(components[1])] as? NSNumber)
      #expect(value == expected.doubleValue, "Shared default drift: \(name)")
    }
  }
  private func milliseconds(_ duration: Duration) -> Int {
    let components = duration.components
    return Int(components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000)
  }
}
