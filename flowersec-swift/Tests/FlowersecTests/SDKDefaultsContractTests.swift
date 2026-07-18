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

    let actual: [String: Double] = [
      "transport.connect_timeout_ms": Double(milliseconds(FlowersecSDKDefaults.Transport.connectTimeout)),
      "transport.handshake_timeout_ms": Double(milliseconds(FlowersecSDKDefaults.Transport.handshakeTimeout)),
      "transport.handshake_clock_skew_ms": Double(milliseconds(FlowersecSDKDefaults.Transport.handshakeClockSkew)),
      "e2ee.max_handshake_payload_bytes": Double(FlowersecSDKDefaults.E2EE.maxHandshakePayloadBytes),
      "e2ee.max_record_bytes": Double(FlowersecSDKDefaults.E2EE.maxRecordBytes),
      "e2ee.outbound_record_chunk_bytes": Double(FlowersecSDKDefaults.E2EE.outboundRecordChunkBytes),
      "e2ee.max_inbound_buffered_bytes": Double(FlowersecSDKDefaults.E2EE.maxInboundBufferedBytes),
      "e2ee.max_outbound_buffered_bytes": Double(FlowersecSDKDefaults.E2EE.maxOutboundBufferedBytes),
      "yamux.max_active_streams": Double(FlowersecSDKDefaults.Yamux.maxActiveStreams),
      "yamux.max_inbound_streams": Double(FlowersecSDKDefaults.Yamux.maxInboundStreams),
      "yamux.max_frame_bytes": Double(FlowersecSDKDefaults.Yamux.maxFrameBytes),
      "yamux.preferred_outbound_frame_bytes": Double(FlowersecSDKDefaults.Yamux.preferredOutboundFrameBytes),
      "yamux.max_stream_write_queue_bytes": Double(FlowersecSDKDefaults.Yamux.maxStreamWriteQueueBytes),
      "yamux.max_stream_receive_bytes": Double(FlowersecSDKDefaults.Yamux.maxStreamReceiveBytes),
      "yamux.max_session_receive_bytes": Double(FlowersecSDKDefaults.Yamux.maxSessionReceiveBytes),
      "rpc.max_json_frame_bytes": Double(FlowersecSDKDefaults.RPC.maxJSONFrameBytes),
      "rpc.max_concurrent_requests": Double(FlowersecSDKDefaults.RPC.maxConcurrentRequests),
      "rpc.max_queued_requests": Double(FlowersecSDKDefaults.RPC.maxQueuedRequests),
      "rpc.max_queued_notifications": Double(FlowersecSDKDefaults.RPC.maxQueuedNotifications),
      "controlplane.max_request_body_bytes": Double(FlowersecSDKDefaults.Controlplane.maxRequestBodyBytes),
      "controlplane.max_response_body_bytes": Double(FlowersecSDKDefaults.Controlplane.maxResponseBodyBytes),
      "proxy.max_json_frame_bytes": Double(FlowersecSDKDefaults.Proxy.maxJSONFrameBytes),
      "proxy.max_concurrent_streams": Double(FlowersecSDKDefaults.Proxy.maxConcurrentStreams),
      "proxy.max_chunk_bytes": Double(FlowersecSDKDefaults.Proxy.maxChunkBytes),
      "proxy.max_body_bytes": Double(FlowersecSDKDefaults.Proxy.maxBodyBytes),
      "proxy.max_ws_frame_bytes": Double(FlowersecSDKDefaults.Proxy.maxWSFrameBytes),
      "proxy.default_timeout_ms": Double(FlowersecSDKDefaults.Proxy.defaultTimeoutMilliseconds),
      "proxy.max_timeout_ms": Double(FlowersecSDKDefaults.Proxy.maxTimeoutMilliseconds),
      "reconnect.max_attempts": Double(FlowersecSDKDefaults.Reconnect.maxAttempts),
      "reconnect.initial_delay_ms": Double(FlowersecSDKDefaults.Reconnect.initialDelayMilliseconds),
      "reconnect.max_delay_ms": Double(FlowersecSDKDefaults.Reconnect.maxDelayMilliseconds),
      "reconnect.factor": FlowersecSDKDefaults.Reconnect.factor,
      "reconnect.jitter_ratio": FlowersecSDKDefaults.Reconnect.jitterRatio,
    ]
    let expected = try runtimeLeaves(document)

    #expect(Set(actual.keys) == Set(expected.keys))
    #expect(actual == expected)
  }

  private func runtimeLeaves(_ document: [String: Any]) throws -> [String: Double] {
    var leaves: [String: Double] = [:]
    for (section, rawValues) in document where section != "version" && section != "consumers" {
      let values = try #require(rawValues as? [String: Any])
      for (key, rawValue) in values {
        let value = try #require(rawValue as? NSNumber)
        leaves["\(section).\(key)"] = value.doubleValue
      }
    }
    return leaves
  }

  private func milliseconds(_ duration: Duration) -> Int {
    let components = duration.components
    return Int(components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000)
  }
}
