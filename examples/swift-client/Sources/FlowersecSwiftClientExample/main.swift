import Flowersec
import Foundation

private struct PingRequest: Codable, Sendable {}
private struct PingResponse: Codable, Sendable { var ok: Bool }

@main
private enum FlowersecSwiftClientExample {
  static func main() async throws {
    guard let rawBaseURL = ProcessInfo.processInfo.environment["FSEC_CONTROLPLANE_BASE_URL"],
      let baseURL = URL(string: rawBaseURL)
    else {
      throw CocoaError(.fileReadNoSuchFile)
    }
    let endpointID = ProcessInfo.processInfo.environment["FSEC_ENDPOINT_ID"] ?? "server-1"
    let artifact = try await Controlplane.requestConnectArtifact(
      ArtifactRequestOptions(
        baseURL: baseURL,
        endpointID: endpointID,
        traceID: "swift-install-example"
      )
    )
    let origin = ProcessInfo.processInfo.environment["FSEC_ORIGIN"]
      ?? "http://127.0.0.1:5173"
    let client = try await Flowersec.connect(
      artifact,
      options: ConnectOptions(
        origin: origin,
        transportSecurityPolicy: .allowPlaintextForLoopback,
        liveness: .disabled
      )
    )

    let ping: PingResponse = try await client.rpc.call(1, PingRequest())
    guard ping.ok else { throw FlowersecRPCError(code: 500, message: "Ping was not acknowledged") }

    let stream = try await client.openStream(kind: "echo")
    let payload = Data("flowersec-swift-example".utf8)
    try await stream.write(payload)
    let echoed = try await stream.readExact(payload.count)
    print("stream=\(String(decoding: echoed, as: UTF8.self))")
    await stream.close()
    _ = try await client.probeLiveness(timeout: .seconds(2))

    let proxy = try ProxyClient(route: client)
    let response = try await proxy.request(.get("/http"))
    print("http_status=\(response.status) body=\(String(decoding: response.body, as: UTF8.self))")
    let webSocket = try await proxy.openWebSocket(path: "/ws")
    try await webSocket.send(ProxyWebSocketFrame(operation: .text, payload: payload))
    print("websocket=\(try await webSocket.receive())")
    try await webSocket.close(reason: "done")
    await client.close()
  }
}
