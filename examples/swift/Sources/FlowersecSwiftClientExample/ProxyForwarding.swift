import Flowersec
import Foundation

// Attach a fixed backend to the already-authenticated application Session.
// The returned registry remains open for the application's other stream kinds.
func makeProxyForwarding(session: any Session, environment: TransportEnvironment,
  origin: URL, numericAddress: String, trustRootsPEM: [Data] = [],
  policy: ProxyForwardingPolicy = ProxyForwardingPolicy()) async throws -> (ProxyServer, StreamHandlers) {
  let limits = try ProxyClientLimits(maximumMetadataBytes: 64 << 10,
    maximumChunkBytes: 64 << 10, maximumBodyBytes: 8 << 20,
    maximumWebSocketFrameBytes: 256 << 10)
  let configuration = NativeProxyUpstreamConfiguration(origin: origin, numericAddress: numericAddress,
    trustRootsPEM: trustRootsPEM, limits: limits, forwardingPolicy: policy)
  let upstream = try await environment.makeNativeProxyUpstream(configuration)
  let server = try ProxyServer(session: session, upstream: upstream, limits: limits, maximumConcurrentStreams: 8)
  let handlers = try StreamHandlers(options: StreamHandlerOptions(maxConcurrentStreams: 8))
  do {
    for kind in ["flowersec-proxy/http1", "flowersec-proxy/ws"] {
      try handlers.handleStream(kind: kind) { incoming in try await server.serve(incoming) }
    }
    return (server, handlers)
  } catch { try? await server.close(); handlers.close(); throw error }
}

// The dispatcher owns its captured Session and joins active application
// callbacks. Proxy close also joins the original upstream socket operations.
func serveProxyForwarding(session: any Session, server: ProxyServer, handlers: StreamHandlers) async throws {
  do {
    try await handlers.serve(session: session)
    try await server.close()
    handlers.close()
  } catch {
    try? await server.close()
    handlers.close()
    throw error
  }
}
