import Foundation
import Testing

@testable import Flowersec

@Test
func unversionedOneShotPublicAPICompiles() async throws {
  let connectSource: @Sendable (TransportEnvironment, ConnectionMaterialSource) async throws -> any Session = {
    environment, source in try await connect(environment: environment, source: source)
  }
  let connectMaterial: @Sendable (TransportEnvironment, ConnectionMaterial) async throws -> any Session = {
    environment, material in try await connect(environment: environment, material: material)
  }
  let controller: (TransportEnvironment, ConnectionMaterialSource) throws -> ConnectionController = {
    try ConnectionController(environment: $0, source: $1)
  }
  let proxy: (any Session) throws -> ProxyClient = { try ProxyClient(session: $0) }
  _ = connectSource; _ = connectMaterial; _ = controller; _ = proxy
}

@Test
func retryDispositionsMatchPortableContract() {
  #expect(ConnectError.expired.retryDisposition == .retryable)
  #expect(ConnectError.canceled.code == .connectionFailed)
  #expect(ConnectError.canceled.retryDisposition == .terminal)
  #expect(SessionError.canceled.retryDisposition == .terminal)
  #expect(SessionError.closed.retryDisposition == .retryable)
  #expect(RetryDisposition.retryAfter(1_234_000) == .retryAfter(1_234_000))
}
