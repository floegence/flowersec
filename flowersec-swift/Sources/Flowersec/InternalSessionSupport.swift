import Foundation

internal protocol FlowersecBinaryTransport: Sendable {
  func writeBinary(_ data: Data) async throws
  func readBinary() async throws -> Data
  func close() async
}

internal enum FlowersecPath: String, Codable, Equatable, Sendable {
  case tunnel
  case direct
}

internal enum FlowersecStage: String, Codable, Equatable, Sendable {
  case validate
  case yamux
  case rpc
  case close
}

internal enum FlowersecCode: String, Codable, Equatable, Sendable {
  case invalidInput = "invalid_input"
  case timeout
  case muxFailed = "mux_failed"
  case rpcFailed = "rpc_failed"
  case notConnected = "not_connected"
  case resourceExhausted = "resource_exhausted"
}

internal struct FlowersecError: LocalizedError, Equatable, Sendable {
  internal var path: FlowersecPath
  internal var stage: FlowersecStage
  internal var code: FlowersecCode
  internal var message: String

  internal var errorDescription: String? { message }

  internal static func invalidConfiguration(
    _ message: String, path: FlowersecPath = .direct
  ) -> FlowersecError {
    FlowersecError(path: path, stage: .validate, code: .invalidInput, message: message)
  }

  internal static func invalidYamux(
    _ message: String, path: FlowersecPath = .direct
  ) -> FlowersecError {
    FlowersecError(path: path, stage: .yamux, code: .muxFailed, message: message)
  }

  internal static func invalidRPC(
    _ message: String, path: FlowersecPath = .direct
  ) -> FlowersecError {
    FlowersecError(path: path, stage: .rpc, code: .rpcFailed, message: message)
  }

  internal static func resourceExhausted(
    path: FlowersecPath = .direct, stage: FlowersecStage, _ message: String
  ) -> FlowersecError {
    FlowersecError(path: path, stage: stage, code: .resourceExhausted, message: message)
  }

  internal static func closed(path: FlowersecPath = .direct) -> FlowersecError {
    FlowersecError(
      path: path, stage: .close, code: .notConnected,
      message: "The Flowersec session closed."
    )
  }

  internal static func timeout(
    path: FlowersecPath = .direct,
    stage: FlowersecStage,
    message: String = "The Flowersec request timed out."
  ) -> FlowersecError {
    FlowersecError(path: path, stage: stage, code: .timeout, message: message)
  }

  internal func withPath(_ path: FlowersecPath) -> FlowersecError {
    var error = self
    error.path = path
    return error
  }
}

internal enum FlowersecWire {
  static let jsonFrameMaxBytes = FlowersecSDKDefaults.RPC.maxJSONFrameBytes
}
