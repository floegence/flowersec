import Foundation

internal protocol FlowersecBinaryTransport: Sendable {
  func writeBinary(_ data: Data) async throws
  func readBinary() async throws -> Data
  func close() async
}

internal enum FlowersecPath: String, Codable, Equatable, Sendable {
  case auto
  case tunnel
  case direct
}

internal enum FlowersecStage: String, Codable, Equatable, Sendable {
  case validate
  case connect
  case yamux
  case rpc
  case close
}

internal enum DiagnosticCodeDomain: String, Codable, Equatable, Sendable {
  case error
  case event
}

internal enum DiagnosticResult: String, Codable, Equatable, Sendable {
  case ok
  case fail
  case retry
  case skip
}

internal struct DiagnosticEvent: Codable, Equatable, Sendable {
  internal var v: Int
  internal var namespace: String
  internal var path: FlowersecPath
  internal var stage: FlowersecStage
  internal var codeDomain: DiagnosticCodeDomain
  internal var code: String
  internal var result: DiagnosticResult
  internal var elapsedMS: Double
  internal var attemptSeq: Int
  internal var traceID: String?
  internal var sessionID: String?
  internal var resource: String?
  internal var current: Int?
  internal var limit: Int?

  internal init(
    v: Int = 1,
    namespace: String = "connect",
    path: FlowersecPath,
    stage: FlowersecStage,
    codeDomain: DiagnosticCodeDomain,
    code: String,
    result: DiagnosticResult,
    elapsedMS: Double = 0,
    attemptSeq: Int = 1,
    traceID: String? = nil,
    sessionID: String? = nil,
    resource: String? = nil,
    current: Int? = nil,
    limit: Int? = nil
  ) {
    self.v = v
    self.namespace = namespace
    self.path = path
    self.stage = stage
    self.codeDomain = codeDomain
    self.code = code
    self.result = result
    self.elapsedMS = elapsedMS
    self.attemptSeq = attemptSeq
    self.traceID = traceID
    self.sessionID = sessionID
    self.resource = resource
    self.current = current
    self.limit = limit
  }

  private enum CodingKeys: String, CodingKey {
    case v, namespace, path, stage, code, result, resource, current, limit
    case codeDomain = "code_domain"
    case elapsedMS = "elapsed_ms"
    case attemptSeq = "attempt_seq"
    case traceID = "trace_id"
    case sessionID = "session_id"
  }
}

internal enum FlowersecCode: String, Codable, Equatable, Sendable {
  case invalidInput = "invalid_input"
  case dialFailed = "dial_failed"
  case timeout
  case muxFailed = "mux_failed"
  case pingFailed = "ping_failed"
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

  internal static func invalidConnectInfo(
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

  internal static func livenessTimeout(
    _ message: String = "The yamux liveness probe timed out.",
    path: FlowersecPath = .direct
  ) -> FlowersecError {
    FlowersecError(path: path, stage: .yamux, code: .timeout, message: message)
  }

  internal static func closed(path: FlowersecPath = .direct) -> FlowersecError {
    FlowersecError(
      path: path, stage: .close, code: .notConnected,
      message: "The Flowersec session closed."
    )
  }

  internal static func timeout(
    path: FlowersecPath = .direct,
    stage: FlowersecStage = .connect,
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
