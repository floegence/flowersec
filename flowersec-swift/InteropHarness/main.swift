#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#else
#error("FlowersecInteropHarness requires a POSIX platform")
#endif
import Flowersec
import Foundation
import NIOCore
@preconcurrency import NIOHTTP1
import NIOPosix
@preconcurrency import NIOWebSocket

private func terminateProcess(_ status: Int32) -> Never {
  #if canImport(Darwin)
  Darwin.exit(status)
  #else
  Glibc.exit(status)
  #endif
}

private func closeFileDescriptor(_ descriptor: Int32) -> Int32 {
  #if canImport(Darwin)
  Darwin.close(descriptor)
  #else
  Glibc.close(descriptor)
  #endif
}

private let protocolVersion = 1
private let saturationGateKind = "interop-rpc-saturation-gate"
private let cases = [
  "connect", "rekey", "streams", "rpc", "liveness", "proxy", "reconnect", "limits",
  "diagnostics",
]
private let limitCases = [
  "active_streams", "inbound_streams", "frame", "stream_receive", "session_receive",
  "proxy_body",
]

private struct Command: Decodable, Sendable {
  var version: Int
  var event: String
  var requestID: String
  var profile: String
  var transport: String
  var suite: String
  var deadlineMilliseconds: Int
  var origin: String
  var upstreamURL: URL
  var workload: Workload
  var reconnectArtifacts: [ClientArtifact]
  var limitArtifacts: [LimitArtifact]
  var limitCase: String
  var directInfo: DirectConnectInfo?
  var directCredential: DirectCredential?
  var tunnelGrant: ChannelInitGrant?

  enum CodingKeys: String, CodingKey {
    case version = "v"
    case event
    case requestID = "request_id"
    case profile
    case transport
    case suite
    case deadlineMilliseconds = "deadline_ms"
    case origin
    case upstreamURL = "upstream_url"
    case workload
    case reconnectArtifacts = "reconnect_artifacts"
    case limitArtifacts = "limit_artifacts"
    case limitCase = "limit_case"
    case directInfo = "direct_info"
    case directCredential = "direct_credential"
    case tunnelGrant = "tunnel_grant"
  }
}

private struct LimitArtifact: Decodable, Sendable {
  var name: String
  var directInfo: DirectConnectInfo?
  var tunnelGrant: ChannelInitGrant?

  enum CodingKeys: String, CodingKey {
    case name
    case directInfo = "direct_info"
    case tunnelGrant = "tunnel_grant"
  }

  func clientArtifact() -> ClientArtifact {
    ClientArtifact(directInfo: directInfo, tunnelGrant: tunnelGrant)
  }
}

private struct ClientArtifact: Decodable, Sendable {
  var directInfo: DirectConnectInfo?
  var tunnelGrant: ChannelInitGrant?

  enum CodingKeys: String, CodingKey {
    case directInfo = "direct_info"
    case tunnelGrant = "tunnel_grant"
  }

  func connectArtifact(transport: String) throws -> ConnectArtifact {
    switch (transport, directInfo, tunnelGrant) {
    case ("direct", .some(let info), .none):
      return .direct(info, metadata: .empty)
    case ("tunnel", .none, .some(let grant)):
      return .tunnel(grant, metadata: .empty)
    default:
      throw HarnessError("invalid \(transport) reconnect artifact")
    }
  }
}

private struct DirectCredential: Decodable, Sendable {
  var channelID: String
  var suite: Int
  var psk: String
  var initExpiresAtUnixS: Int64

  enum CodingKeys: String, CodingKey {
    case channelID = "channel_id"
    case suite
    case psk = "e2ee_psk_b64u"
    case initExpiresAtUnixS = "init_expires_at_unix_s"
  }
}

private struct Workload: Decodable, Sendable {
  var streams: StreamWorkload
  var rekey: RekeyWorkload
  var livenessProbes: Int
  var rpc: RPCWorkload
  var proxy: ProxyWorkload
  var reconnectCycles: Int
  var limitChecks: Int

  enum CodingKeys: String, CodingKey {
    case streams, rekey, rpc, proxy
    case livenessProbes = "liveness_probes"
    case reconnectCycles = "reconnect_cycles"
    case limitChecks = "limit_checks"
  }
}

private struct StreamWorkload: Decodable, Sendable {
  var concurrent: Int
  var bytesPerStream: Int
  var chunkBytes: Int
  var slowReaders: Int
  var churn: Int
  var fin: Int
  var reset: Int

  enum CodingKeys: String, CodingKey {
    case concurrent, churn, fin, reset
    case bytesPerStream = "bytes_per_stream"
    case chunkBytes = "chunk_bytes"
    case slowReaders = "slow_readers"
  }
}

private struct RekeyWorkload: Decodable, Sendable {
  var client: Int
  var server: Int
  var concurrent: Int
}

private struct RPCWorkload: Decodable, Sendable {
  var calls: Int
  var notifications: Int
  var cancellations: Int
  var timeouts: Int
  var saturationActive: Int
  var saturationQueued: Int
  var saturationRejected: Int

  enum CodingKeys: String, CodingKey {
    case calls, notifications, cancellations, timeouts
    case saturationActive = "saturation_active"
    case saturationQueued = "saturation_queued"
    case saturationRejected = "saturation_rejected"
  }
}

private struct ProxyWorkload: Decodable, Sendable {
  var httpRequests: Int
  var httpBodyBytes: Int
  var websocketFrames: Int
  var websocketFrameBytes: Int

  enum CodingKeys: String, CodingKey {
    case httpRequests = "http_requests"
    case httpBodyBytes = "http_body_bytes"
    case websocketFrames = "websocket_frames"
    case websocketFrameBytes = "websocket_frame_bytes"
  }
}

private struct Stop: Decodable, Sendable {
  var version: Int
  var event: String
  var requestID: String

  enum CodingKeys: String, CodingKey {
    case version = "v"
    case event
    case requestID = "request_id"
  }
}

private struct Metrics: Encodable, Sendable {
  var sessions = 0
  var rekeys = 0
  var streams = 0
  var slowReaders = 0
  var fins = 0
  var resets = 0
  var bytesWritten = 0
  var bytesRead = 0
  var rpcCalls = 0
  var rpcNotifications = 0
  var rpcCancellations = 0
  var rpcTimeouts = 0
  var rpcQueueRejections = 0
  var limitChecks = 0
  var backpressureChecks = 0
  var httpRequests = 0
  var websocketFrames = 0
  var reconnects = 0
  var livenessProbes = 0
  var resourceRejections = 0

  enum CodingKeys: String, CodingKey {
    case sessions, rekeys, streams
    case slowReaders = "slow_readers"
    case fins, resets, reconnects
    case bytesWritten = "bytes_written"
    case bytesRead = "bytes_read"
    case rpcCalls = "rpc_calls"
    case rpcNotifications = "rpc_notifications"
    case rpcCancellations = "rpc_cancellations"
    case rpcTimeouts = "rpc_timeouts"
    case rpcQueueRejections = "rpc_queue_rejections"
    case limitChecks = "limit_checks"
    case backpressureChecks = "backpressure_checks"
    case httpRequests = "http_requests"
    case websocketFrames = "websocket_frames"
    case livenessProbes = "liveness_probes"
    case resourceRejections = "resource_rejections"
  }
}

private struct Diagnostic: Encodable, Sendable {
  var `case`: String
  var path: String
  var stage: String
  var code: String
}

private struct ClientOutcome: Sendable {
  var metrics: Metrics
  var diagnostics: [Diagnostic]
}

private struct EchoRequest: Codable, Sendable {
  var value: Int
  var notify: Bool
}

private struct EchoResponse: Codable, Sendable {
  var value: Int
}

private struct EmptyRequest: Codable, Sendable {}
private struct OKResponse: Codable, Sendable { var ok: Bool }
private struct HelloNotification: Codable, Sendable { var hello: String }

@main
private enum FlowersecInteropHarness {
  static func main() async {
    var requestID: String?
    do {
      guard CommandLine.arguments.dropFirst() == ["--protocol"] else {
        throw HarnessError("Swift interop harness requires exactly --protocol")
      }
      try writeEvent([
        "v": protocolVersion,
        "event": "hello",
        "language": "swift",
        "roles": ["client", "server"],
        "cases": cases,
      ])
      let command = try readCommand()
      requestID = command.requestID
      try validate(command)
      switch command.event {
      case "run_client":
        let outcome = try await exerciseClient(command)
        try writeResult(
          requestID: command.requestID,
          metrics: outcome.metrics,
          diagnostics: outcome.diagnostics
        )
      case "serve":
        try await serve(command)
      default:
        throw HarnessError("event must be run_client or serve")
      }
    } catch {
      do {
        var fatal: [String: Any] = [
          "v": protocolVersion,
          "event": "fatal",
          "stage": "harness",
          "code": "swift_harness_failed",
          "message": error.localizedDescription,
        ]
        if let requestID { fatal["request_id"] = requestID }
        try writeEvent(fatal)
      } catch let emitError {
        FileHandle.standardError.write(Data("failed to emit Swift fatal: \(emitError)\n".utf8))
      }
      terminateProcess(1)
    }
  }
}

private func exerciseClient(_ command: Command) async throws -> ClientOutcome {
  let options = ConnectOptions(
    origin: command.origin,
    transportSecurityPolicy: .allowPlaintextForLoopback,
    liveness: .disabled
  )
  let client: FlowersecClient
  if command.transport == "direct" {
    client = try await Flowersec.connectDirect(command.directInfo!, options: options)
  } else {
    client = try await Flowersec.connectTunnel(command.tunnelGrant!, options: options)
  }
  do {
    var metrics = try await exerciseConnectedClient(client, command: command)
    var diagnostics = [try diagnosticFor("rpc_queue", path: command.transport)]
    await client.close()
    metrics.sessions = 1
    try await exerciseReconnect(command, metrics: &metrics)
    try await exerciseLimits(command, metrics: &metrics, diagnostics: &diagnostics)
    return ClientOutcome(metrics: metrics, diagnostics: diagnostics)
  } catch {
    await client.close()
    throw error
  }
}

private func exerciseLimits(
  _ command: Command,
  metrics: inout Metrics,
  diagnostics: inout [Diagnostic]
) async throws {
  for artifact in command.limitArtifacts {
    var yamuxLimits = YamuxLimits()
    if artifact.name == "active_streams" {
      yamuxLimits.maxActiveStreams = 2
      yamuxLimits.maxInboundStreams = 1
    }
    let options = ConnectOptions(
      origin: command.origin,
      transportSecurityPolicy: .allowPlaintextForLoopback,
      yamuxLimits: yamuxLimits,
      liveness: .disabled
    )
    let client: FlowersecClient
    switch try artifact.clientArtifact().connectArtifact(transport: command.transport) {
    case .direct(let info, metadata: _):
      client = try await Flowersec.connectDirect(info, options: options)
    case .tunnel(let grant, metadata: _):
      client = try await Flowersec.connectTunnel(grant, options: options)
    }
    do {
      let backpressure = try await exerciseLimitAction(client, name: artifact.name)
      metrics.sessions += 1
      metrics.limitChecks += 1
      if backpressure { metrics.backpressureChecks += 1 } else { metrics.resourceRejections += 1 }
      diagnostics.append(try diagnosticFor(artifact.name, path: command.transport))
      await client.close()
    } catch {
      await client.close()
      throw HarnessError("limit \(artifact.name) failed: \(describe(error))")
    }
  }
}

private func exerciseLimitAction(_ client: FlowersecClient, name: String) async throws -> Bool {
  switch name {
  case "active_streams":
    let held = try await client.openStream(kind: "hold")
    do {
      _ = try await client.openStream(kind: "hold")
      throw HarnessError("active stream limit accepted the second user stream")
    } catch let error as FlowersecError where error.code == .resourceExhausted {
      try await held.reset()
      try await rpcControl(client, typeID: 5)
      return false
    }
  case "inbound_streams", "frame":
    let stream: any FlowersecByteStream
    do {
      stream = try await client.openStream(kind: "hold")
    } catch where isExpectedLimitStreamError(error) {
      return false
    }
    if name == "frame" {
      do {
        try await stream.write(Data(repeating: Character("f").asciiValue!, count: 2048))
      } catch {
        guard isExpectedLimitStreamError(error) else {
          throw HarnessError("frame limit write returned \(describe(error))")
        }
        return false
      }
    }
    do {
      _ = try await withThrowingTaskGroup(of: Data.self) { group in
        group.addTask { try await stream.readExact(1) }
        group.addTask {
          try await Task.sleep(for: .seconds(1))
          throw HarnessError("\(name) stream did not fail before the deadline")
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else {
          throw HarnessError("limit read race ended without a result")
        }
        return result
      }
      throw HarnessError("\(name) stream unexpectedly produced data")
    } catch let error as HarnessError {
      throw error
    } catch where isExpectedLimitStreamError(error) {
      if name == "inbound_streams" { try await rpcControl(client, typeID: 5) }
      return false
    }
  case "stream_receive":
    let stream = try await client.openStream(kind: "hold")
    let completion = AsyncCompletionFlag()
    let write = Task<Result<Void, Error>, Never> {
      do {
        try await stream.write(Data(repeating: Character("b").asciiValue!, count: (256 * 1024) + 1))
        await completion.finish()
        return .success(())
      } catch {
        await completion.finish()
        return .failure(error)
      }
    }
    try await Task.sleep(for: .milliseconds(100))
    if await completion.isFinished {
      _ = await write.value
      throw HarnessError("stream receive boundary did not apply backpressure")
    }
    try await stream.reset()
    switch await write.value {
    case .failure(let error) where isExpectedLimitStreamError(error):
      break
    case .failure(let error):
      throw HarnessError("backpressured write returned \(error.localizedDescription) after reset")
    case .success:
      throw HarnessError("reset released the backpressured write without an error")
    }
    try await rpcControl(client, typeID: 5)
    return true
  case "session_receive":
    let first: any FlowersecByteStream
    let second: any FlowersecByteStream
    do {
      first = try await client.openStream(kind: "hold")
      second = try await client.openStream(kind: "hold")
    } catch where isExpectedLimitStreamError(error) {
      return false
    } catch {
      throw HarnessError("session receive stream setup failed: \(describe(error))")
    }
    let payload = Data(repeating: Character("s").asciiValue!, count: 256 * 1024)
    let firstWrite = Task { try await first.write(payload) }
    let secondWrite = Task { try await second.write(payload) }
    enum TerminationRace: @unchecked Sendable {
      case terminated((any Error)?)
      case timeout
    }
    let termination = await withTaskGroup(of: TerminationRace.self) { group in
      group.addTask { .terminated(await client.terminated()) }
      group.addTask {
        do {
          try await Task.sleep(for: .seconds(1))
          return .timeout
        } catch {
          return .timeout
        }
      }
      let first = await group.next()
      group.cancelAll()
      while await group.next() != nil {}
      return first
    }
    let firstResult = await firstWrite.result
    let secondResult = await secondWrite.result
    let writeFailed: Bool
    switch (firstResult, secondResult) {
    case (.success(_), .success(_)): writeFailed = false
    case (.failure(_), _), (_, .failure(_)): writeFailed = true
    }
    guard writeFailed else {
      throw HarnessError("session receive limit allowed both writes to complete")
    }
    guard let termination, case .terminated(let terminationError) = termination else {
      throw HarnessError("session receive limit did not terminate the session")
    }
    guard let terminationError, isExpectedSessionTermination(terminationError) else {
      throw HarnessError(
        "session receive terminated with \(terminationError?.localizedDescription ?? "no error")"
      )
    }
    return false
  case "proxy_body":
    let proxy = try ProxyClient(route: client)
    do {
      _ = try await proxy.request(
        ProxyHTTPRequest(
          method: "POST",
          path: "/http",
          body: Data(repeating: Character("p").asciiValue!, count: 1025)
        )
      )
      throw HarnessError("proxy body limit unexpectedly accepted the request")
    } catch let error as HarnessError {
      throw error
    } catch ProxyError.remote(let code, _) where code == "request_body_too_large" {
      try await rpcControl(client, typeID: 5)
      return false
    }
  default:
    throw HarnessError("unknown limit case \(name)")
  }
}

private func isExpectedLimitStreamError(_ error: any Error) -> Bool {
  if error is FlowersecStreamResetError { return true }
  guard let error = error as? FlowersecError else { return false }
  return error.code == .resourceExhausted || error.code == .notConnected
}

private func describe(_ error: any Error) -> String {
  if let error = error as? FlowersecError {
    return "path=\(error.path.rawValue) stage=\(error.stage.rawValue) code=\(error.code.rawValue): \(error.localizedDescription)"
  }
  let error = error as NSError
  return "domain=\(error.domain) code=\(error.code): \(error.localizedDescription)"
}

private func isExpectedSessionTermination(_ error: any Error) -> Bool {
  guard let error = error as? FlowersecError else { return false }
  return error.code == .resourceExhausted || error.code == .notConnected
}

private func exerciseReconnect(_ command: Command, metrics: inout Metrics) async throws {
  let artifacts = try command.reconnectArtifacts.map {
    try $0.connectArtifact(transport: command.transport)
  }
  let queue = ReconnectArtifactQueue(artifacts)
  let manager = ReconnectManager()
  let source = ArtifactSource.refreshable { _ in try await queue.next() }
  let config = ReconnectConfig(
    source: source,
    options: ConnectOptions(
      origin: command.origin,
      transportSecurityPolicy: .allowPlaintextForLoopback,
      liveness: .disabled
    ),
    settings: ReconnectSettings(
      enabled: true,
      maxAttempts: 1,
      initialDelay: .zero,
      maxDelay: .zero,
      factor: 1,
      jitterRatio: 0
    )
  )
  do {
    try await manager.connect(config)
    metrics.sessions += 1
    for index in 0..<command.workload.reconnectCycles {
      guard let previous = await manager.state().client else {
        throw HarnessError("reconnect manager has no connected client")
      }
      try await rpcControl(previous, typeID: 6)
      let connected = try await waitForReconnectClient(manager, previous: previous)
      try await rpcEcho(connected, value: index, notify: false)
      metrics.sessions += 1
      metrics.reconnects += 1
    }
    guard let finalClient = await manager.state().client else {
      throw HarnessError("reconnect manager lost the final client")
    }
    try await rpcControl(finalClient, typeID: 5)
    guard await queue.isEmpty else {
      throw HarnessError("reconnect artifact sequence was not consumed exactly")
    }
    await manager.disconnect()
  } catch {
    await manager.disconnect()
    throw error
  }
}

private func waitForReconnectClient(
  _ manager: ReconnectManager,
  previous: FlowersecClient
) async throws -> FlowersecClient {
  for await state in await manager.subscribe() {
    switch state.status {
    case .connected:
      if let client = state.client, client !== previous { return client }
    case .error:
      throw state.error ?? ReconnectError.terminated("Reconnect failed.")
    case .disconnected:
      throw ReconnectError.canceled
    case .connecting:
      continue
    }
  }
  throw ReconnectError.canceled
}

private func exerciseConnectedClient(
  _ client: FlowersecClient,
  command: Command
) async throws -> Metrics {
  var metrics = Metrics()
  let notifications = NotificationCounter()
  let subscription = client.rpc.onNotify(2) { data in
    await notifications.record(data)
  }
  defer { subscription.cancel() }

  for index in 0..<command.workload.rekey.client {
    try await client.rekey()
    metrics.rekeys += 1
    try await rpcEcho(client, value: index, notify: false)
  }
  for _ in 0..<command.workload.rekey.server {
    try await rpcControl(client, typeID: 3)
    metrics.rekeys += 1
  }
  for _ in 0..<command.workload.rekey.concurrent {
    async let local: Void = client.rekey()
    async let remote: Void = rpcControl(client, typeID: 3)
    _ = try await (local, remote)
    metrics.rekeys += 2
  }

  let streamMetrics = try await exerciseStreams(client, workload: command.workload.streams)
  metrics.streams += streamMetrics.streams
  metrics.slowReaders += streamMetrics.slowReaders
  metrics.fins += streamMetrics.fins
  metrics.resets += streamMetrics.resets
  metrics.bytesWritten += streamMetrics.written
  metrics.bytesRead += streamMetrics.read

  for _ in 0..<command.workload.livenessProbes {
    _ = try await client.probeLiveness(timeout: .seconds(2))
    metrics.livenessProbes += 1
  }
  for index in 0..<command.workload.rpc.calls {
    try await rpcEcho(
      client,
      value: index,
      notify: index < command.workload.rpc.notifications
    )
    metrics.rpcCalls += 1
  }
  let queueRejections = try await exerciseRPCSaturation(
    client,
    workload: command.workload.rpc
  )
  metrics.rpcQueueRejections += queueRejections
  metrics.resourceRejections += queueRejections
  metrics.limitChecks += 1
  for _ in 0..<command.workload.rpc.cancellations {
    let task = Task<OKResponse, Error> {
      try await client.rpc.call(4, EmptyRequest(), timeout: .seconds(2))
    }
    task.cancel()
    do {
      _ = try await task.value
      throw HarnessError("RPC cancellation unexpectedly succeeded")
    } catch is CancellationError {
      metrics.rpcCancellations += 1
    }
  }
  for _ in 0..<command.workload.rpc.timeouts {
    do {
      let _: OKResponse = try await client.rpc.call(4, EmptyRequest(), timeout: .milliseconds(1))
      throw HarnessError("RPC timeout unexpectedly succeeded")
    } catch let error as FlowersecError where error.code == .timeout {
      metrics.rpcTimeouts += 1
    }
  }
  try await notifications.waitFor(command.workload.rpc.notifications)
  metrics.rpcNotifications = command.workload.rpc.notifications
  try await exerciseProxy(client, workload: command.workload.proxy, metrics: &metrics)
  try await rpcControl(client, typeID: 5)
  return metrics
}

private struct StreamMetrics: Sendable {
  var streams: Int
  var slowReaders: Int
  var fins: Int
  var resets: Int
  var written: Int
  var read: Int
}

private func exerciseStreams(
  _ client: FlowersecClient,
  workload: StreamWorkload
) async throws -> StreamMetrics {
  var transferred: [(Int, Int, Bool)] = []
  try await withThrowingTaskGroup(of: (Int, Int, Bool).self) { group in
    for index in 0..<workload.concurrent {
      group.addTask {
        let stream = try await client.openStream(kind: "echo")
        let payload = Data(repeating: UInt8(index % 251), count: workload.bytesPerStream)
        var offset = 0
        while offset < payload.count {
          let end = min(payload.count, offset + workload.chunkBytes)
          try await stream.write(payload.subdata(in: offset..<end))
          offset = end
        }
        let slowReader = index < workload.slowReaders
        if slowReader { try await Task.sleep(for: .milliseconds(25)) }
        let echoed = try await stream.readExact(payload.count)
        guard echoed == payload else { throw HarnessError("echo payload mismatch") }
        await stream.close()
        return (payload.count, echoed.count, slowReader)
      }
    }
    for try await result in group { transferred.append(result) }
  }
  var metrics = StreamMetrics(
    streams: transferred.count,
    slowReaders: transferred.filter { $0.2 }.count,
    fins: 0,
    resets: 0,
    written: transferred.reduce(0) { $0 + $1.0 },
    read: transferred.reduce(0) { $0 + $1.1 }
  )
  for _ in 0..<workload.churn {
    let stream = try await client.openStream(kind: "churn")
    do {
      _ = try await stream.readExact(1)
      throw HarnessError("churn stream produced data before FIN")
    } catch let error as HarnessError {
      throw error
    } catch let error as FlowersecError where error.code == .notConnected {
    } catch {
      throw error
    }
    await stream.close()
    metrics.streams += 1
  }
  for _ in 0..<workload.fin {
    let stream = try await client.openStream(kind: "echo")
    await stream.close()
    metrics.streams += 1
    metrics.fins += 1
  }
  for _ in 0..<workload.reset {
    let stream = try await client.openStream(kind: "echo")
    try await stream.reset()
    metrics.streams += 1
    metrics.resets += 1
  }
  return metrics
}

private func exerciseRPCSaturation(
  _ client: FlowersecClient,
  workload: RPCWorkload
) async throws -> Int {
  let total = workload.saturationActive + workload.saturationQueued + workload.saturationRejected
  let gate = SaturationGateWriter(stream: try await client.openStream(kind: saturationGateKind))
  var succeeded = 0
  var rejected = 0
  do {
    try await withThrowingTaskGroup(of: Bool.self) { group in
      for _ in 0..<total {
        group.addTask {
          do {
            let response: OKResponse = try await client.rpc.call(
              7,
              EmptyRequest(),
              timeout: .seconds(5)
            )
            guard response.ok else { throw HarnessError("invalid saturation RPC response") }
            return false
          } catch let error as FlowersecRPCError where error.code == 429 {
            try await gate.release()
            return true
          } catch let error as FlowersecError where error.code == .resourceExhausted {
            try await gate.release()
            return true
          }
        }
      }
      for try await wasRejected in group {
        if wasRejected { rejected += 1 } else { succeeded += 1 }
      }
    }
  } catch {
    do {
      try await gate.cleanup()
    } catch let cleanupError {
      throw HarnessError(
        "RPC saturation failed: \(error.localizedDescription); gate cleanup failed: \(cleanupError.localizedDescription)"
      )
    }
    throw error
  }
  try await gate.requireReleased()
  guard succeeded == workload.saturationActive + workload.saturationQueued,
    rejected == workload.saturationRejected
  else {
    throw HarnessError("RPC saturation got \(succeeded) successes and \(rejected) rejections")
  }
  return rejected
}

private func exerciseProxy(
  _ client: FlowersecClient,
  workload: ProxyWorkload,
  metrics: inout Metrics
) async throws {
  let proxy = try ProxyClient(route: client)
  let body = Data(repeating: Character("p").asciiValue!, count: workload.httpBodyBytes)
  for _ in 0..<workload.httpRequests {
    let response = try await proxy.request(
      ProxyHTTPRequest(method: "POST", path: "/http", body: body)
    )
    guard response.status == 200, response.body == body else {
      throw HarnessError("proxy HTTP response mismatch")
    }
    metrics.httpRequests += 1
  }
  let websocket = try await proxy.openWebSocket(path: "/ws")
  let payload = Data(repeating: Character("w").asciiValue!, count: workload.websocketFrameBytes)
  for _ in 0..<workload.websocketFrames {
    try await websocket.send(ProxyWebSocketFrame(operation: .text, payload: payload))
    let response = try await websocket.receive()
    guard response == ProxyWebSocketFrame(operation: .text, payload: payload) else {
      throw HarnessError("proxy WebSocket response mismatch")
    }
    metrics.websocketFrames += 1
  }
  try await websocket.close(code: nil)
}

private func serve(_ command: Command) async throws {
  let listener: DirectWebSocketServer?
  let session: EndpointSession
  if command.transport == "direct" {
    let credential = command.directCredential!
    let server = try await DirectWebSocketServer.start(expectedOrigin: command.origin)
    listener = server
    try writeEvent([
      "v": protocolVersion,
      "event": "ready",
      "request_id": command.requestID,
      "direct_info": [
        "ws_url": server.url.absoluteString,
        "channel_id": credential.channelID,
        "e2ee_psk_b64u": credential.psk,
        "channel_init_expire_at_unix_s": credential.initExpiresAtUnixS,
        "default_suite": credential.suite,
      ],
    ])
    guard let suite = Suite(rawValue: credential.suite),
      let psk = decodeBase64URL(credential.psk), psk.count == 32
    else { throw HarnessError("invalid direct credential") }
    session = try await Endpoint.acceptDirect(
      transport: try await server.acceptTransport(),
      credential: DirectEndpointCredential(
        channelID: credential.channelID,
        suite: suite,
        psk: psk,
        initExpiresAtUnixS: credential.initExpiresAtUnixS
      ),
      secureTransport: false,
      options: EndpointOptions(
        origin: command.origin,
        transportSecurityPolicy: .allowPlaintextForLoopback,
        yamuxLimits: serverYamuxLimits(command)
      )
    )
  } else {
    listener = nil
    let connection = Task {
      try await Endpoint.connectTunnel(
        grant: command.tunnelGrant!,
        options: EndpointOptions(
          origin: command.origin,
          transportSecurityPolicy: .allowPlaintextForLoopback,
          yamuxLimits: serverYamuxLimits(command)
        )
      )
    }
    try writeEvent([
      "v": protocolVersion,
      "event": "ready",
      "request_id": command.requestID,
    ])
    session = try await connection.value
  }

  let metrics = MetricsStore(initial: Metrics(sessions: 1))
  let completion = CompletionSignal()

  enum Event: @unchecked Sendable {
    case stop(Stop)
    case serviceFinished(Result<Void, Error>)
  }
  let event = await withTaskGroup(of: Event.self, returning: Event.self) { group in
    group.addTask {
      do {
        let stop = try readStop()
        return .stop(stop)
      } catch {
        return .serviceFinished(.failure(error))
      }
    }
    group.addTask {
      do {
        try await runService(
          session,
          command: command,
          metrics: metrics,
          completion: completion
        )
        return .serviceFinished(.success(()))
      } catch {
        return .serviceFinished(.failure(error))
      }
    }
    let first = await group.next()!
    switch first {
    case .stop(let stop):
      guard stop.version == protocolVersion, stop.event == "stop",
        stop.requestID == command.requestID
      else {
        await session.close()
        group.cancelAll()
        while await group.next() != nil {}
        return .serviceFinished(.failure(HarnessError("invalid stop event")))
      }
      var shutdownError: Error?
      if !(await completion.isComplete) {
        let terminal = await session.terminationError()
        if ["frame", "session_receive"].contains(command.limitCase),
          terminal?.code == .resourceExhausted
        {
          await completion.complete()
        } else {
          shutdownError = terminal ?? HarnessError("server workload stopped before completion")
        }
      }
      await session.close()
      group.cancelAll()
      while let remaining = await group.next() {
        if case .serviceFinished(.failure(let error)) = remaining,
          !(error is CancellationError)
        {
          shutdownError = error
        }
      }
      if let shutdownError {
        return .serviceFinished(.failure(shutdownError))
      }
      return first
    case .serviceFinished:
      _ = closeFileDescriptor(STDIN_FILENO)
      await session.close()
    }
    group.cancelAll()
    while await group.next() != nil {}
    return first
  }

  switch event {
  case .stop(let stop):
    _ = stop
  case .serviceFinished(.failure(let error)):
    await session.close()
    if let listener { try await listener.close() }
    throw error
  case .serviceFinished(.success):
    await session.close()
    if let listener { try await listener.close() }
    throw HarnessError("server task ended before stop")
  }
  await session.close()
  if let listener { try await listener.close() }
  await completion.waitForScheduledWork()
  try writeResult(requestID: command.requestID, metrics: await metrics.value, diagnostics: [])
}

private func runService(
  _ session: EndpointSession,
  command: Command,
  metrics: MetricsStore,
  completion: CompletionSignal
) async throws {
  do {
    try await serveSession(
      session,
      command: command,
      metrics: metrics,
      completion: completion
    )
    guard await completion.isComplete else {
      throw HarnessError("server task ended without completing its workload")
    }
    while !Task.isCancelled {
      try await Task.sleep(for: .milliseconds(10))
    }
  } catch {
    if await completion.isComplete {
      do {
        while !Task.isCancelled {
          try await Task.sleep(for: .milliseconds(10))
        }
      } catch is CancellationError {
        return
      }
    }
    await session.close()
    throw error
  }
}

private func serveSession(
  _ session: EndpointSession,
  command: Command,
  metrics: MetricsStore,
  completion: CompletionSignal
) async throws {
  var stage = "rpc_accept"
  do {
    let accepted = try await session.acceptStream()
    guard accepted.kind == "rpc" else { throw HarnessError("first stream must be RPC") }
    let router = RPCRouter()
    let saturation = SaturationGate()
    let rpc = try RPCServer(
      stream: accepted.stream,
      router: router,
      options: RPCServerOptions(
        maxConcurrentRequests: command.workload.rpc.saturationActive,
        maxQueuedRequests: command.workload.rpc.saturationQueued,
        maxQueuedNotifications: command.workload.rpc.saturationQueued
      ),
      path: session.path
    )
    await router.register(1) { (request: EchoRequest) async throws -> EchoResponse in
      if request.notify {
        try await rpc.notify(2, HelloNotification(hello: "world"))
      }
      return EchoResponse(value: request.value)
    }
    await router.register(3) { (_: EmptyRequest) async throws -> OKResponse in
      try await session.rekey()
      await metrics.incrementRekeys()
      return OKResponse(ok: true)
    }
    await router.register(4) { (_: EmptyRequest) async throws -> OKResponse in
      try await Task.sleep(for: .milliseconds(100))
      return OKResponse(ok: true)
    }
    await router.register(5) { (_: EmptyRequest) async throws -> OKResponse in
      await completion.complete()
      return OKResponse(ok: true)
    }
    await router.register(6) { (_: EmptyRequest) async throws -> OKResponse in
      await completion.scheduleDisconnect(session)
      return OKResponse(ok: true)
    }
    await router.register(7) { (_: EmptyRequest) async throws -> OKResponse in
      await saturation.wait()
      return OKResponse(ok: true)
    }
    let rpcTask = Task {
      do {
        try await rpc.serve()
      } catch {
        FileHandle.standardError.write(
          Data("RPC server task failed: \(error.localizedDescription)\n".utf8)
        )
        throw error
      }
    }
    let proxyContract =
      command.limitCase == "proxy_body"
      ? ProxyContractOptions(maxBodyBytes: 1024) : ProxyContractOptions()
    let proxy = try ProxyServer(
      options: ProxyServerOptions(
        upstream: command.upstreamURL,
        upstreamOrigin: command.upstreamURL.absoluteString,
        contract: proxyContract
      )
    )

    do {
      while !Task.isCancelled {
        stage = "stream_accept"
        let next: EndpointStream
        do {
          next = try await session.acceptStream()
        } catch is FlowersecStreamResetError {
          await metrics.incrementResets()
          continue
        } catch {
          if await completion.isComplete { break }
          if ["inbound_streams", "frame", "session_receive"].contains(command.limitCase) {
            await completion.complete()
            break
          }
          throw error
        }
        switch next.kind {
        case "echo":
          stage = "echo"
          do {
            let payload = try await next.stream.readExact(command.workload.streams.bytesPerStream)
            try await next.stream.write(payload)
            await metrics.addBytes(payload.count)
            await next.stream.close()
          } catch is FlowersecStreamResetError {
            await metrics.incrementResets()
          } catch let error as FlowersecError where error.code == .notConnected {
            await next.stream.close()
          }
        case "churn":
          await next.stream.close()
        case "hold":
          while !Task.isCancelled {
            try await Task.sleep(for: .milliseconds(10))
          }
        case saturationGateKind:
          let signal = try await next.stream.readExact(1)
          guard signal == Data([1]) else {
            throw HarnessError("invalid RPC saturation gate signal")
          }
          await saturation.release()
          await next.stream.close()
        case ProxyProtocol.http1Kind, ProxyProtocol.webSocketKind:
          stage = next.kind == ProxyProtocol.http1Kind ? "proxy_http" : "proxy_websocket"
          try await proxy.serveStream(kind: next.kind, stream: next.stream)
        default:
          try await next.stream.reset()
          throw HarnessError("unsupported stream kind \(next.kind)")
        }
      }
    } catch {
      await saturation.release()
      rpcTask.cancel()
      await rpc.close()
      throw error
    }
    await saturation.release()
    rpcTask.cancel()
    await rpc.close()
    do {
      try await rpcTask.value
    } catch is CancellationError {
    } catch {
      guard await completion.isComplete else { throw error }
    }
  } catch let error as FlowersecError
    where
    ["inbound_streams", "frame", "session_receive"].contains(command.limitCase)
    && error.code == .resourceExhausted
  {
    await completion.complete()
  } catch let error as FlowersecError
    where
    ["frame", "session_receive"].contains(command.limitCase)
    && error.code == .notConnected
  {
    let terminal = await session.terminationError()
    guard terminal?.code == .resourceExhausted else {
      throw HarnessError("Swift server stage \(stage) failed: \(error.localizedDescription)")
    }
    await completion.complete()
  } catch is CancellationError {
    throw CancellationError()
  } catch {
    throw HarnessError("Swift server stage \(stage) failed: \(error.localizedDescription)")
  }
}

private func rpcEcho(_ client: FlowersecClient, value: Int, notify: Bool) async throws {
  let response: EchoResponse = try await client.rpc.call(
    1,
    EchoRequest(value: value, notify: notify)
  )
  guard response.value == value else { throw HarnessError("invalid RPC echo response") }
}

private func serverYamuxLimits(_ command: Command) -> YamuxLimits {
  let required = command.workload.streams.concurrent + 1
  var limits = YamuxLimits(
    maxActiveStreams: max(64, required),
    maxInboundStreams: max(32, required)
  )
  switch command.limitCase {
  case "inbound_streams":
    limits.maxInboundStreams = 1
  case "frame":
    limits.maxFrameBytes = 1024
    limits.preferredOutboundFrameBytes = 1024
  case "session_receive":
    limits.maxSessionReceiveBytes = 256 * 1024
  default:
    break
  }
  return limits
}

private func rpcControl(_ client: FlowersecClient, typeID: UInt32) async throws {
  let response: OKResponse = try await client.rpc.call(typeID, EmptyRequest())
  guard response.ok else { throw HarnessError("invalid control RPC response") }
}

private actor NotificationCounter {
  private var count = 0
  private var invalid = false

  func record(_ data: Data) {
    do {
      let message = try JSONDecoder().decode(HelloNotification.self, from: data)
      if message.hello == "world" { count += 1 } else { invalid = true }
    } catch {
      invalid = true
    }
  }

  func waitFor(_ expected: Int) async throws {
    let clock = ContinuousClock()
    let deadline = clock.now + .seconds(2)
    while count < expected {
      if invalid { throw HarnessError("invalid notification payload") }
      if clock.now >= deadline { throw HarnessError("notification deadline exceeded") }
      try await Task.sleep(for: .milliseconds(1))
    }
  }
}

private actor MetricsStore {
  private var metrics: Metrics

  init(initial: Metrics) { metrics = initial }
  var value: Metrics { metrics }
  func incrementRekeys() { metrics.rekeys += 1 }
  func incrementResets() { metrics.resets += 1 }
  func addBytes(_ count: Int) {
    metrics.bytesRead += count
    metrics.bytesWritten += count
  }
}

private actor CompletionSignal {
  private(set) var isComplete = false
  private var disconnectTask: Task<Void, Never>?

  func complete() {
    guard !isComplete else { return }
    isComplete = true
  }

  func scheduleDisconnect(_ session: EndpointSession) {
    complete()
    disconnectTask = Task {
      do {
        try await Task.sleep(for: .milliseconds(50))
      } catch is CancellationError {
        return
      } catch {
        FileHandle.standardError.write(
          Data("disconnect delay failed: \(error.localizedDescription)\n".utf8)
        )
        return
      }
      await session.close()
    }
  }

  func waitForScheduledWork() async {
    if let disconnectTask { await disconnectTask.value }
  }
}

private actor ReconnectArtifactQueue {
  private var artifacts: [ConnectArtifact]

  init(_ artifacts: [ConnectArtifact]) { self.artifacts = artifacts }

  func next() throws -> ConnectArtifact {
    guard !artifacts.isEmpty else {
      throw ArtifactSourceError.acquisitionFailed("Reconnect artifact sequence exhausted.")
    }
    return artifacts.removeFirst()
  }

  var isEmpty: Bool { artifacts.isEmpty }
}

private actor AsyncCompletionFlag {
  private(set) var isFinished = false
  func finish() { isFinished = true }
}

private actor SaturationGate {
  private var released = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    if released { return }
    await withCheckedContinuation { continuation in
      waiters.append(continuation)
    }
  }

  func release() {
    guard !released else { return }
    released = true
    let pending = waiters
    waiters.removeAll()
    for waiter in pending { waiter.resume() }
  }
}

private actor SaturationGateWriter {
  private let stream: any FlowersecByteStream
  private var releaseStarted = false
  private var released = false

  init(stream: any FlowersecByteStream) { self.stream = stream }

  func release() async throws {
    guard !releaseStarted else { return }
    releaseStarted = true
    try await stream.write(Data([1]))
    await stream.close()
    released = true
  }

  func cleanup() async throws {
    if !released { try await stream.reset() }
  }

  func requireReleased() throws {
    guard released else { throw HarnessError("RPC saturation completed without a queue rejection") }
  }
}

private struct HarnessError: LocalizedError, Sendable {
  var message: String
  init(_ message: String) { self.message = message }
  var errorDescription: String? { message }
}

private func readCommand() throws -> Command {
  guard let line = readLine(strippingNewline: true) else {
    throw HarnessError("protocol stdin reached EOF")
  }
  let data = Data(line.utf8)
  let object = try strictObject(data, name: "command")
  let required: Set<String> = [
    "v", "event", "request_id", "profile", "transport", "suite", "deadline_ms", "origin",
    "upstream_url", "workload", "reconnect_artifacts", "limit_artifacts", "limit_case",
  ]
  try requireKeys(
    object,
    required: required,
    optional: ["direct_info", "direct_credential", "tunnel_grant"],
    name: "command"
  )
  let workload = try objectValue(object, "workload")
  try requireKeys(
    workload,
    required: [
      "streams", "rekey", "liveness_probes", "rpc", "proxy", "reconnect_cycles",
      "limit_checks",
    ],
    name: "workload"
  )
  try requireKeys(
    try objectValue(workload, "streams"),
    required: [
      "concurrent", "bytes_per_stream", "chunk_bytes", "slow_readers", "churn", "fin", "reset",
    ],
    name: "streams"
  )
  try requireKeys(
    try objectValue(workload, "rekey"),
    required: ["client", "server", "concurrent"],
    name: "rekey"
  )
  try requireKeys(
    try objectValue(workload, "rpc"),
    required: [
      "calls", "notifications", "cancellations", "timeouts", "saturation_active",
      "saturation_queued", "saturation_rejected",
    ],
    name: "rpc"
  )
  try requireKeys(
    try objectValue(workload, "proxy"),
    required: [
      "http_requests", "http_body_bytes", "websocket_frames", "websocket_frame_bytes",
    ],
    name: "proxy"
  )
  if let direct = object["direct_info"] as? [String: Any] {
    try requireKeys(
      direct,
      required: [
        "ws_url", "channel_id", "e2ee_psk_b64u", "channel_init_expire_at_unix_s",
        "default_suite",
      ],
      name: "direct_info"
    )
  }
  if let direct = object["direct_credential"] as? [String: Any] {
    try requireKeys(
      direct,
      required: ["channel_id", "suite", "e2ee_psk_b64u", "init_expires_at_unix_s"],
      name: "direct_credential"
    )
  }
  if let grant = object["tunnel_grant"] as? [String: Any] {
    try requireKeys(
      grant,
      required: [
        "tunnel_url", "channel_id", "channel_init_expire_at_unix_s", "idle_timeout_seconds",
        "role", "token", "e2ee_psk_b64u", "allowed_suites", "default_suite",
      ],
      name: "tunnel_grant"
    )
  }
  guard let reconnectArtifacts = object["reconnect_artifacts"] as? [[String: Any]] else {
    throw HarnessError("reconnect_artifacts must be an array")
  }
  guard let limitArtifacts = object["limit_artifacts"] as? [[String: Any]],
    object["limit_case"] is String
  else { throw HarnessError("invalid limit plan fields") }
  for (index, artifact) in limitArtifacts.enumerated() {
    try requireKeys(
      artifact,
      required: ["name"],
      optional: ["direct_info", "tunnel_grant"],
      name: "limit_artifacts[\(index)]"
    )
  }
  for (index, artifact) in reconnectArtifacts.enumerated() {
    try requireKeys(
      artifact,
      required: [],
      optional: ["direct_info", "tunnel_grant"],
      name: "reconnect_artifacts[\(index)]"
    )
    if let direct = artifact["direct_info"] as? [String: Any] {
      try requireKeys(
        direct,
        required: [
          "ws_url", "channel_id", "e2ee_psk_b64u", "channel_init_expire_at_unix_s",
          "default_suite",
        ],
        name: "reconnect_artifacts[\(index)].direct_info"
      )
    }
    if let grant = artifact["tunnel_grant"] as? [String: Any] {
      try requireKeys(
        grant,
        required: [
          "tunnel_url", "channel_id", "channel_init_expire_at_unix_s", "idle_timeout_seconds",
          "role", "token", "e2ee_psk_b64u", "allowed_suites", "default_suite",
        ],
        name: "reconnect_artifacts[\(index)].tunnel_grant"
      )
    }
  }
  return try JSONDecoder().decode(Command.self, from: data)
}

private func readStop() throws -> Stop {
  guard let line = readLine(strippingNewline: true) else {
    throw HarnessError("protocol stdin reached EOF before stop")
  }
  let data = Data(line.utf8)
  let object = try strictObject(data, name: "stop")
  try requireKeys(object, required: ["v", "event", "request_id"], name: "stop")
  return try JSONDecoder().decode(Stop.self, from: data)
}

private func validate(_ command: Command) throws {
  guard command.version == protocolVersion, !command.requestID.isEmpty, !command.profile.isEmpty,
    ["run_client", "serve"].contains(command.event),
    ["direct", "tunnel"].contains(command.transport),
    ["x25519", "p256"].contains(command.suite), command.deadlineMilliseconds > 0
  else { throw HarnessError("invalid command envelope") }
  let expected =
    command.event == "run_client"
    ? (command.transport == "direct" ? [true, false, false] : [false, false, true])
    : (command.transport == "direct" ? [false, true, false] : [false, false, true])
  let actual = [
    command.directInfo != nil, command.directCredential != nil, command.tunnelGrant != nil,
  ]
  guard actual == expected else { throw HarnessError("invalid command credential field set") }
  if command.event == "run_client" {
    guard command.reconnectArtifacts.count == command.workload.reconnectCycles + 1 else {
      throw HarnessError("client command requires one fresh artifact per reconnect session")
    }
    for artifact in command.reconnectArtifacts {
      _ = try artifact.connectArtifact(transport: command.transport)
    }
    let expectedLimits = max(0, command.workload.limitChecks - 1)
    guard command.limitCase.isEmpty, command.limitArtifacts.count == expectedLimits else {
      throw HarnessError("client command contains an invalid limit plan")
    }
    for (index, artifact) in command.limitArtifacts.enumerated() {
      guard index < limitCases.count, artifact.name == limitCases[index] else {
        throw HarnessError("client limit artifacts must follow the canonical order")
      }
      _ = try artifact.clientArtifact().connectArtifact(transport: command.transport)
    }
  } else if !command.reconnectArtifacts.isEmpty {
    throw HarnessError("server command must not contain client reconnect artifacts")
  } else if !command.limitArtifacts.isEmpty
    || (!command.limitCase.isEmpty && !limitCases.contains(command.limitCase))
  {
    throw HarnessError("server command contains an invalid limit plan")
  }
  let positive = [
    command.workload.streams.concurrent, command.workload.streams.bytesPerStream,
    command.workload.streams.chunkBytes, command.workload.streams.slowReaders,
    command.workload.streams.churn, command.workload.streams.fin,
    command.workload.streams.reset, command.workload.rekey.client,
    command.workload.rekey.server, command.workload.livenessProbes,
    command.workload.rpc.calls, command.workload.rpc.notifications,
    command.workload.rpc.cancellations, command.workload.rpc.timeouts,
    command.workload.rpc.saturationActive, command.workload.rpc.saturationQueued,
    command.workload.rpc.saturationRejected,
    command.workload.proxy.httpRequests, command.workload.proxy.httpBodyBytes,
    command.workload.proxy.websocketFrames, command.workload.proxy.websocketFrameBytes,
    command.workload.reconnectCycles, command.workload.limitChecks,
  ]
  guard positive.allSatisfy({ $0 > 0 }), command.workload.rpc.saturationRejected == 1 else {
    throw HarnessError("workload values must be positive and saturation_rejected must be one")
  }
}

private func strictObject(_ data: Data, name: String) throws -> [String: Any] {
  guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
    throw HarnessError("\(name) must be a JSON object")
  }
  return value
}

private func objectValue(_ object: [String: Any], _ key: String) throws -> [String: Any] {
  guard let value = object[key] as? [String: Any] else {
    throw HarnessError("\(key) must be an object")
  }
  return value
}

private func requireKeys(
  _ object: [String: Any],
  required: Set<String>,
  optional: Set<String> = [],
  name: String
) throws {
  let keys = Set(object.keys)
  let missing = required.subtracting(keys)
  let unknown = keys.subtracting(required.union(optional))
  guard missing.isEmpty, unknown.isEmpty else {
    throw HarnessError(
      "\(name) fields are invalid; missing=\(missing.sorted()) unknown=\(unknown.sorted())")
  }
}

private func writeResult(
  requestID: String,
  metrics: Metrics,
  diagnostics: [Diagnostic]
) throws {
  let data = try JSONEncoder().encode(metrics)
  let object = try JSONSerialization.jsonObject(with: data)
  let diagnosticData = try JSONEncoder().encode(diagnostics)
  let diagnosticObject = try JSONSerialization.jsonObject(with: diagnosticData)
  try writeEvent([
    "v": protocolVersion,
    "event": "result",
    "request_id": requestID,
    "metrics": object,
    "diagnostics": diagnosticObject,
  ])
}

private func diagnosticFor(_ caseName: String, path: String) throws -> Diagnostic {
  let stage: String
  let code: String
  switch caseName {
  case "rpc_queue":
    stage = "rpc"
    code = "resource_exhausted"
  case "active_streams", "inbound_streams", "frame", "stream_receive", "session_receive":
    stage = "yamux"
    code = "resource_exhausted"
  case "proxy_body":
    stage = "rpc"
    code = "resource_exhausted"
  default:
    throw HarnessError("unknown diagnostic case \(caseName)")
  }
  return Diagnostic(case: caseName, path: path, stage: stage, code: code)
}

private func writeEvent(_ event: [String: Any]) throws {
  var data = try JSONSerialization.data(withJSONObject: event, options: [.sortedKeys])
  data.append(0x0A)
  try FileHandle.standardOutput.write(contentsOf: data)
}

private actor AcceptedTransportBox {
  private var transport: NIOWebSocketBinaryTransport?
  private var activeTransport: NIOWebSocketBinaryTransport?
  private var waiter: CheckedContinuation<NIOWebSocketBinaryTransport, Error>?

  func deliver(_ value: NIOWebSocketBinaryTransport) throws {
    guard transport == nil, waiter == nil else {
      throw HarnessError("direct listener accepted more than one WebSocket")
    }
    transport = value
  }

  func accept() async throws -> NIOWebSocketBinaryTransport {
    if let transport {
      self.transport = nil
      activeTransport = transport
      return transport
    }
    return try await withCheckedThrowingContinuation { continuation in
      waiter = continuation
    }
  }

  func resume(_ value: NIOWebSocketBinaryTransport) {
    if let waiter {
      self.waiter = nil
      activeTransport = value
      waiter.resume(returning: value)
    } else {
      transport = value
    }
  }

  func closeError() -> Error? {
    activeTransport?.recordedCloseError()
  }
}

private final class DirectWebSocketServer: @unchecked Sendable {
  let url: URL
  private let group: MultiThreadedEventLoopGroup
  private let channel: Channel
  private let accepted: AcceptedTransportBox

  private init(
    url: URL,
    group: MultiThreadedEventLoopGroup,
    channel: Channel,
    accepted: AcceptedTransportBox
  ) {
    self.url = url
    self.group = group
    self.channel = channel
    self.accepted = accepted
  }

  static func start(expectedOrigin: String) async throws -> DirectWebSocketServer {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let accepted = AcceptedTransportBox()
    let upgrader = NIOWebSocketServerUpgrader(
      maxFrameSize: 16 * 1024 * 1024,
      shouldUpgrade: { channel, request in
        guard request.headers.first(name: "origin") == expectedOrigin else {
          return channel.eventLoop.makeSucceededFuture(nil)
        }
        return channel.eventLoop.makeSucceededFuture(HTTPHeaders())
      },
      upgradePipelineHandler: { channel, _ in
        let transport = NIOWebSocketBinaryTransport(channel: channel)
        return channel.pipeline.addHandlers(
          NIOWebSocketFrameAggregator(
            minNonFinalFragmentSize: 1,
            maxAccumulatedFrameCount: 1024,
            maxAccumulatedFrameSize: 16 * 1024 * 1024
          ),
          NIOWebSocketTransportHandler(transport: transport)
        ).map {
          Task { await accepted.resume(transport) }
        }
      }
    )
    let upgrade: NIOHTTPServerUpgradeSendableConfiguration = (
      upgraders: [upgrader as HTTPServerProtocolUpgrader & Sendable],
      completionHandler: { _ in }
    )
    do {
      let channel = try await ServerBootstrap(group: group)
        .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
        .childChannelInitializer { channel in
          channel.pipeline.configureHTTPServerPipeline(withServerUpgrade: upgrade)
        }
        .bind(host: "127.0.0.1", port: 0)
        .get()
      guard let port = channel.localAddress?.port,
        let url = URL(string: "ws://127.0.0.1:\(port)")
      else {
        try await channel.close()
        try await group.shutdownGracefully()
        throw HarnessError("direct listener did not expose a TCP port")
      }
      return DirectWebSocketServer(url: url, group: group, channel: channel, accepted: accepted)
    } catch {
      try await group.shutdownGracefully()
      throw error
    }
  }

  func acceptTransport() async throws -> NIOWebSocketBinaryTransport {
    try await accepted.accept()
  }

  func close() async throws {
    var failures: [String] = []
    do { try await channel.close() } catch { failures.append("listener close: \(error)") }
    do { try await group.shutdownGracefully() } catch {
      failures.append("event loop shutdown: \(error)")
    }
    if let error = await accepted.closeError() {
      failures.append("accepted transport close: \(error)")
    }
    if !failures.isEmpty {
      throw HarnessError(failures.joined(separator: "; "))
    }
  }
}

private func decodeBase64URL(_ value: String) -> Data? {
  var base64 = value.replacingOccurrences(of: "-", with: "+")
    .replacingOccurrences(of: "_", with: "/")
  let remainder = base64.count % 4
  if remainder != 0 {
    base64 += String(repeating: "=", count: 4 - remainder)
  }
  return Data(base64Encoded: base64)
}

private final class NIOWebSocketBinaryTransport: FlowersecBinaryTransport, @unchecked Sendable {
  private let channel: Channel
  private let lock = NSLock()
  private var frames: [Data] = []
  private var waiters: [CheckedContinuation<Data, Error>] = []
  private var closed = false
  private var closeError: Error?

  init(channel: Channel) { self.channel = channel }

  func writeBinary(_ data: Data) async throws {
    guard lock.withLock({ !closed }) else { throw HarnessError("accepted WebSocket is closed") }
    var buffer = channel.allocator.buffer(capacity: data.count)
    buffer.writeBytes(data)
    try await channel.writeAndFlush(
      WebSocketFrame(fin: true, opcode: .binary, data: buffer)
    ).get()
  }

  func readBinary() async throws -> Data {
    return try await withCheckedThrowingContinuation { continuation in
      lock.withLock {
        if closed {
          continuation.resume(throwing: HarnessError("accepted WebSocket is closed"))
        } else if !frames.isEmpty {
          continuation.resume(returning: frames.removeFirst())
        } else {
          waiters.append(continuation)
        }
      }
    }
  }

  func close() async {
    let pending = lock.withLock { () -> [CheckedContinuation<Data, Error>] in
      guard !closed else { return [] }
      closed = true
      let pending = waiters
      waiters.removeAll()
      frames.removeAll()
      return pending
    }
    for waiter in pending { waiter.resume(throwing: HarnessError("accepted WebSocket closed")) }
    do {
      try await channel.close()
    } catch ChannelError.alreadyClosed {
      return
    } catch {
      lock.withLock { closeError = error }
    }
  }

  func recordedCloseError() -> Error? {
    lock.withLock { closeError }
  }

  func receive(_ data: Data) {
    let waiter = lock.withLock { () -> CheckedContinuation<Data, Error>? in
      guard !closed else { return nil }
      if waiters.isEmpty {
        frames.append(data)
        return nil
      }
      return waiters.removeFirst()
    }
    waiter?.resume(returning: data)
  }

  func fail(_ error: Error) {
    let pending = lock.withLock { () -> [CheckedContinuation<Data, Error>] in
      guard !closed else { return [] }
      closed = true
      let pending = waiters
      waiters.removeAll()
      frames.removeAll()
      return pending
    }
    for waiter in pending { waiter.resume(throwing: error) }
  }
}

private final class NIOWebSocketTransportHandler: ChannelInboundHandler, @unchecked Sendable {
  typealias InboundIn = WebSocketFrame
  typealias OutboundOut = WebSocketFrame

  private let transport: NIOWebSocketBinaryTransport

  init(transport: NIOWebSocketBinaryTransport) { self.transport = transport }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let frame = Self.unwrapInboundIn(data)
    switch frame.opcode {
    case .binary:
      var buffer = frame.unmaskedData
      let bytes = buffer.readBytes(length: buffer.readableBytes) ?? []
      transport.receive(Data(bytes))
    case .ping:
      context.writeAndFlush(
        Self.wrapOutboundOut(WebSocketFrame(fin: true, opcode: .pong, data: frame.unmaskedData)),
        promise: nil
      )
    case .connectionClose:
      transport.fail(HarnessError("accepted WebSocket received close"))
      context.close(promise: nil)
    default:
      let error = HarnessError("accepted WebSocket received a non-binary data frame")
      FileHandle.standardError.write(Data("NIO adapter rejected opcode \(frame.opcode)\n".utf8))
      transport.fail(error)
      context.fireErrorCaught(error)
      context.close(promise: nil)
    }
  }

  func channelInactive(context: ChannelHandlerContext) {
    transport.fail(HarnessError("accepted WebSocket became inactive"))
    context.fireChannelInactive()
  }

  func errorCaught(context: ChannelHandlerContext, error: Error) {
    FileHandle.standardError.write(Data("NIO adapter pipeline error: \(error)\n".utf8))
    transport.fail(error)
    context.close(promise: nil)
  }
}
