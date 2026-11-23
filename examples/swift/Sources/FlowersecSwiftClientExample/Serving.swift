import Flowersec
import Foundation

func exampleConcurrency(_ env: [String: String]) throws -> Int {
  guard let limit = Int(env["FSEC_RPC_CONCURRENT_REQUESTS"] ?? "32"), limit > 0 else {
    throw ExampleConfigurationError.invalidConfiguration
  }
  return limit
}

private func serveStreams(_ session: any Session, bidirectional: Bool) async throws {
  while true {
    let incoming: IncomingStream
    do { incoming = try await session.acceptStream() }
    catch SessionError.closed where !bidirectional { return }
    catch SessionError.goingAway where !bidirectional { return }
    switch incoming.kind {
    case "parity.echo":
      guard try await readAll(from: incoming.stream, maximum: 5) == Data("hello".utf8) else {
        throw ExampleConfigurationError.invalidStreamResponse
      }
      try await writeAll(Data("world".utf8), to: incoming.stream)
      try await incoming.stream.closeWrite()
    case "parity.subscribed", "parity.finished":
      guard bidirectional else { try await incoming.stream.reset(); continue }
      guard try await readAll(from: incoming.stream, maximum: 0).isEmpty else {
        throw ExampleConfigurationError.invalidStreamResponse
      }
      try await writeAll(Data("ok".utf8), to: incoming.stream)
      try await incoming.stream.closeWrite()
      if incoming.kind == "parity.finished" { return }
    default: try await incoming.stream.reset()
    }
  }
}

private func acknowledge(_ kind: String, on session: any Session) async throws {
  let stream = try await session.openStream(kind: kind)
  try await stream.closeWrite()
  guard try await readAll(from: stream, maximum: 2) == Data("ok".utf8) else {
    throw ExampleConfigurationError.invalidStreamResponse
  }
}

func runEndpoint(session: any Session, app: ParityApplication, env: [String: String], serving: Bool) async throws {
  if let echo = app.largeEcho, env["FSEC_EXAMPLE_BIDIRECTIONAL"] != "1" {
    let serve = serving || app.largeMode == .serve
    try await app.checkOptionalCalls(on: session, callLarge: !serve)
    if serve {
      try await withThrowingTaskGroup(of: Void.self) { group in
        group.addTask {
          let end = await session.waitTermination()
          guard end.error == .closed else { throw end.error }
          guard await echo.accepted else { throw ExampleConfigurationError.invalidRPCResponse }
        }
        group.addTask { try await Task.sleep(for: .seconds(120)); throw SessionError.timeout }
        defer { group.cancelAll() }
        do { _ = try await group.next() }
        catch { try? await session.close(); throw error }
      }
    }
  } else if env["FSEC_EXAMPLE_BIDIRECTIONAL"] == "1" {
    let (events, observer) = AsyncStream.makeStream(of: Bool.self, bufferingPolicy: .bufferingNewest(1))
    let subscription = try await session.rpc.subscribeNotification(7002, as: ValuePayload.self) { notification in
      try app.permissions.execute(7002)
      observer.yield((try? notification.get().value) == "notify")
      observer.finish()
    }
    do {
      try await withThrowingTaskGroup(of: Void.self) { group in
        group.addTask { try await serveStreams(session, bidirectional: true) }
        group.addTask {
          try await runApplicationWorkflow(session: session, app: app) {
            try await acknowledge("parity.subscribed", on: session)
          }
          try await withThrowingTaskGroup(of: Void.self) { wait in
            wait.addTask {
              var iterator = events.makeAsyncIterator()
              guard await iterator.next() == true else { throw ExampleConfigurationError.invalidRPCResponse }
            }
            wait.addTask { try await Task.sleep(for: .seconds(10)); throw SessionError.timeout }
            defer { wait.cancelAll() }
            _ = try await wait.next()
          }
          try await acknowledge("parity.finished", on: session)
        }
        do { while try await group.next() != nil {} }
        catch { group.cancelAll(); observer.finish(); try? await session.close(); throw error }
      }
    } catch { observer.finish(); await subscription.cancel(); throw error }
    observer.finish()
    await subscription.cancel()
  } else if serving { try await serveStreams(session, bidirectional: false) }
  else { try await runApplicationWorkflow(session: session, app: app) }
}

#if os(macOS) || os(iOS)
/// The issuer publishes an immutable artifact at the configured path after the listener is ready.
/// This single-invitation example deliberately leaves an uncertain spend receipt in place.
func runDirectListener(_ env: [String: String]) async throws {
  guard let endpoint = env["FSEC_LISTEN_ENDPOINT"], let origin = env["FSEC_ORIGIN"],
        let port = Int(env["FSEC_LISTEN_PORT"] ?? ""), let cert = env["FSEC_LISTEN_CERT_PEM_PATH"],
        let key = env["FSEC_LISTEN_KEY_PEM_PATH"], let artifactPath = env["FSEC_ARTIFACT_V5_PATH"],
        let receiptPath = env["FSEC_SERVER_SPEND_RECEIPT_PATH"] else { throw ExampleConfigurationError.invalidConfiguration }
  let app = try ParityApplication(env)
  let listener = try await DirectWebSocketListener.listen(bindAddress: env["FSEC_LISTEN_ADDRESS"] ?? "127.0.0.1",
    port: port, endpoint: endpoint, allowedOrigins: [origin],
    certificateChainPEM: Data(contentsOf: URL(fileURLWithPath: cert)),
    privateKeyPEM: Data(contentsOf: URL(fileURLWithPath: key)), rpcFrameLimits: app.frameLimits,
    maxConcurrentRPCRequests: try exampleConcurrency(env), authorize: { _ in
      let url = URL(fileURLWithPath: artifactPath)
      let published = try Data(contentsOf: url)
      return try DirectAdmissionGrant(reservingFor: parseArtifact(published), handlers: app.handlers) {
        try Task.checkCancellation()
        guard try Data(contentsOf: url) == published else { throw ExampleConfigurationError.invalidConfiguration }
        try commitSpendReceipt(at: receiptPath)
        return durableConnectionLease(releaseAt: receiptPath + ".released")
      }
    }, onSession: { session, _ in try await runEndpoint(session: session, app: app, env: env, serving: true) })
  FileHandle.standardOutput.write(Data("listening=\(listener.port)\n".utf8))
  try await withTaskCancellationHandler { try await listener.waitClosedAndCheckReleases() } onCancel: { Task { await listener.close() } }
}
#endif
