import Foundation

struct OpaqueSessionV3: Session, CustomStringConvertible, CustomDebugStringConvertible,
  CustomReflectable
{
  let rpc: any RPCPeer

  private let session: TransportV3Session

  init(_ session: TransportV3Session) {
    self.session = session
    rpc = RedactedRPCPeerV3(peer: session.rpc)
  }

  func openStream(
    kind: String,
    metadata: StreamMetadata
  ) async throws -> any ByteStream {
    do {
      return RedactedByteStreamV3(
        stream: try await session.openStream(kind: kind, metadata: metadata)
      )
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  func acceptStream() async throws -> IncomingStream {
    do {
      let incoming = try await session.acceptStream()
      return IncomingStream(
        kind: incoming.kind,
        metadata: incoming.metadata,
        stream: RedactedByteStreamV3(stream: incoming.stream)
      )
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  func rekey() async throws {
    do {
      try await session.rekey()
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  func probeLiveness() async throws -> Duration {
    do {
      return try await session.probeLiveness()
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  func waitTermination() async -> SessionTermination {
    SessionTermination(error: redactTransportErrorV3(await session.waitClosed()))
  }

  func close() async throws {
    do {
      try await session.close()
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  var description: String { "Flowersec.Session" }
  var debugDescription: String { description }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
}

private struct RedactedByteStreamV3: ByteStream, CustomStringConvertible,
  CustomDebugStringConvertible, CustomReflectable
{
  let kind: String

  private let stream: any ByteStream

  init(stream: any ByteStream) {
    self.stream = stream
    kind = stream.kind
  }

  func read(maxBytes: Int) async throws -> Data? {
    do {
      return try await stream.read(maxBytes: maxBytes)
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  func write(_ data: Data) async throws -> Int {
    do {
      return try await stream.write(data)
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  func closeWrite() async throws {
    do {
      try await stream.closeWrite()
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  func reset() async throws {
    do {
      try await stream.reset()
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  func close() async throws {
    do {
      try await stream.close()
    } catch {
      throw redactTransportErrorV3(error)
    }
  }
  func terminalError() async -> SessionError? { await stream.terminalError() }

  var description: String { "Flowersec.ByteStream" }
  var debugDescription: String { description }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
}

private struct RedactedRPCPeerV3: RPCPeer, CustomStringConvertible,
  CustomDebugStringConvertible, CustomReflectable
{
  let peer: any RPCPeer

  func call<Request: Encodable & Sendable, Response: Decodable & Sendable>(
    _ typeID: UInt32,
    _ request: Request,
    as responseType: Response.Type,
    timeout: Duration
  ) async throws -> Response {
    do {
      return try await peer.call(typeID, request, as: responseType, timeout: timeout)
    } catch let error as FlowersecRPCError {
      throw RPCError(code: error.code, message: error.message)
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  func notify<Payload: Encodable & Sendable>(
    _ typeID: UInt32,
    _ payload: Payload
  ) async throws {
    do {
      try await peer.notify(typeID, payload)
    } catch let error as FlowersecRPCError {
      throw RPCError(code: error.code, message: error.message)
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  func subscribeNotification<Payload: Decodable & Sendable>(
    _ typeID: UInt32,
    as payloadType: Payload.Type,
    handler: @escaping @Sendable (Result<Payload, RPCNotificationError>) async throws -> Void
  ) async throws -> any RPCNotificationSubscription {
    do {
      return RedactedRPCNotificationSubscriptionV3(
        subscription: try await peer.subscribeNotification(
          typeID,
          as: payloadType,
          handler: handler
        )
      )
    } catch {
      throw redactTransportErrorV3(error)
    }
  }

  var description: String { "Flowersec.RPCPeer" }
  var debugDescription: String { description }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
}

private struct RedactedRPCNotificationSubscriptionV3: RPCNotificationSubscription,
  CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable
{
  private let subscription: any RPCNotificationSubscription

  init(subscription: any RPCNotificationSubscription) {
    self.subscription = subscription
  }

  func cancel() async { await subscription.cancel() }

  var description: String { "Flowersec.RPCNotificationSubscription" }
  var debugDescription: String { description }
  var customMirror: Mirror { Mirror(self, unlabeledChildren: [Any]()) }
}

func redactTransportErrorV3(_ error: any Error) -> SessionError {
  if let redacted = error as? SessionError { return redacted }
  if error is CancellationError { return .canceled }
  if let transport = error as? TransportV3SessionError {
    switch transport {
    case .closed:
      return .closed
    case .goingAway:
      return .goingAway
    case .resourceExhausted:
      return .resourceExhausted
    case .openRejected:
      return .streamRejected
    case .streamReset:
      return .streamReset
    case .rekeyFailed:
      return .rekeyFailed
    case .livenessFailed:
      return .livenessFailed
    case .invalidConfiguration, .handshakeFailed, .protocolViolation:
      return .operationFailed
    }
  }
  if let flowersec = error as? FlowersecError {
    switch flowersec.code {
    case .timeout:
      return .timeout
    case .notConnected:
      return .closed
    case .resourceExhausted:
      return .resourceExhausted
    case .invalidInput, .muxFailed, .rpcFailed:
      return .operationFailed
    }
  }
  return .operationFailed
}
