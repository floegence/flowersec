import Foundation

struct OpaqueSessionV2: SessionV2 {
  let rpc: any RPCPeerV2

  private let session: TransportV2Session

  init(_ session: TransportV2Session) {
    self.session = session
    rpc = RedactedRPCPeerV2(peer: session.rpc)
  }

  func openStream(
    kind: String,
    metadata: StreamMetadataV2
  ) async throws -> any ByteStreamV2 {
    do {
      return RedactedByteStreamV2(
        stream: try await session.openStream(kind: kind, metadata: metadata)
      )
    } catch {
      throw redactTransportErrorV2(error)
    }
  }

  func acceptStream() async throws -> IncomingStreamV2 {
    do {
      let incoming = try await session.acceptStream()
      return IncomingStreamV2(
        kind: incoming.kind,
        metadata: incoming.metadata,
        stream: RedactedByteStreamV2(stream: incoming.stream)
      )
    } catch {
      throw redactTransportErrorV2(error)
    }
  }

  func rekey() async throws {
    do {
      try await session.rekey()
    } catch {
      throw redactTransportErrorV2(error)
    }
  }

  func probeLiveness() async throws -> Duration {
    do {
      return try await session.probeLiveness()
    } catch {
      throw redactTransportErrorV2(error)
    }
  }

  func waitClosed() async -> SessionErrorV2 {
    redactTransportErrorV2(await session.waitClosed())
  }

  func close() async { await session.close() }
}

private struct RedactedByteStreamV2: ByteStreamV2 {
  let kind: String

  private let stream: any ByteStreamV2

  init(stream: any ByteStreamV2) {
    self.stream = stream
    kind = stream.kind
  }

  func read(maxBytes: Int) async throws -> Data? {
    do {
      return try await stream.read(maxBytes: maxBytes)
    } catch {
      throw redactTransportErrorV2(error)
    }
  }

  func write(_ data: Data) async throws -> Int {
    do {
      return try await stream.write(data)
    } catch {
      throw redactTransportErrorV2(error)
    }
  }

  func closeWrite() async throws {
    do {
      try await stream.closeWrite()
    } catch {
      throw redactTransportErrorV2(error)
    }
  }

  func reset() async { await stream.reset() }
  func close() async { await stream.close() }
  func terminalError() async -> SessionErrorV2? { await stream.terminalError() }
}

private struct RedactedRPCPeerV2: RPCPeerV2 {
  let peer: any RPCPeerV2

  func call<Request: Encodable & Sendable, Response: Decodable & Sendable>(
    _ typeID: UInt32,
    _ request: Request,
    as responseType: Response.Type,
    timeout: Duration
  ) async throws -> Response {
    do {
      return try await peer.call(typeID, request, as: responseType, timeout: timeout)
    } catch let error as FlowersecRPCError {
      throw RPCErrorV2(code: error.code, message: error.message)
    } catch {
      throw redactTransportErrorV2(error)
    }
  }

  func notify<Payload: Encodable & Sendable>(
    _ typeID: UInt32,
    _ payload: Payload
  ) async throws {
    do {
      try await peer.notify(typeID, payload)
    } catch let error as FlowersecRPCError {
      throw RPCErrorV2(code: error.code, message: error.message)
    } catch {
      throw redactTransportErrorV2(error)
    }
  }
}

func redactTransportErrorV2(_ error: any Error) -> SessionErrorV2 {
  if let redacted = error as? SessionErrorV2 { return redacted }
  if error is CancellationError { return .canceled }
  if let transport = error as? TransportV2SessionError {
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
    case .invalidInput, .dialFailed, .muxFailed, .pingFailed, .rpcFailed:
      return .operationFailed
    }
  }
  return .operationFailed
}
