import Foundation

public struct ProxyClient: Sendable {
  private let route: any ProxyStreamRoute
  private let options: ProxyContractOptions
  private let headers: ProxyHeaderPolicy

  public init(
    route: any ProxyStreamRoute,
    options: ProxyContractOptions = ProxyContractOptions()
  ) throws {
    try proxyValidateContract(options)
    self.route = route
    self.options = options
    self.headers = try ProxyHeaderPolicy(options: options)
  }

  public func request(_ request: ProxyHTTPRequest) async throws -> ProxyHTTPResponse {
    try proxyValidatePath(request.path)
    let method = request.method.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
    guard !method.isEmpty else { throw ProxyError.invalidMetadata("method is required") }
    guard request.body.count <= options.maxBodyBytes else { throw ProxyError.bodyTooLarge }
    let stream = try await route.openStream(kind: ProxyProtocol.http1Kind)
    do {
      let requestID = try Data.secureRandom(count: 18).base64URLEncodedString()
      let timeout = request.timeout ?? options.defaultHTTPRequestTimeout
      let timeoutMilliseconds = try timeout.map(proxyDurationMilliseconds)
      try await ProxyFraming.writeJSON(
        ProxyHTTPRequestMeta(
          requestID: requestID,
          method: method,
          path: request.path,
          headers: headers.filterRequest(request.headers),
          externalOrigin: request.externalOrigin,
          timeoutMilliseconds: timeoutMilliseconds
        ),
        to: stream,
        maxBytes: options.maxJSONFrameBytes
      )
      try await ProxyFraming.writeBody(request.body, to: stream, options: options)
      let meta = try await ProxyFraming.readJSON(
        ProxyHTTPResponseMeta.self,
        from: stream,
        maxBytes: options.maxJSONFrameBytes
      )
      try validate(meta, requestID: requestID)
      guard meta.ok else {
        let error = meta.error!
        throw ProxyError.remote(code: error.code, message: error.message)
      }
      let body = try await ProxyFraming.readBody(from: stream, options: options)
      await stream.close()
      return ProxyHTTPResponse(
        status: meta.status!,
        headers: headers.filterResponse(meta.headers),
        body: body
      )
    } catch {
      await stream.close()
      throw error
    }
  }

  public func openWebSocket(
    path: String,
    headers inputHeaders: [ProxyHeader] = []
  ) async throws -> ProxyWebSocket {
    try proxyValidatePath(path)
    let stream = try await route.openStream(kind: ProxyProtocol.webSocketKind)
    do {
      let connectionID = try Data.secureRandom(count: 18).base64URLEncodedString()
      let requestedProtocols = proxyWebSocketProtocols(inputHeaders)
      try await ProxyFraming.writeJSON(
        ProxyWebSocketOpenMeta(
          connectionID: connectionID,
          path: path,
          headers: headers.filterWebSocket(inputHeaders)
        ),
        to: stream,
        maxBytes: options.maxJSONFrameBytes
      )
      let response = try await ProxyFraming.readJSON(
        ProxyWebSocketOpenResponse.self,
        from: stream,
        maxBytes: options.maxJSONFrameBytes
      )
      try validate(response, connectionID: connectionID)
      guard response.ok else {
        let error = response.error!
        throw ProxyError.remote(code: error.code, message: error.message)
      }
      if let selected = response.selectedProtocol, !selected.isEmpty,
        !requestedProtocols.contains(selected)
      {
        throw ProxyError.invalidMetadata("WebSocket subprotocol mismatch")
      }
      return ProxyWebSocket(
        stream: stream,
        selectedProtocol: response.selectedProtocol?.isEmpty == false
          ? response.selectedProtocol : nil,
        maxFrameBytes: options.maxWebSocketFrameBytes
      )
    } catch {
      await stream.close()
      throw error
    }
  }

  private func validate(_ meta: ProxyHTTPResponseMeta, requestID: String) throws {
    guard meta.version == ProxyProtocol.version, meta.requestID == requestID else {
      throw ProxyError.invalidMetadata("HTTP response correlation mismatch")
    }
    if meta.ok {
      guard let status = meta.status, (100...999).contains(status) else {
        throw ProxyError.invalidMetadata("HTTP response status is invalid")
      }
    } else {
      guard let error = meta.error, !error.code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw ProxyError.invalidMetadata("HTTP response error is missing")
      }
    }
  }

  private func validate(_ response: ProxyWebSocketOpenResponse, connectionID: String) throws {
    guard response.version == ProxyProtocol.version, response.connectionID == connectionID else {
      throw ProxyError.invalidMetadata("WebSocket response correlation mismatch")
    }
    if !response.ok {
      guard let error = response.error, !error.code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw ProxyError.invalidMetadata("WebSocket response error is missing")
      }
    }
  }
}

public actor ProxyWebSocket {
  public nonisolated let selectedProtocol: String?
  private let stream: any FlowersecByteStream
  private let maxFrameBytes: Int
  private var closed = false

  init(
    stream: any FlowersecByteStream,
    selectedProtocol: String?,
    maxFrameBytes: Int
  ) {
    self.stream = stream
    self.selectedProtocol = selectedProtocol
    self.maxFrameBytes = maxFrameBytes
  }

  public func send(_ frame: ProxyWebSocketFrame) async throws {
    guard !closed else { throw ProxyError.stream("WebSocket is closed") }
    try await ProxyFraming.writeWebSocketFrame(frame, to: stream, maxBytes: maxFrameBytes)
    if frame.operation == .close { closed = true }
  }

  public func receive() async throws -> ProxyWebSocketFrame {
    guard !closed else { throw ProxyError.stream("WebSocket is closed") }
    let frame = try await ProxyFraming.readWebSocketFrame(from: stream, maxBytes: maxFrameBytes)
    if frame.operation == .close { closed = true }
    return frame
  }

  public func close(code: UInt16? = 1000, reason: String = "") async throws {
    guard !closed else { return }
    try await send(ProxyWebSocketFrame.close(code: code, reason: reason))
    await stream.close()
  }

  public func abort() async {
    closed = true
    await stream.close()
  }
}

private func proxyWebSocketProtocols(_ headers: [ProxyHeader]) -> Set<String> {
  Set(headers.filter {
    $0.name.caseInsensitiveCompare("sec-websocket-protocol") == .orderedSame
  }.flatMap {
    $0.value.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespacesAndNewlines)
    }
  }.filter { !$0.isEmpty })
}
