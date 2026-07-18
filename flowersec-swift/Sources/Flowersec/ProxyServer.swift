import AsyncHTTPClient
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix

public final class ProxyServer: @unchecked Sendable {
  private let configuration: ProxyCompiledServerOptions
  private let httpExecutor: ProxyHTTPExecutor
  private let webSocketFactory: ProxyUpstreamWebSocketFactory
  private let concurrency: ProxyConcurrencyGate

  public init(options: ProxyServerOptions) throws {
    let configuration = try ProxyCompiledServerOptions(options)
    self.configuration = configuration
    self.httpExecutor = ProxyHTTPRuntime.execute
    self.webSocketFactory = { url, headers, maxBytes, timeout in
      try await ProxyNIOWebSocketConnector.connect(
        url: url,
        headers: headers,
        maxFrameBytes: maxBytes,
        timeout: timeout
      )
    }
    self.concurrency = ProxyConcurrencyGate(limit: configuration.maxConcurrentStreams)
  }

  init(
    options: ProxyServerOptions,
    httpExecutor: @escaping ProxyHTTPExecutor = ProxyHTTPRuntime.execute,
    webSocketFactory: @escaping ProxyUpstreamWebSocketFactory
  ) throws {
    let configuration = try ProxyCompiledServerOptions(options)
    self.configuration = configuration
    self.httpExecutor = httpExecutor
    self.webSocketFactory = webSocketFactory
    self.concurrency = ProxyConcurrencyGate(limit: configuration.maxConcurrentStreams)
  }

  public func serve(_ session: EndpointSession) async throws {
    do {
      try await withThrowingTaskGroup(of: Void.self) { group in
        while !Task.isCancelled {
          let accepted = try await session.acceptStream()
          group.addTask { [self] in
            await serveAcceptedStream(accepted)
          }
        }
        try await group.waitForAll()
      }
    } catch {
      await session.close()
      throw error
    }
  }

  func serveAcceptedStream(_ accepted: EndpointStream) async {
    guard await concurrency.tryAcquire() else {
      try? await accepted.stream.reset()
      return
    }
    await withTaskCancellationHandler {
      do {
        try await serveStream(kind: accepted.kind, stream: accepted.stream)
      } catch {
        try? await accepted.stream.reset()
      }
    } onCancel: {
      Task { try? await accepted.stream.reset() }
    }
    await concurrency.release()
  }

  public func serveStream(kind: String, stream: any FlowersecByteStream) async throws {
    switch kind {
    case ProxyProtocol.http1Kind:
      try await serveHTTP(stream)
    case ProxyProtocol.webSocketKind:
      try await serveWebSocket(stream)
    default:
      await stream.close()
    }
  }

  private func serveHTTP(_ stream: any FlowersecByteStream) async throws {
    let meta: ProxyHTTPRequestMeta
    do {
      meta = try await ProxyFraming.readJSON(
        ProxyHTTPRequestMeta.self,
        from: stream,
        maxBytes: configuration.contract.maxJSONFrameBytes
      )
      try validateHTTP(meta)
    } catch {
      try await respondHTTPError(
        stream,
        requestID: "unknown",
        code: "invalid_request_meta",
        cause: error
      )
      return
    }

    let bodyReader = ProxyFramedHTTPBodyReader(
      stream: stream,
      maxChunkBytes: configuration.contract.maxChunkBytes,
      maxBodyBytes: configuration.contract.maxBodyBytes
    )
    let body = ProxyHTTPBodyStream(nextChunk: { try await bodyReader.next() })
    var responseStarted = false
    do {
      let url = try configuration.upstreamURL(path: meta.path, webSocket: false)
      var headers = configuration.headers.filterRequest(meta.headers)
      try applyExternalOrigin(meta.externalOrigin, to: &headers)
      let timeout = try configuration.resolveTimeout(meta.timeoutMilliseconds)
      let method = meta.method.uppercased()
      if method == "GET" || method == "HEAD" {
        for try await _ in body {}
      }
      let response = try await httpExecutor(
        ProxyHTTPUpstreamRequest(
          method: method,
          url: url,
          headers: headers,
          body: method == "GET" || method == "HEAD" ? .empty : body,
          timeout: timeout
        )
      )
      if let contentLength = response.contentLength,
        contentLength > configuration.contract.maxBodyBytes
      {
        throw ProxyError.bodyTooLarge
      }
      try await ProxyFraming.writeJSON(
        ProxyHTTPResponseMeta(
          requestID: meta.requestID,
          ok: true,
          status: response.status,
          headers: configuration.headers.filterResponse(response.headers)
        ),
        to: stream,
        maxBytes: configuration.contract.maxJSONFrameBytes
      )
      responseStarted = true
      let responseWriter = ProxyHTTPResponseBodyWriter(
        stream: stream,
        maxChunkBytes: configuration.contract.maxChunkBytes,
        maxBodyBytes: configuration.contract.maxBodyBytes
      )
      try await response.body { chunk in
        try await responseWriter.write(chunk)
      }
      try await ProxyFraming.writeBodyTerminator(to: stream)
      await stream.close()
    } catch {
      if responseStarted {
        try? await stream.reset()
        return
      }
      if let bodyError = await bodyReader.failure() {
        try await respondHTTPError(
          stream,
          requestID: meta.requestID,
          code: proxyClassifyRequestBodyError(bodyError),
          cause: bodyError
        )
        return
      }
      try await respondHTTPError(
        stream,
        requestID: meta.requestID,
        code: proxyClassifyHTTPError(error),
        cause: error
      )
    }
  }

  private func serveWebSocket(_ stream: any FlowersecByteStream) async throws {
    let meta: ProxyWebSocketOpenMeta
    do {
      meta = try await ProxyFraming.readJSON(
        ProxyWebSocketOpenMeta.self,
        from: stream,
        maxBytes: configuration.contract.maxJSONFrameBytes
      )
      try validateWebSocket(meta)
    } catch {
      try await respondWebSocketError(
        stream,
        connectionID: "unknown",
        code: "invalid_ws_open_meta",
        cause: error
      )
      return
    }

    let upstream: any ProxyUpstreamWebSocket
    do {
      let url = try configuration.upstreamURL(path: meta.path, webSocket: true)
      var headers = configuration.headers.filterWebSocket(meta.headers)
      headers.removeAll { $0.name.caseInsensitiveCompare("origin") == .orderedSame }
      headers.append(ProxyHeader(name: "origin", value: configuration.upstreamOrigin))
      upstream = try await webSocketFactory(
        url,
        headers,
        configuration.contract.maxWebSocketFrameBytes,
        configuration.defaultTimeout
      )
      try await ProxyFraming.writeJSON(
        ProxyWebSocketOpenResponse(
          connectionID: meta.connectionID,
          ok: true,
          selectedProtocol: upstream.selectedProtocol
        ),
        to: stream,
        maxBytes: configuration.contract.maxJSONFrameBytes
      )
    } catch {
      try await respondWebSocketError(
        stream,
        connectionID: meta.connectionID,
        code: proxyClassifyWebSocketError(error),
        cause: error
      )
      return
    }

    do {
      try await withThrowingTaskGroup(of: Void.self) { group in
        group.addTask { [configuration] in
          while true {
            let frame = try await ProxyFraming.readWebSocketFrame(
              from: stream,
              maxBytes: configuration.contract.maxWebSocketFrameBytes
            )
            try await upstream.send(frame)
            if frame.operation == .close { return }
          }
        }
        group.addTask { [configuration] in
          while true {
            let frame = try await upstream.receive()
            try await ProxyFraming.writeWebSocketFrame(
              frame,
              to: stream,
              maxBytes: configuration.contract.maxWebSocketFrameBytes
            )
            if frame.operation == .close { return }
          }
        }
        _ = try await group.next()
        group.cancelAll()
        await upstream.close()
        await stream.close()
      }
    } catch {
      await upstream.close()
      await stream.close()
      throw error
    }
  }

  private func respondHTTPError(
    _ stream: any FlowersecByteStream,
    requestID: String,
    code: String,
    cause: Error
  ) async throws {
    do {
      try await writeHTTPError(
        stream,
        requestID: requestID,
        code: code,
        message: cause.localizedDescription
      )
      await stream.close()
    } catch {
      await stream.close()
      throw ProxyServerFailure(
        "Proxy request failed: \(cause.localizedDescription); error response failed: \(error.localizedDescription)"
      )
    }
  }

  private func respondWebSocketError(
    _ stream: any FlowersecByteStream,
    connectionID: String,
    code: String,
    cause: Error
  ) async throws {
    do {
      try await writeWebSocketError(
        stream,
        connectionID: connectionID,
        code: code,
        message: cause.localizedDescription
      )
      await stream.close()
    } catch {
      await stream.close()
      throw ProxyServerFailure(
        "Proxy WebSocket failed: \(cause.localizedDescription); error response failed: \(error.localizedDescription)"
      )
    }
  }

  private func validateHTTP(_ meta: ProxyHTTPRequestMeta) throws {
    guard meta.version == ProxyProtocol.version else {
      throw ProxyError.invalidMetadata("unsupported version")
    }
    guard !meta.requestID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      throw ProxyError.invalidMetadata("request_id is required")
    }
    let method = meta.method.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !method.isEmpty, method == method.uppercased() else {
      throw ProxyError.invalidMetadata("HTTP method is invalid")
    }
    if let timeout = meta.timeoutMilliseconds, timeout < 0 {
      throw ProxyError.invalidMetadata("timeout_ms must be non-negative")
    }
    try proxyValidatePath(meta.path)
  }

  private func validateWebSocket(_ meta: ProxyWebSocketOpenMeta) throws {
    guard meta.version == ProxyProtocol.version,
      !meta.connectionID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    else { throw ProxyError.invalidMetadata("WebSocket open metadata is invalid") }
    try proxyValidatePath(meta.path)
  }

  private func applyExternalOrigin(
    _ externalOrigin: String?,
    to headers: inout [ProxyHeader]
  ) throws {
    guard let rawValue = externalOrigin?.trimmingCharacters(in: .whitespacesAndNewlines),
      !rawValue.isEmpty
    else { return }
    let external = try proxyNormalizedOrigin(rawValue)
    if let current = headers.first(where: {
      $0.name.caseInsensitiveCompare("origin") == .orderedSame
    }), try proxyNormalizedOrigin(current.value) != external {
      throw ProxyError.invalidMetadata("external_origin conflicts with Origin")
    }
    guard let components = URLComponents(string: external), let host = components.host,
      let scheme = components.scheme
    else { throw ProxyError.invalidMetadata("external_origin is invalid") }
    let authority = components.port.map { "\(host):\($0)" } ?? host
    headers.removeAll {
      $0.name.caseInsensitiveCompare("host") == .orderedSame
        || $0.name.caseInsensitiveCompare("x-forwarded-proto") == .orderedSame
    }
    headers.append(ProxyHeader(name: "host", value: authority))
    headers.append(ProxyHeader(name: "x-forwarded-proto", value: scheme))
  }

  private func writeHTTPError(
    _ stream: any FlowersecByteStream,
    requestID: String,
    code: String,
    message: String
  ) async throws {
    try await ProxyFraming.writeJSON(
      ProxyHTTPResponseMeta(
        requestID: requestID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
          ? "unknown" : requestID,
        ok: false,
        error: ProxyRemoteError(code: code, message: message)
      ),
      to: stream,
      maxBytes: configuration.contract.maxJSONFrameBytes
    )
    try await stream.write(Data(repeating: 0, count: 4))
  }

  private func writeWebSocketError(
    _ stream: any FlowersecByteStream,
    connectionID: String,
    code: String,
    message: String
  ) async throws {
    try await ProxyFraming.writeJSON(
      ProxyWebSocketOpenResponse(
        connectionID: connectionID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
          ? "unknown" : connectionID,
        ok: false,
        error: ProxyRemoteError(code: code, message: message)
      ),
      to: stream,
      maxBytes: configuration.contract.maxJSONFrameBytes
    )
  }
}

private struct ProxyServerFailure: LocalizedError, Sendable {
  let message: String

  init(_ message: String) {
    self.message = message
  }

  var errorDescription: String? { message }
}

struct ProxyHTTPUpstreamRequest: Sendable {
  var method: String
  var url: URL
  var headers: [ProxyHeader]
  var body: ProxyHTTPBodyStream
  var timeout: Duration?
}

struct ProxyHTTPUpstreamResponse: Sendable {
  var status: Int
  var headers: [ProxyHeader]
  var contentLength: Int?
  var body: @Sendable (@escaping @Sendable (Data) async throws -> Void) async throws -> Void
}

struct ProxyHTTPBodyStream: AsyncSequence, Sendable {
  typealias Element = Data

  struct AsyncIterator: AsyncIteratorProtocol {
    let nextChunk: @Sendable () async throws -> Data?

    mutating func next() async throws -> Data? { try await nextChunk() }
  }

  static let empty = ProxyHTTPBodyStream(nextChunk: { nil })

  let nextChunk: @Sendable () async throws -> Data?

  func makeAsyncIterator() -> AsyncIterator { AsyncIterator(nextChunk: nextChunk) }

  func collect() async throws -> Data {
    var result = Data()
    for try await chunk in self { result.append(chunk) }
    return result
  }
}

typealias ProxyHTTPExecutor =
  @Sendable (ProxyHTTPUpstreamRequest) async throws
  -> ProxyHTTPUpstreamResponse

private enum ProxyHTTPRuntime {
  static let client = HTTPClient(
    eventLoopGroupProvider: .shared(MultiThreadedEventLoopGroup.singleton),
    configuration: HTTPClient.Configuration(redirectConfiguration: .disallow)
  )

  static func execute(_ input: ProxyHTTPUpstreamRequest) async throws
    -> ProxyHTTPUpstreamResponse
  {
    var request = HTTPClientRequest(url: input.url.absoluteString)
    request.method = HTTPMethod(rawValue: input.method)
    for header in input.headers { request.headers.add(name: header.name, value: header.value) }
    if input.method != "GET" && input.method != "HEAD" {
      request.body = .stream(
        input.body.map { ByteBuffer(bytes: $0) },
        length: .unknown
      )
    }
    let response: HTTPClientResponse
    do {
      if let timeout = input.timeout {
        response = try await client.execute(
          request,
          timeout: TimeAmount.milliseconds(try proxyDurationMilliseconds(timeout))
        )
      } else {
        response = try await client.execute(request, deadline: NIODeadline.distantFuture)
      }
    } catch is CancellationError {
      throw ProxyError.canceled
    } catch let error as HTTPClientError where proxyIsHTTPTimeout(error) {
      throw ProxyUpstreamFailure(.timeout, error)
    } catch let error as NIOConnectionError {
      throw ProxyUpstreamFailure(.dial, error)
    } catch {
      throw ProxyUpstreamFailure(.request, error)
    }
    let headers = response.headers.map { ProxyHeader(name: $0.name, value: $0.value) }
    return ProxyHTTPUpstreamResponse(
      status: Int(response.status.code),
      headers: headers,
      contentLength: proxyHTTPContentLength(response.headers),
      body: { write in
        do {
          for try await buffer in response.body {
            try await write(Data(buffer.readableBytesView))
          }
        } catch is CancellationError {
          throw ProxyError.canceled
        } catch let error as HTTPClientError where proxyIsHTTPTimeout(error) {
          throw ProxyUpstreamFailure(.timeout, error)
        } catch {
          throw ProxyUpstreamFailure(.request, error)
        }
      }
    )
  }
}

private struct ProxyCompiledServerOptions: Sendable {
  var upstream: URL
  var upstreamOrigin: String
  var contract: ProxyContractOptions
  var headers: ProxyHeaderPolicy
  var defaultTimeout: Duration?
  var maxTimeout: Duration?
  var maxConcurrentStreams: Int

  init(_ options: ProxyServerOptions) throws {
    try proxyValidateContract(options.contract)
    guard let scheme = options.upstream.scheme?.lowercased(), scheme == "http" || scheme == "https",
      let host = options.upstream.host?.lowercased(), options.upstream.port != nil,
      options.upstream.user == nil, options.upstream.password == nil,
      options.upstream.query == nil, options.upstream.fragment == nil,
      options.upstream.path.isEmpty || options.upstream.path == "/"
    else {
      throw ProxyError.invalidConfiguration(
        "upstream must be an http(s) origin with an explicit port"
      )
    }
    let allowed = Set(
      (options.allowedUpstreamHosts.isEmpty ? ["127.0.0.1"] : options.allowedUpstreamHosts)
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
    )
    guard !allowed.contains(""), allowed.contains(host) else {
      throw ProxyError.invalidConfiguration("upstream host is not allowed")
    }
    guard options.defaultTimeout.map({ $0 >= .zero }) ?? true,
      options.maxTimeout.map({ $0 >= .zero }) ?? true,
      options.maxConcurrentStreams > 0
    else { throw ProxyError.invalidConfiguration("server limits are invalid") }
    self.upstream = options.upstream
    self.upstreamOrigin = try proxyNormalizedOrigin(options.upstreamOrigin)
    self.contract = options.contract
    self.headers = try ProxyHeaderPolicy(options: options.contract)
    self.defaultTimeout = options.defaultTimeout
    self.maxTimeout = options.maxTimeout
    self.maxConcurrentStreams = options.maxConcurrentStreams
  }

  func upstreamURL(path: String, webSocket: Bool) throws -> URL {
    try proxyValidatePath(path)
    guard let relative = URLComponents(string: "http://flowersec.invalid\(path)"),
      var components = URLComponents(url: upstream, resolvingAgainstBaseURL: false)
    else { throw ProxyError.invalidPath }
    components.scheme = webSocket ? (upstream.scheme == "https" ? "wss" : "ws") : upstream.scheme
    components.path = relative.path
    components.query = relative.query
    components.fragment = nil
    guard let result = components.url else { throw ProxyError.invalidPath }
    return result
  }

  func resolveTimeout(_ milliseconds: Int64?) throws -> Duration? {
    guard let milliseconds else { return defaultTimeout.map { capped($0) } }
    guard milliseconds >= 0 else {
      throw ProxyError.invalidMetadata("timeout_ms must be non-negative")
    }
    if milliseconds == 0 { return defaultTimeout.map { capped($0) } }
    return capped(.milliseconds(milliseconds))
  }

  private func capped(_ timeout: Duration) -> Duration {
    guard let maxTimeout else { return timeout }
    return min(timeout, maxTimeout)
  }
}

private actor ProxyConcurrencyGate {
  private let limit: Int
  private var active = 0

  init(limit: Int) { self.limit = limit }

  func tryAcquire() -> Bool {
    guard active < limit else { return false }
    active += 1
    return true
  }

  func release() {
    precondition(active > 0, "proxy concurrency permit released without acquisition")
    active -= 1
  }
}

private actor ProxyFramedHTTPBodyReader {
  private let stream: any FlowersecByteStream
  private let maxChunkBytes: Int
  private let maxBodyBytes: Int
  private var total = 0
  private var finished = false
  private var terminalError: (any Error)?

  init(stream: any FlowersecByteStream, maxChunkBytes: Int, maxBodyBytes: Int) {
    self.stream = stream
    self.maxChunkBytes = maxChunkBytes
    self.maxBodyBytes = maxBodyBytes
  }

  func next() async throws -> Data? {
    if let terminalError { throw terminalError }
    if finished { return nil }
    do {
      if Task.isCancelled { throw ProxyError.canceled }
      let header = try await stream.readExact(4)
      guard header.count == 4 else { throw ProxyError.stream("truncated body chunk header") }
      let length = Int(header.readUInt32BE(at: 0))
      if length == 0 {
        finished = true
        return nil
      }
      guard length <= maxChunkBytes else { throw ProxyError.frameTooLarge }
      guard total <= maxBodyBytes - length else { throw ProxyError.bodyTooLarge }
      let chunk = try await stream.readExact(length)
      guard chunk.count == length else { throw ProxyError.stream("truncated body chunk") }
      total += length
      return chunk
    } catch {
      terminalError = error
      throw error
    }
  }

  func failure() -> (any Error)? { terminalError }
}

private actor ProxyHTTPResponseBodyWriter {
  private let stream: any FlowersecByteStream
  private let maxChunkBytes: Int
  private let maxBodyBytes: Int
  private var total = 0

  init(stream: any FlowersecByteStream, maxChunkBytes: Int, maxBodyBytes: Int) {
    self.stream = stream
    self.maxChunkBytes = maxChunkBytes
    self.maxBodyBytes = maxBodyBytes
  }

  func write(_ chunk: Data) async throws {
    guard chunk.count <= maxBodyBytes, total <= maxBodyBytes - chunk.count else {
      throw ProxyError.bodyTooLarge
    }
    total += chunk.count
    try await ProxyFraming.writeBodyChunk(
      chunk,
      to: stream,
      maxChunkBytes: maxChunkBytes
    )
  }
}

private func proxyHTTPContentLength(_ headers: HTTPHeaders) -> Int? {
  let values = headers["content-length"]
  guard values.count == 1, let length = Int(values[0]), length >= 0 else { return nil }
  return length
}

private func proxyClassifyRequestBodyError(_ error: any Error) -> String {
  if error as? ProxyError == .bodyTooLarge || error as? ProxyError == .frameTooLarge {
    return "request_body_too_large"
  }
  if error as? ProxyError == .canceled || error is CancellationError { return "canceled" }
  return "request_body_invalid"
}

private func proxyClassifyHTTPError(_ error: any Error) -> String {
  switch error as? ProxyError {
  case .bodyTooLarge, .frameTooLarge: return "response_body_too_large"
  case .invalidMetadata, .invalidPath: return "invalid_request_meta"
  case .canceled: return "canceled"
  default: break
  }
  switch (error as? ProxyUpstreamFailure)?.kind {
  case .timeout: return "timeout"
  case .dial: return "upstream_dial_failed"
  case .rejected, .request, nil: return "upstream_request_failed"
  }
}

private func proxyClassifyWebSocketError(_ error: any Error) -> String {
  if error is CancellationError || error as? ProxyError == .canceled { return "canceled" }
  switch (error as? ProxyUpstreamFailure)?.kind {
  case .timeout: return "timeout"
  case .rejected: return "upstream_ws_rejected"
  case .dial, .request, nil: return "upstream_ws_dial_failed"
  }
}

private func proxyIsHTTPTimeout(_ error: HTTPClientError) -> Bool {
  error == .readTimeout || error == .writeTimeout || error == .connectTimeout
    || error == .socksHandshakeTimeout || error == .httpProxyHandshakeTimeout
    || error == .tlsHandshakeTimeout || error == .deadlineExceeded
    || error == .getConnectionFromPoolTimeout
}
