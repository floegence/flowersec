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
    while !Task.isCancelled {
      let accepted = try await session.acceptStream()
      await concurrency.acquire()
      Task { [self] in
        defer { Task { await concurrency.release() } }
        do { try await serveStream(kind: accepted.kind, stream: accepted.stream) }
        catch { await accepted.stream.close() }
      }
    }
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
      try? await writeHTTPError(
        stream,
        requestID: "unknown",
        code: "invalid_request_meta",
        message: error.localizedDescription
      )
      await stream.close()
      return
    }

    let body: Data
    do {
      body = try await ProxyFraming.readBody(from: stream, options: configuration.contract)
    } catch {
      let code = error as? ProxyError == .bodyTooLarge || error as? ProxyError == .frameTooLarge
        ? "request_body_too_large" : "request_body_invalid"
      try? await writeHTTPError(
        stream,
        requestID: meta.requestID,
        code: code,
        message: error.localizedDescription
      )
      await stream.close()
      return
    }

    do {
      let url = try configuration.upstreamURL(path: meta.path, webSocket: false)
      var headers = configuration.headers.filterRequest(meta.headers)
      try applyExternalOrigin(meta.externalOrigin, to: &headers)
      let timeout = try configuration.resolveTimeout(meta.timeoutMilliseconds)
      let response = try await httpExecutor(
        ProxyHTTPUpstreamRequest(
          method: meta.method,
          url: url,
          headers: headers,
          body: (meta.method == "GET" || meta.method == "HEAD") ? Data() : body,
          timeout: timeout,
          maxResponseBodyBytes: configuration.contract.maxBodyBytes
        )
      )
      guard response.body.count <= configuration.contract.maxBodyBytes else {
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
      try await ProxyFraming.writeBody(response.body, to: stream, options: configuration.contract)
      await stream.close()
    } catch {
      try? await writeHTTPError(
        stream,
        requestID: meta.requestID,
        code: proxyClassifyHTTPError(error),
        message: error.localizedDescription
      )
      await stream.close()
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
      try? await writeWebSocketError(
        stream,
        connectionID: "unknown",
        code: "invalid_ws_open_meta",
        message: error.localizedDescription
      )
      await stream.close()
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
      try? await writeWebSocketError(
        stream,
        connectionID: meta.connectionID,
        code: proxyClassifyWebSocketError(error),
        message: error.localizedDescription
      )
      await stream.close()
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

struct ProxyHTTPUpstreamRequest: Sendable {
  var method: String
  var url: URL
  var headers: [ProxyHeader]
  var body: Data
  var timeout: Duration?
  var maxResponseBodyBytes: Int
}

struct ProxyHTTPUpstreamResponse: Sendable {
  var status: Int
  var headers: [ProxyHeader]
  var body: Data
}

typealias ProxyHTTPExecutor = @Sendable (ProxyHTTPUpstreamRequest) async throws
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
    if !input.body.isEmpty { request.body = .bytes(input.body) }
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
    } catch {
      throw ProxyError.upstream(error.localizedDescription)
    }
    let bodyBuffer: ByteBuffer
    do { bodyBuffer = try await response.body.collect(upTo: input.maxResponseBodyBytes) }
    catch is NIOTooManyBytesError { throw ProxyError.bodyTooLarge }
    catch { throw ProxyError.upstream(error.localizedDescription) }
    let headers = response.headers.map { ProxyHeader(name: $0.name, value: $0.value) }
    return ProxyHTTPUpstreamResponse(
      status: Int(response.status.code),
      headers: headers,
      body: Data(bodyBuffer.readableBytesView)
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
  private var waiters: [CheckedContinuation<Void, Never>] = []

  init(limit: Int) { self.limit = limit }

  func acquire() async {
    if active < limit {
      active += 1
      return
    }
    await withCheckedContinuation { waiters.append($0) }
  }

  func release() {
    if waiters.isEmpty { active = max(0, active - 1) }
    else { waiters.removeFirst().resume() }
  }
}

private func proxyClassifyHTTPError(_ error: any Error) -> String {
  switch error as? ProxyError {
  case .bodyTooLarge, .frameTooLarge: return "response_body_too_large"
  case .invalidMetadata, .invalidPath: return "invalid_request_meta"
  case .canceled: return "canceled"
  default:
    let message = error.localizedDescription.lowercased()
    if message.contains("timeout") || message.contains("timed out") { return "timeout" }
    if message.contains("connect") { return "upstream_dial_failed" }
    return "upstream_request_failed"
  }
}

private func proxyClassifyWebSocketError(_ error: any Error) -> String {
  if error is CancellationError || error as? ProxyError == .canceled { return "canceled" }
  let message = error.localizedDescription.lowercased()
  if message.contains("timeout") || message.contains("timed out") { return "timeout" }
  if message.contains("rejected") { return "upstream_ws_rejected" }
  return "upstream_ws_dial_failed"
}
