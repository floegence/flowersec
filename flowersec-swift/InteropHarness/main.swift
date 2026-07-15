import Flowersec
import Foundation

private struct PingRequest: Codable, Sendable {}
private struct PingResponse: Codable, Sendable { var ok: Bool }
private struct HelloNotify: Codable, Sendable { var hello: String }

private enum HarnessMode {
  case tunnel(String)
  case direct(DirectCredentialInput)
}

private struct HarnessOptions {
  var mode: HarnessMode
  var upstreamURL: URL
}

private struct DirectCredentialInput: Decodable {
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

@main
private enum FlowersecInteropHarness {
  static func main() async throws {
    let options = try arguments()
    let session: EndpointSession
    switch options.mode {
    case .tunnel(let serverGrantJSON):
      let grant = try JSONDecoder().decode(
        ChannelInitGrant.self,
        from: Data(serverGrantJSON.utf8)
      )
      writeEvent(["v": 1, "event": "attaching"])
      session = try await Endpoint.connectTunnel(
        grant: grant,
        options: EndpointOptions(
          origin: "https://app.redeven.com",
          transportSecurityPolicy: .allowPlaintextForLoopback
        )
      )
    case .direct(let input):
      guard let suite = Suite(rawValue: input.suite),
        let psk = decodeBase64URL(input.psk),
        psk.count == 32
      else {
        throw FlowersecRPCError(code: 400, message: "Invalid direct credential")
      }
      let transport = StdioBinaryTransport()
      writeEvent(["v": 1, "event": "ready"])
      session = try await Endpoint.acceptDirect(
        transport: transport,
        credential: DirectEndpointCredential(
          channelID: input.channelID,
          suite: suite,
          psk: psk,
          initExpiresAtUnixS: input.initExpiresAtUnixS
        ),
        secureTransport: false,
        options: EndpointOptions(
          origin: "https://app.example.com",
          transportSecurityPolicy: .allowPlaintextForLoopback
        )
      )
    }
    try await serve(session: session, upstreamURL: options.upstreamURL)
  }

  private static func serve(session: EndpointSession, upstreamURL: URL) async throws {
    let accepted = try await session.acceptStream()
    guard accepted.kind == "rpc" else {
      throw FlowersecRPCError(code: 400, message: "First stream is not RPC")
    }
    let router = RPCRouter()
    let rpc = try RPCServer(stream: accepted.stream, router: router, path: session.path)
    await router.register(1) { (_: PingRequest) async throws -> PingResponse in
      try await rpc.notify(2, HelloNotify(hello: "world"))
      return PingResponse(ok: true)
    }
    let rpcTask = Task { try await rpc.serve() }
    let proxy = try ProxyServer(
      options: ProxyServerOptions(
        upstream: upstreamURL,
        upstreamOrigin: upstreamURL.absoluteString
      )
    )

    do {
      while true {
        let stream = try await session.acceptStream()
        switch stream.kind {
        case "echo":
          Task {
            do {
              let payload = try await stream.stream.readExact(17)
              try await stream.stream.write(payload)
            } catch {}
            await stream.stream.close()
          }
        case "flowersec-proxy/http1", "flowersec-proxy/ws":
          Task {
            do { try await proxy.serveStream(kind: stream.kind, stream: stream.stream) } catch {
              await stream.stream.close()
            }
          }
        default:
          await stream.stream.close()
        }
      }
    } catch {
      rpcTask.cancel()
      await rpc.close()
      await session.close()
    }
  }

  private static func arguments() throws -> HarnessOptions {
    var serverGrantJSON: String?
    var directCredentialJSON: String?
    var upstreamURL: URL?
    var iterator = CommandLine.arguments.dropFirst().makeIterator()
    while let argument = iterator.next() {
      switch argument {
      case "--tunnel-grant-json":
        serverGrantJSON = iterator.next()
      case "--direct-credential-json":
        directCredentialJSON = iterator.next()
      case "--upstream-url":
        upstreamURL = iterator.next().flatMap(URL.init(string:))
      default:
        throw FlowersecRPCError(code: 400, message: "Unknown argument \(argument)")
      }
    }
    guard let upstreamURL, (serverGrantJSON == nil) != (directCredentialJSON == nil) else {
      throw FlowersecRPCError(code: 400, message: "Missing harness arguments")
    }
    if let serverGrantJSON {
      return HarnessOptions(mode: .tunnel(serverGrantJSON), upstreamURL: upstreamURL)
    }
    guard let directCredentialJSON else {
      throw FlowersecRPCError(code: 400, message: "Missing direct credential")
    }
    let input = try JSONDecoder().decode(
      DirectCredentialInput.self,
      from: Data(directCredentialJSON.utf8)
    )
    return HarnessOptions(mode: .direct(input), upstreamURL: upstreamURL)
  }

  private static func writeEvent(_ event: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: event),
      var line = String(data: data, encoding: .utf8)
    else { return }
    line.append("\n")
    FileHandle.standardOutput.write(Data(line.utf8))
  }

  private static func decodeBase64URL(_ value: String) -> Data? {
    var base64 = value.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = base64.count % 4
    if remainder != 0 {
      base64 += String(repeating: "=", count: 4 - remainder)
    }
    return Data(base64Encoded: base64)
  }
}

private final class StdioBinaryTransport: FlowersecBinaryTransport, @unchecked Sendable {
  private static let maxFrameBytes = 16 * 1024 * 1024
  private let input = FileHandle.standardInput
  private let output = FileHandle.standardOutput
  private let readLock = NSLock()
  private let writeLock = NSLock()
  private let stateLock = NSLock()
  private var closed = false

  func writeBinary(_ data: Data) async throws {
    try writeBinarySync(data)
  }

  func readBinary() async throws -> Data {
    try readBinarySync()
  }

  func close() async {
    closeSync()
  }

  private func closeSync() {
    stateLock.lock()
    closed = true
    stateLock.unlock()
  }

  private func writeBinarySync(_ data: Data) throws {
    guard !isClosed(), data.count <= Self.maxFrameBytes else {
      throw FlowersecRPCError(code: 500, message: "stdio transport is closed or oversized")
    }
    writeLock.lock()
    defer { writeLock.unlock() }
    var length = UInt32(data.count).bigEndian
    output.write(Data(bytes: &length, count: MemoryLayout<UInt32>.size))
    output.write(data)
  }

  private func readBinarySync() throws -> Data {
    guard !isClosed() else {
      throw FlowersecRPCError(code: 500, message: "stdio transport is closed")
    }
    readLock.lock()
    defer { readLock.unlock() }
    let header = try readExact(4)
    let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    guard length <= Self.maxFrameBytes else {
      throw FlowersecRPCError(code: 500, message: "stdio transport frame is oversized")
    }
    return try readExact(Int(length))
  }

  private func isClosed() -> Bool {
    stateLock.lock()
    defer { stateLock.unlock() }
    return closed
  }

  private func readExact(_ count: Int) throws -> Data {
    var data = Data()
    while data.count < count {
      let chunk = input.readData(ofLength: count - data.count)
      guard !chunk.isEmpty else {
        throw FlowersecRPCError(code: 500, message: "stdio transport reached EOF")
      }
      data.append(chunk)
    }
    return data
  }
}
