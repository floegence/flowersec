#if os(macOS)
import Foundation
import Security
import XCTest
@testable import Flowersec

private func peerParityBootstrapURL(_ string: String) throws -> URL {
  guard let url = URL(string: string), ["http", "https"].contains(url.scheme ?? ""),
    ["localhost", "127.0.0.1", "::1"].contains(url.host ?? ""),
    url.user == nil, url.password == nil, url.fragment == nil,
    let port = url.port, (1024...65535).contains(port)
  else { throw PeerParityFailure.unsupportedMaterial }
  return url
}

private final class PeerParityBootstrapDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
  private let hostname: String
  private let roots: [SecCertificate]
  private let gate = NSLock()
  private var invalidated = false
  private var invalidationWaiter: CheckedContinuation<Void, Never>?
  init(hostname: String, rootsPEM: [Data]) throws {
    self.hostname = hostname
    var certificates: [SecCertificate] = []
    for pem in rootsPEM {
      guard let text = String(data: pem, encoding: .utf8) else { throw PeerParityFailure.invalidMaterial }
      for section in text.components(separatedBy: "-----BEGIN CERTIFICATE-----").dropFirst() {
        guard let end = section.range(of: "-----END CERTIFICATE-----") else { throw PeerParityFailure.invalidMaterial }
        let base64 = String(section[..<end.lowerBound]).components(separatedBy: .whitespacesAndNewlines).joined()
        guard let der = Data(base64Encoded: base64),
          let certificate = SecCertificateCreateWithData(nil, der as CFData), certificates.count < 16 else {
          throw PeerParityFailure.invalidMaterial
        }
        certificates.append(certificate)
      }
    }
    roots = certificates
    super.init()
  }
  func urlSession(_ session: URLSession, task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
    completionHandler(nil)
  }
  func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    urlSession(session, didReceive: challenge, completionHandler: completionHandler)
  }
  func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
      challenge.protectionSpace.host == hostname, let trust = challenge.protectionSpace.serverTrust,
      SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, hostname as CFString)) == errSecSuccess,
      SecTrustSetAnchorCertificates(trust, roots as CFArray) == errSecSuccess,
      SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else {
      completionHandler(.cancelAuthenticationChallenge, nil); return
    }
    guard SecTrustEvaluateWithError(trust, nil) else {
      completionHandler(.cancelAuthenticationChallenge, nil); return
    }
    completionHandler(.useCredential, URLCredential(trust: trust))
  }
  func urlSession(_ session: URLSession, didBecomeInvalidWithError error: (any Error)?) {
    let waiting = gate.withLock { () -> CheckedContinuation<Void, Never>? in
      invalidated = true; defer { invalidationWaiter = nil }; return invalidationWaiter
    }
    waiting?.resume()
  }
  func waitInvalidated() async {
    await withCheckedContinuation { continuation in
      let complete = gate.withLock {
        if invalidated { return true }; invalidationWaiter = continuation; return false
      }
      if complete { continuation.resume() }
    }
  }
}

extension PeerParityMaterial.Namespace {
  func bootstrap(nonce: Data, roots: [Data]) async throws -> TransportNamespaceSnapshot {
    struct Request: Encodable { let tenant: String; let authority: String; let nonce: Data }
    struct Response: Decodable { let response: Data; let state: Data }
    let url = try peerParityBootstrapURL(bootstrapURL)
    guard url.scheme != "https" || !roots.isEmpty else { throw PeerParityFailure.invalidMaterial }
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.timeoutInterval = 10
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try JSONEncoder().encode(Request(tenant: tenant, authority: authority, nonce: nonce))
    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpCookieStorage = nil
    configuration.urlCache = nil
    configuration.tlsMinimumSupportedProtocolVersion = .TLSv13
    configuration.tlsMaximumSupportedProtocolVersion = .TLSv13
    configuration.httpMaximumConnectionsPerHost = 1
    let delegate = try PeerParityBootstrapDelegate(hostname: request.url!.host!, rootsPEM: roots)
    let callbacks = OperationQueue()
    callbacks.maxConcurrentOperationCount = 1
    let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: callbacks)
    do {
      let (bytes, response) = try await session.bytes(for: request, delegate: delegate)
      guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
        throw PeerParityFailure.bootstrapFailed
      }
      var input = Data()
      for try await byte in bytes {
        guard input.count < 524_288 else { throw PeerParityFailure.responseTooLarge }
        input.append(byte)
      }
      let snapshot = try JSONDecoder().decode(Response.self, from: input)
      guard !snapshot.response.isEmpty, snapshot.response.count <= 270_336,
        !snapshot.state.isEmpty, snapshot.state.count <= 262_144 else {
        throw PeerParityFailure.responseTooLarge
      }
      session.finishTasksAndInvalidate()
      await delegate.waitInvalidated()
      return TransportNamespaceSnapshot(response: snapshot.response, state: snapshot.state)
    } catch {
      session.invalidateAndCancel()
      await delegate.waitInvalidated()
      throw error
    }
  }
}

#endif
