import Crypto
import Foundation

enum CandidateLifecycleV2: Int, Equatable, Sendable {
  case attempt
  case ready
  case winner
  case admitted
  case established
  case terminated
}

enum ConnectorBoundaryErrorV2: Error, Equatable, Sendable {
  case runtimeUnsupported
  case runtimeFailed
  case admissionFailed
  case sessionFailed
}

private enum CandidatePreparationResultV2: Sendable {
  case ready(CandidateAttemptV2)
  case failed
}

protocol RuntimeCarrierAdapterV2: Sendable {
  var capabilities: RuntimeCapabilityDescriptorV2 { get }

  func validate(options: ConnectorOptions) throws

  func prepare(
    candidate: CanonicalCandidateV2,
    path: PathKind,
    role: SessionRoleV2,
    options: ConnectorOptions
  ) async throws -> any PreparedCarrierConnectionV2
}

protocol PreparedCarrierConnectionV2: Sendable {
  var carrier: CarrierKind { get }

  func writeAdmission(_ frame: Data) async throws
  func readAdmission() async throws -> Data
  func makeCarrier(inboundCapacity: UInt16) async throws -> any TransportV2CarrierSession
  func close() async
}

actor CandidateAttemptV2 {
  nonisolated let candidate: CanonicalCandidateV2
  private(set) var lifecycle = CandidateLifecycleV2.attempt
  private var connection: (any PreparedCarrierConnectionV2)?

  init(candidate: CanonicalCandidateV2) {
    self.candidate = candidate
  }

  func markReady(_ connection: any PreparedCarrierConnectionV2) throws {
    guard lifecycle == .attempt, connection.carrier.rawValue == candidate.carrier else {
      throw ConnectorBoundaryErrorV2.runtimeFailed
    }
    self.connection = connection
    lifecycle = .ready
  }

  func selectWinner() throws {
    guard lifecycle == .ready else { throw ConnectorBoundaryErrorV2.runtimeFailed }
    lifecycle = .winner
  }

  func connectionForAdmission() throws -> any PreparedCarrierConnectionV2 {
    guard lifecycle == .winner, let connection else {
      throw ConnectorBoundaryErrorV2.admissionFailed
    }
    return connection
  }

  func markAdmitted() throws {
    guard lifecycle == .winner else { throw ConnectorBoundaryErrorV2.admissionFailed }
    lifecycle = .admitted
  }

  func relinquishAdmittedConnection() throws {
    guard lifecycle == .admitted, connection != nil else {
      throw ConnectorBoundaryErrorV2.sessionFailed
    }
    connection = nil
  }

  func markEstablished() throws {
    guard lifecycle == .admitted else { throw ConnectorBoundaryErrorV2.sessionFailed }
    lifecycle = .established
  }

  func terminate() async {
    guard lifecycle != .terminated else { return }
    lifecycle = .terminated
    await connection?.close()
    connection = nil
  }
}

struct AdmittedCarrierV2: Sendable {
  let carrier: any TransportV2CarrierSession
  let binding: Data
}

struct AdmissionCommitV2: Sendable {
  let lease: ArtifactLeaseV2
  let attempt: CandidateAttemptV2

  func commit(inboundCapacity: UInt16) async throws -> AdmittedCarrierV2 {
    let connection = try await attempt.connectionForAdmission()
    let fsb2 = try AdmissionCodecV2.encodeFSB2(
      artifact: lease.artifact,
      chosenCandidateID: attempt.candidate.id
    )
    try Task.checkCancellation()
    try await lease.commitSpend()
    try Task.checkCancellation()
    try await connection.writeAdmission(fsb2)
    let response = try AdmissionCodecV2.decodeFSA2(try await connection.readAdmission())
    guard response.status == .success else { throw ConnectorBoundaryErrorV2.admissionFailed }
    try await attempt.markAdmitted()
    let carrier = try await connection.makeCarrier(inboundCapacity: inboundCapacity)
    guard carrier.chosenCarrier.rawValue == attempt.candidate.carrier else {
      throw ConnectorBoundaryErrorV2.admissionFailed
    }
    try await attempt.relinquishAdmittedConnection()
    return AdmittedCarrierV2(
      carrier: carrier,
      binding: Self.binding(fsb2)
    )
  }

  private static func binding(_ fsb2: Data) -> Data {
    var input = Data("flowersec-v2-admission\0".utf8)
    input.append(fsb2)
    return Data(SHA256.hash(data: input))
  }
}

struct SessionConnectorV2: Sendable {
  private let lease: ArtifactLeaseV2
  private let options: ConnectorOptions
  private let runtime: any RuntimeCarrierAdapterV2

  init(
    lease: ArtifactLeaseV2,
    options: ConnectorOptions,
    runtime: any RuntimeCarrierAdapterV2
  ) throws {
    try Self.validate(options, artifact: lease.artifact.value)
    do {
      try runtime.validate(options: options)
    } catch {
      throw ConnectErrorV2.invalidOptions
    }
    self.lease = lease
    self.options = options
    self.runtime = runtime
  }

  func connect() async throws -> any Session {
    do {
      let completion = ConnectorCompletionRaceV2<any Session>()
      let operation = Task<any Session, Error> { try await connectWithoutDeadline() }
      let timeout = Task<Void, Never> {
        do {
          try await Task.sleep(for: options.connectTimeout)
          if completion.resolve(.failure(ConnectErrorV2.timeout)) {
            operation.cancel()
          }
        } catch {
          return
        }
      }
      Task {
        let result: Result<any Session, Error>
        do {
          result = .success(try await operation.value)
        } catch {
          result = .failure(error)
        }
        if completion.resolve(result) {
          timeout.cancel()
        } else if case .success(let session) = result {
          try? await session.close()
        }
      }
      return try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
          completion.install(continuation)
        }
      } onCancel: {
        operation.cancel()
        timeout.cancel()
        completion.resolve(.failure(CancellationError()))
      }
    } catch is CancellationError {
      throw ConnectErrorV2.canceled
    } catch ConnectorBoundaryErrorV2.runtimeUnsupported {
      throw ConnectErrorV2.runtimeUnsupported
    } catch let error as ConnectErrorV2 {
      throw error
    } catch {
      throw ConnectErrorV2.connectionFailed
    }
  }

  private func connectWithoutDeadline() async throws -> any Session {
    try Task.checkCancellation()
    let artifact = lease.artifact.value
    guard artifact.session.initExpireAtUnixSeconds > Int64(Date().timeIntervalSince1970) else {
      throw ConnectErrorV2.expiredArtifact
    }
    let candidateSet = try AdmissionCodecV2.canonicalizeCandidates(lease.artifact)
    let path: PathKind = artifact.path.kind == "direct" ? .direct : .tunnel
    let role: SessionRoleV2 = artifact.path.role == 2 ? .server : .client
    let canonicalByID = Dictionary(
      uniqueKeysWithValues: candidateSet.candidates.map { ($0.id, $0) })
    let candidates = artifact.path.candidates.compactMap { declared -> CanonicalCandidateV2? in
      guard
        let candidate = canonicalByID[declared.id],
        runtime.capabilities.tuples.contains(where: {
          $0.carrier.rawValue == candidate.carrier && $0.path == path && $0.sessionRole == role
            && $0.networkMode == .dial
        })
      else { return nil }
      return candidate
    }
    guard !candidates.isEmpty else { throw ConnectorBoundaryErrorV2.runtimeUnsupported }

    let attempt = try await selectWinner(candidates: candidates, path: path, role: role)
    do {
      let admitted = try await AdmissionCommitV2(lease: lease, attempt: attempt).commit(
        inboundCapacity: artifact.session.maxInboundStreams + 2
      )
      do {
        let session = try await TransportV2Session.establish(
          carrier: admitted.carrier,
          config: try Self.sessionConfig(
            artifact: artifact,
            path: path,
            role: role,
            admissionBinding: admitted.binding
          )
        )
        try Task.checkCancellation()
        try await attempt.markEstablished()
        Task {
          _ = await session.waitClosed()
          await attempt.terminate()
        }
        return OpaqueSessionV2(session)
      } catch {
        admitted.carrier.abort(code: 6, reason: "session establishment failed")
        throw error
      }
    } catch {
      await attempt.terminate()
      throw error
    }
  }

  private func selectWinner(
    candidates: [CanonicalCandidateV2],
    path: PathKind,
    role: SessionRoleV2
  ) async throws -> CandidateAttemptV2 {
    let order = Dictionary(
      uniqueKeysWithValues: candidates.enumerated().map { ($0.element.id, $0.offset) })
    return try await withThrowingTaskGroup(of: CandidatePreparationResultV2.self) { group in
      for candidate in candidates {
        group.addTask {
          let attempt = CandidateAttemptV2(candidate: candidate)
          do {
            let connection = try await runtime.prepare(
              candidate: candidate,
              path: path,
              role: role,
              options: options
            )
            guard !Task.isCancelled else {
              await connection.close()
              return .failed
            }
            do {
              try await attempt.markReady(connection)
            } catch {
              await connection.close()
              throw error
            }
            return .ready(attempt)
          } catch {
            await attempt.terminate()
            return .failed
          }
        }
      }

      var winner: CandidateAttemptV2?
      var losers: [CandidateAttemptV2] = []
      while let result = try await group.next() {
        guard case .ready(let attempt) = result else { continue }
        if winner == nil {
          try await attempt.selectWinner()
          winner = attempt
          group.cancelAll()
        } else {
          losers.append(attempt)
        }
      }
      for loser in losers.sorted(by: {
        order[$0.candidate.id, default: Int.max] < order[$1.candidate.id, default: Int.max]
      }) {
        await loser.terminate()
      }
      guard let winner else { throw ConnectorBoundaryErrorV2.runtimeFailed }
      do {
        try Task.checkCancellation()
      } catch {
        await winner.terminate()
        throw error
      }
      return winner
    }
  }

  private static func validate(_ options: ConnectorOptions, artifact: ArtifactWireV2) throws {
    guard options.connectTimeout > .zero else { throw ConnectErrorV2.invalidOptions }
    if let origin = options.origin {
      guard let value = URLComponents(string: origin),
        value.host != nil, value.user == nil, value.password == nil,
        value.path.isEmpty || value.path == "/", value.query == nil, value.fragment == nil
      else { throw ConnectErrorV2.invalidOptions }
      let secureOrigin = value.scheme == "https"
      let loopbackPlaintextOrigin = value.scheme == "http"
        && (value.host == "127.0.0.1" || value.host == "::1")
        && rootlessLoopbackDirectOnly(artifact)
      guard secureOrigin || loopbackPlaintextOrigin else { throw ConnectErrorV2.invalidOptions }
    }
  }

  private static func rootlessLoopbackDirectOnly(_ artifact: ArtifactWireV2) -> Bool {
    guard artifact.path.kind == "direct", !artifact.path.candidates.isEmpty else { return false }
    return artifact.path.candidates.allSatisfy { candidate in
      guard candidate.carrier == "websocket", let value = URLComponents(string: candidate.url)
      else { return false }
      return value.scheme == "ws" && (value.host == "127.0.0.1" || value.host == "::1")
    }
  }

  private static func sessionConfig(
    artifact: ArtifactWireV2,
    path: PathKind,
    role: SessionRoleV2,
    admissionBinding: Data
  ) throws -> TransportV2SessionConfig {
    TransportV2SessionConfig(
      role: role,
      path: path,
      channelID: artifact.session.channelID,
      sessionContractHash: try decode32(artifact.session.contractHashBase64URL),
      suite: TransportCipherSuiteV2(rawValue: artifact.session.defaultSuite)!,
      psk: try decode32(artifact.session.e2eePSKBase64URL),
      maxInboundStreams: artifact.session.maxInboundStreams,
      idleTimeoutSeconds: artifact.session.idleTimeoutSeconds,
      localAdmissionBinding: admissionBinding,
      peerAdmissionBinding: path == .direct ? admissionBinding : Data(repeating: 0, count: 32),
      localEndpointInstanceID: artifact.path.localEndpointInstanceID ?? "",
      expectedPeerEndpointInstanceID: artifact.path.expectedPeerEndpointInstanceID ?? ""
    )
  }

  private static func decode32(_ value: String) throws -> Data {
    var text = value.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    text += String(repeating: "=", count: (4 - text.count % 4) % 4)
    guard let data = Data(base64Encoded: text), data.count == 32 else {
      throw ConnectorBoundaryErrorV2.sessionFailed
    }
    return data
  }
}

private final class ConnectorCompletionRaceV2<Value: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Value, Error>?
  private var result: Result<Value, Error>?

  func install(_ continuation: CheckedContinuation<Value, Error>) {
    let resolved = lock.withLock { () -> Result<Value, Error>? in
      if let result { return result }
      self.continuation = continuation
      return nil
    }
    if let resolved { continuation.resume(with: resolved) }
  }

  @discardableResult
  func resolve(_ result: Result<Value, Error>) -> Bool {
    var continuation: CheckedContinuation<Value, Error>?
    let won = lock.withLock { () -> Bool in
      guard self.result == nil else { return false }
      self.result = result
      continuation = self.continuation
      self.continuation = nil
      return true
    }
    continuation?.resume(with: result)
    return won
  }
}
