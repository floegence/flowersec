import Foundation

public enum ConnectionPhase: String, Equatable, Sendable {
  case notStarted = "not_started", spentNotAdmitted = "spent_not_admitted"
  case admittedNotReady = "admitted_not_ready", ready, unknown
}
public enum ConnectionSpendState: String, Equatable, Sendable { case unspent, spent, unknown }
public enum ConnectionSpent: String, Equatable, Sendable { case no = "false", yes = "true", unknown }
public enum ConnectionAdmissionState: String, Equatable, Sendable {
  case notStarted = "not_started", inFlight = "in_flight", admitted, unknown
}
public enum ConnectionNetworkReady: String, Equatable, Sendable { case notStarted = "not_started", ready, unknown }
public enum ConnectionApplicationPublish: String, Equatable, Sendable {
  case notStarted = "not_started", published, failed, unknown
}
public enum ConnectionSourceProfile: String, Equatable, Sendable {
  case preauthorizedPool = "preauthorized_pool", liveAuthority = "live_authority"
}
public enum ConnectionQueryAvailability: String, Equatable, Sendable { case unavailable }

/// Detached observations. These values carry no material, key, Session or activation authority.
public struct ConnectionAttemptFacts: Equatable, Sendable {
  public let spendState: ConnectionSpendState
  public let admissionState: ConnectionAdmissionState
  public let networkReady: ConnectionNetworkReady
  public let applicationPublish: ConnectionApplicationPublish
  public let sourceProfile: ConnectionSourceProfile?
  public let queryAvailability: ConnectionQueryAvailability
  public var spent: ConnectionSpent {
    switch spendState { case .unspent: .no; case .spent: .yes; case .unknown: .unknown }
  }
  public var phase: ConnectionPhase {
    if networkReady == .ready { return .ready }
    if admissionState == .admitted { return .admittedNotReady }
    if spendState == .unknown || admissionState == .unknown || admissionState == .inFlight || networkReady == .unknown { return .unknown }
    return spendState == .spent ? .spentNotAdmitted : .notStarted
  }
  var permitsAutomaticRetry: Bool {
    phase == .notStarted && spendState == .unspent && applicationPublish == .notStarted
  }
  static let notStarted = ConnectionAttemptFacts(spendState: .unspent, admissionState: .notStarted,
    networkReady: .notStarted, applicationPublish: .notStarted, sourceProfile: nil, queryAvailability: .unavailable)
  static let unobserved = ConnectionAttemptFacts(spendState: .unknown, admissionState: .unknown,
    networkReady: .unknown, applicationPublish: .unknown, sourceProfile: nil, queryAvailability: .unavailable)
}

/// An explanation of existing facts. Building a report reserves no work and performs no query.
public struct LocalReport: Equatable, Sendable {
  public enum Constraint: String, Equatable, Sendable { case configuration, resource, source, connection, unavailable }
  public enum Reservation: String, Equatable, Sendable { case notReserved = "not_reserved" }
  public enum Action: String, Equatable, Sendable { case inspectConfiguration = "inspect_configuration", endConnection = "end_connection" }
  public let code: String
  public let constraint: Constraint
  public let required: UInt64?
  public let available: UInt64?
  public let reservation: Reservation
  public let connection: ConnectionAttemptFacts
  public let cleanup: CleanupStatus
  public let actions: [Action]
  init(code: String, connection: ConnectionAttemptFacts, cleanup: CleanupStatus) {
    self.code = code; self.connection = connection; self.cleanup = cleanup
    constraint = code == "invalid_material" || code == "unsupported" ? .configuration :
      code == "resource_exhausted" ? .resource : code == "exhausted" || code == "generation_conflict" ? .source : .connection
    required = nil; available = nil; reservation = .notReserved
    actions = constraint == .configuration ? [.inspectConfiguration] : connection.phase == .notStarted ? [] : [.endConnection]
  }
}

// Only original connection owners record cutpoints. This bounded value storage
// retains no provider, callback, credential or protocol graph.
final class V4ConnectionFacts: @unchecked Sendable {
  private let gate = NSLock()
  private var spend: ConnectionSpendState = .unspent
  private var admission: ConnectionAdmissionState = .notStarted
  private var ready: ConnectionNetworkReady = .notStarted
  private var publication: ConnectionApplicationPublish = .notStarted
  private let source: ConnectionSourceProfile?
  #if os(macOS) || os(iOS)
  private var diagnostic: V4DiagnosticContext?
  private var diagnosticCounters: V4DiagnosticCounters?
  func observeDiagnostic(_ context: V4DiagnosticContext?, counters: V4DiagnosticCounters) {
    gate.withLock { diagnostic = context; diagnosticCounters = counters }
  }
  func diagnosticClosed() { gate.withLock { diagnostic }?.emit(.closed) }
  #endif
  init(source: ConnectionSourceProfile? = nil) { self.source = source }
  func spendDispatched() { gate.withLock { if spend == .unspent { spend = .unknown } } }
  func spent() { gate.withLock { spend = .spent } }
  func admissionDispatched() { gate.withLock { if admission == .notStarted { admission = .inFlight } } }
  func admissionRejected() { gate.withLock { if admission != .admitted { admission = .notStarted } } }
  func spendConfirmedAbsent() { gate.withLock { if spend == .unknown { spend = .unspent } } }
  func admitted() { gate.withLock { admission = .admitted } }
  func networkReady() { gate.withLock { ready = .ready; admission = .admitted } }
  func published() {
    let changed = gate.withLock { () -> Bool in
      guard publication == .notStarted else { return false }; publication = .published; return true
    }
    #if os(macOS) || os(iOS)
    if changed { gate.withLock { diagnostic }?.emit(.succeeded) }
    #endif
  }
  func publicationFailed() {
    let changed = gate.withLock { () -> Bool in
      guard publication != .published && publication != .failed else { return false }; publication = .failed; return true
    }
    #if os(macOS) || os(iOS)
    if changed {
      let observation = gate.withLock { (diagnostic, diagnosticCounters) }
      observation.1?.increment(.connectionFailures)
      observation.0?.emit(.failed, code: .operationFailed, retry: .terminal)
    }
    #endif
  }
  func finishFailure() { gate.withLock {
    if admission == .inFlight { admission = .unknown }
    if ready == .notStarted && admission == .unknown { ready = .notStarted }
  } }
  func snapshot() -> ConnectionAttemptFacts {
    gate.withLock { ConnectionAttemptFacts(spendState: spend, admissionState: admission, networkReady: ready,
      applicationPublish: publication, sourceProfile: source, queryAvailability: .unavailable) }
  }
}

protocol V4ConnectionFactsOwner: Sendable { var connectionFactsOwner: V4ConnectionFacts { get } }
