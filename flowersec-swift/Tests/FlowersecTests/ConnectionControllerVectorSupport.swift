import Foundation

struct ConnectionControllerVectorDocument: Decodable {
  let version: Int
  let states: [String]
  let retryDispositions: [String]
  let defaults: ConnectionControllerVectorDefaults
  let backoffVectors: [ConnectionControllerBackoffVector]
  let scenarios: [ConnectionControllerVectorScenario]
  let invariants: ConnectionControllerVectorInvariants

  enum CodingKeys: String, CodingKey {
    case version, states, defaults, scenarios, invariants
    case retryDispositions = "retry_dispositions"
    case backoffVectors = "backoff_vectors"
  }
}

struct ConnectionControllerVectorDefaults: Decodable {
  let initialDelayMilliseconds: Int
  let maximumDelayMilliseconds: Int
  let factor: UInt64
  let jitterRatio: Double
  let attemptLimit: UInt64?

  enum CodingKeys: String, CodingKey {
    case factor
    case initialDelayMilliseconds = "initial_delay_ms"
    case maximumDelayMilliseconds = "max_delay_ms"
    case jitterRatio = "jitter_ratio"
    case attemptLimit = "attempt_limit"
  }
}

struct ConnectionControllerBackoffVector: Decodable {
  let consecutiveFailure: UInt64
  let delayMilliseconds: Int

  enum CodingKeys: String, CodingKey {
    case consecutiveFailure = "consecutive_failure"
    case delayMilliseconds = "delay_ms"
  }
}

struct ConnectionControllerVectorInvariants: Decodable {
  let oneShotArtifactController: String
  let freshArtifactPerAttempt: Bool
  let singleScheduler: Bool
  let singleInFlightAttempt: Bool
  let startIdempotent: Bool
  let closeIdempotent: Bool
  let retryNowOutsideWaiting: Bool
  let retryAfterBypass: Bool
  let subordinateCloseFailurePropagates: Bool
  let publicRetryConfiguration: [String]
  let oldStreamMigration: Bool
  let rpcReplay: Bool
  let writeReplay: Bool
  let crossSessionExactlyOnce: Bool

  enum CodingKeys: String, CodingKey {
    case oneShotArtifactController = "one_shot_artifact_controller"
    case freshArtifactPerAttempt = "fresh_artifact_per_attempt"
    case singleScheduler = "single_scheduler"
    case singleInFlightAttempt = "single_in_flight_attempt"
    case startIdempotent = "start_idempotent"
    case closeIdempotent = "close_idempotent"
    case retryNowOutsideWaiting = "retry_now_outside_waiting"
    case retryAfterBypass = "retry_after_bypass"
    case subordinateCloseFailurePropagates = "subordinate_close_failure_propagates"
    case publicRetryConfiguration = "public_retry_configuration"
    case oldStreamMigration = "old_stream_migration"
    case rpcReplay = "rpc_replay"
    case writeReplay = "write_replay"
    case crossSessionExactlyOnce = "cross_session_exactly_once"
  }
}

struct ConnectionControllerVectorScenario: Decodable {
  let name: String
  let events: [String]
  let states: [String]
  let artifactAcquisitions: Int?
  let schedulerCount: Int?
  let maxInFlightAttempts: Int?
  let retryAtUnixMilliseconds: Int?
  let clockStartUnixMilliseconds: Int?
  let sessions: [String]?
  let replay: [String]?
  let policy: ConnectionControllerVectorPolicy?
  let retryNowResults: [Bool]?
  let closeCalls: Int?
  let cleanupCalls: Int?

  enum CodingKeys: String, CodingKey {
    case name, events, states, sessions, replay, policy
    case artifactAcquisitions = "artifact_acquisitions"
    case schedulerCount = "scheduler_count"
    case maxInFlightAttempts = "max_in_flight_attempts"
    case retryAtUnixMilliseconds = "retry_at_unix_ms"
    case clockStartUnixMilliseconds = "clock_start_unix_ms"
    case retryNowResults = "retry_now_results"
    case closeCalls = "close_calls"
    case cleanupCalls = "cleanup_calls"
  }
}

struct ConnectionControllerVectorPolicy: Decodable {
  let maximumAttempts: UInt64

  enum CodingKeys: String, CodingKey {
    case maximumAttempts = "max_attempts"
  }
}

func loadConnectionControllerVectors() throws -> ConnectionControllerVectorDocument {
  let url = packageRoot().appendingPathComponent(
    "testdata/transport_v2/connection_controller_vectors.json")
  return try JSONDecoder().decode(
    ConnectionControllerVectorDocument.self,
    from: Data(contentsOf: url)
  )
}

func connectionControllerScenario(named name: String) throws -> ConnectionControllerVectorScenario {
  let document = try loadConnectionControllerVectors()
  guard let scenario = document.scenarios.first(where: { $0.name == name }) else {
    throw ConnectionControllerVectorError.missingScenario(name)
  }
  return scenario
}

private enum ConnectionControllerVectorError: Error {
  case missingScenario(String)
}
