import Foundation

struct V4PreparedServiceRequest: Sendable {
  let header: V4ApplicationHeader
  let reference: OperationReference?
  let preparationEnd: UInt64
  init(client: ServiceClient, method: MethodDefinition, snapshot: ServiceContractSnapshot,
    payload: Data, options: ServiceCallOptions, resume: Bool = false) throws {
    try client.checkAdmission(); try options.context?.checkCancellation()
    guard let interval = client.environment.clock.sample().interval, interval.upperMS < options.deadlineAtMS,
      payload.count <= (try snapshot.contract.uint(23)) else { throw ServiceFailure.deadlineExceeded }
    let contract = snapshot.contract
    let execution = method.semantics == .execution
    if execution, client.session.serviceManagement == nil { throw ServiceFailure.serviceUnavailable }
    let responseLimit = method.shape == .notify ? 0 : options.responseLimitBytes ?? method.options.maxResponseBytes
    guard responseLimit >= (try contract.uint(9)), responseLimit <= (try contract.uint(10)) else { throw ServiceFailure.contractMismatch }
    let mode: UInt64 = options.context != nil || options.admissionMode == .tryNow ? 1 : 0
    let kind: String
    if resume { kind = "resume_request" }
    else if method.shape == .notify { kind = execution ? "execution_notify" : "observation_notify" }
    else if method.shape == .serverStreaming { kind = execution ? "execution_stream_request" : "transient_stream_request" }
    else { kind = execution ? "execution_unary_request" : "transient_unary_request" }
    var fields: [Int: V4ApplicationHeader.Scalar] = [2: .uint(UInt64(method.typeID)), 3: .uint(UInt64(payload.count)),
      5: .uint(options.deadlineAtMS), 6: .bytes(contract.digest)]
    if method.shape != .notify || execution { fields[7] = .uint(mode); fields[8] = .uint(UInt64(responseLimit)) }
    let registry = client.channel.registry
    if execution {
      guard let offer = snapshot.offer, let authority = client.target.executionCallerAuthority,
        let cutoff = options.admissionNotAfterMS, cutoff > 0, cutoff <= options.deadlineAtMS,
        options.deadlineAtMS - cutoff <= (try contract.uint(17)) else { throw ServiceFailure.admissionWindowClosed }
      try offer.check(contract: contract, cutoff: cutoff, environment: client.environment)
      var operation = try V4Crypto.random(32)
      operation.replaceSubrange(0..<8, with: V4Crypto.integer(cutoff, width: 8))
      fields[1] = .bytes(operation); fields[4] = .bytes(Data(repeating: 0, count: 32))
      let temporary = try V4ApplicationHeader(kind: kind, fields: fields, registry: registry)
      let digest = try contract.executionRequestDigest(header: temporary, payload: payload)
      fields[4] = .bytes(digest)
      reference = try OperationReference(target: client.target, authority: authority, namespace: client.definition.namespace,
        operation: operation, request: digest, contract: contract.digest, shape: method.shape, durable: contract.uint(13) == 1,
        deadline: options.deadlineAtMS, cancellation: contract.uint(19) == 1, limit: responseLimit)
      preparationEnd = cutoff
    } else {
      guard options.admissionNotAfterMS == nil, options.deadlineAtMS - interval.upperMS <= (try contract.uint(11)) else {
        throw ServiceFailure.deadlineExceeded
      }
      reference = nil; preparationEnd = options.deadlineAtMS
    }
    header = try V4ApplicationHeader(kind: kind, fields: fields, registry: registry)
  }
}
