import CoreFoundation
import Crypto
import Foundation

let openRejectResourceExhaustedReasonV2: UInt16 = 2

public actor TransportV2Session: SessionV2 {
  public nonisolated let path: PathKind
  public nonisolated let chosenCarrier: CarrierKind
  public nonisolated let endpointInstanceID: String?
  public nonisolated let rpc: any RPCPeerV2

  private let carrier: any TransportV2CarrierSession
  private let controlReader: TransportV2CarrierReader
  private let controlWriter: TransportV2CarrierWriter
  private let config: TransportV2SessionConfig
  private let h3: Data
  private let sendDirection: TransportDirectionV2
  private let receiveDirection: TransportDirectionV2

  private var sendRoots: [UInt32: EpochRootsV2]
  private var receiveRoots: [UInt32: EpochRootsV2]
  private var sendEpoch: UInt32 = 0
  private var receiveEpoch: UInt32 = 0
  private var controlReceiveEpoch: UInt32 = 0
  private var controlSendSequence: UInt64 = 0
  private var controlReceiveSequence: UInt64 = 0
  private var controlSendExhausted = false
  private var controlReceiveExhausted = false
  private var nextLogicalStreamID: UInt64
  private var localOpenedHighWatermark: UInt64 = 0
  private var nextPing: UInt64 = 1
  private var nextTransition: UInt64 = 1
  private var receivedTransition: UInt64 = 0
  private var streams: [UInt64: TransportV2ByteStream] = [:]
  private var outboundLedger: TransportV2StreamLedger
  private var peerLedger: TransportV2StreamLedger
  private var sentGoAway = false
  private var sentGoAwayLastAccepted: UInt64 = 0
  private var receivedGoAway = ReceivedGoAwayStateV2()
  private var activeOpenOperations = 0
  private var openOperationWaiters: [UInt64: CheckedContinuation<Void, Error>] = [:]
  private var activeInboundResponders = 0
  private var localInboundRespondersFrozen = false
  private var peerInboundRespondersFrozen = false
  private var inboundResponderWaiters: [UInt64: CheckedContinuation<Void, Error>] = [:]
  private var inboundApplicationStreams = 0
  private var outboundApplicationStreams = 0
  private var incoming: [IncomingStreamV2] = []
  private var incomingWaiters: [UInt64: CheckedContinuation<IncomingStreamV2, Error>] = [:]
  private var incomingWaiterOrder: [UInt64] = []
  private var nextIncomingWaiterID: UInt64 = 1
  private var pings: [UInt64: PingWaiterV2] = [:]
  private var rpcClient: RPCClient?
  private var rpcServerClaimed = false
  private var rpcServerTask: Task<Void, Never>?
  private var rekeyInProgress = false
  private var rekeyWaiters: [UInt64: CheckedContinuation<Void, Error>] = [:]
  private var activeRekeyPreparations: Set<UInt64> = []
  private var failedRekeyPreparations: Set<UInt64> = []
  private var nextLifecycleWaiterID: UInt64 = 1
  private var pendingRekey: PendingSessionRekeyV2?
  private var lastAcceptedSessionRekeyACK: Data?
  private var pendingReceiveRekeyTransition: UInt64?
  private var terminationError: TransportV2SessionError?
  private var terminationWaiters: [CheckedContinuation<TransportV2SessionError, Never>] = []
  private var controlTask: Task<Void, Never>?
  private var acceptTask: Task<Void, Never>?
  private var idleTask: Task<Void, Never>?
  private var activityGeneration: UInt64 = 0
  private var closeDeadlineTask: Task<Void, Never>?
  private var closeWorkTask: Task<Void, Never>?
  private var closeGeneration: UInt64 = 0
  private var closeSignal: TransportV2CloseSignal?
  private var closing = false
  private var closed = false

  private init(
    carrier: any TransportV2CarrierSession,
    control: any TransportV2CarrierStream,
    config: TransportV2SessionConfig,
    material: TransportV2HandshakeMaterial,
    rpc: any RPCPeerV2
  ) throws {
    self.carrier = carrier
    self.config = config
    self.h3 = material.h3
    controlReader = TransportV2CarrierReader(stream: control)
    controlWriter = TransportV2CarrierWriter(stream: control)
    path = config.path
    chosenCarrier = carrier.chosenCarrier
    endpointInstanceID = config.path == .tunnel ? config.expectedPeerEndpointInstanceID : nil
    self.rpc = rpc

    switch config.role {
    case .client:
      sendDirection = .clientToServer
      receiveDirection = .serverToClient
      nextLogicalStreamID = 1
      outboundLedger = TransportV2StreamLedger(openerRole: .client)
      peerLedger = TransportV2StreamLedger(openerRole: .server)
    case .server:
      sendDirection = .serverToClient
      receiveDirection = .clientToServer
      nextLogicalStreamID = 2
      outboundLedger = TransportV2StreamLedger(openerRole: .server)
      peerLedger = TransportV2StreamLedger(openerRole: .client)
    }
    sendRoots = [
      0: try TransportV2Crypto.deriveEpochZero(
        sessionPRK: material.sessionPRK,
        direction: sendDirection
      )
    ]
    receiveRoots = [
      0: try TransportV2Crypto.deriveEpochZero(
        sessionPRK: material.sessionPRK,
        direction: receiveDirection
      )
    ]
  }

  public static func establish(
    carrier: any TransportV2CarrierSession,
    config: TransportV2SessionConfig
  ) async throws -> TransportV2Session {
    try await withTaskCancellationHandler {
      try await withThrowingTaskGroup(of: TransportV2Session.self) { group in
        group.addTask {
          try await establishWithoutDeadline(carrier: carrier, config: config)
        }
        group.addTask {
          try await Task.sleep(for: config.deadlines.establish)
          carrier.abort(code: 6, reason: "session establish timeout")
          throw TransportV2SessionError.handshakeFailed
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else {
          throw TransportV2SessionError.handshakeFailed
        }
        return result
      }
    } onCancel: {
      carrier.abort(code: 6, reason: "session establish cancelled")
    }
  }

  private static func establishWithoutDeadline(
    carrier: any TransportV2CarrierSession,
    config: TransportV2SessionConfig
  ) async throws -> TransportV2Session {
    let (control, material) = try await TransportV2Handshake.perform(
      carrier: carrier,
      config: config
    )
    let rpcReference = TransportV2RPCReference()
    let session = try TransportV2Session(
      carrier: carrier,
      control: control,
      config: config,
      material: material,
      rpc: rpcReference
    )
    rpcReference.bind(session)
    do {
      try await session.finishReadyBoundary()
      await session.startLoops()
      return session
    } catch {
      carrier.abort(code: 6, reason: "session ready failed")
      throw TransportV2SessionError.protocolViolation
    }
  }

  public func openStream(
    kind: String,
    metadata: StreamMetadataV2
  ) async throws -> any ByteStreamV2 {
    try await openStream(kind: kind, metadata: metadata, internalRPC: false)
  }

  public func acceptStream() async throws -> IncomingStreamV2 {
    try Task.checkCancellation()
    guard !closing, !closed else { throw TransportV2SessionError.closed }
    if !incoming.isEmpty { return incoming.removeFirst() }
    let waiterID = nextIncomingWaiterID
    nextIncomingWaiterID &+= 1
    if nextIncomingWaiterID == 0 { nextIncomingWaiterID = 1 }
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<IncomingStreamV2, Error>) in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
        } else if closing || closed {
          continuation.resume(throwing: TransportV2SessionError.closed)
        } else {
          incomingWaiters[waiterID] = continuation
          incomingWaiterOrder.append(waiterID)
        }
      }
    } onCancel: {
      Task { await self.cancelIncomingWaiter(waiterID) }
    }
  }

  public func rekey() async throws {
    let requestID = allocateLifecycleWaiterID()
    try await withTaskCancellationHandler {
      try await runRekey(requestID: requestID)
    } onCancel: {
      Task { await self.cancelRekeyPreparation(requestID: requestID) }
    }
  }

  private func runRekey(requestID: UInt64) async throws {
    activeRekeyPreparations.insert(requestID)
    let preparationDeadline = startRekeyPreparationDeadline(
      requestID: requestID,
      duration: config.deadlines.rekeyPrepare
    )
    defer {
      preparationDeadline.cancel()
      activeRekeyPreparations.remove(requestID)
      failedRekeyPreparations.remove(requestID)
      removeLifecycleWaiter(requestID)
    }

    while rekeyInProgress {
      guard !closing, !closed else { throw TransportV2SessionError.closed }
      try await waitForRekeyGate(requestID: requestID)
      try checkRekeyPreparation(requestID: requestID)
    }
    guard !closing, !closed else { throw TransportV2SessionError.closed }
    rekeyInProgress = true
    var inboundRespondersFrozen = false
    defer {
      if inboundRespondersFrozen { unfreezeInboundResponders(peerInitiated: false) }
      finishRekeyGate()
    }

    var committed = false
    var nextEpochToRollback: UInt32? = nil
    do {
      while activeOpenOperations != 0 {
        guard !closing, !closed else { throw TransportV2SessionError.closed }
        try await waitForActiveOpenOperations(requestID: requestID)
        try checkRekeyPreparation(requestID: requestID)
      }
      try await freezeInboundResponders(peerInitiated: false, waiterID: requestID)
      inboundRespondersFrozen = true
      try checkRekeyPreparation(requestID: requestID)

      let watermark = localHighWatermark()
      guard outboundLedger.frontier == watermark else {
        throw TransportV2SessionError.rekeyFailed
      }
      guard sendEpoch != UInt32.max, nextTransition != 0 else {
        try? await sendGoAway(reason: 5)
        throw TransportV2SessionError.resourceExhausted
      }
      let transition = nextTransition
      let nextEpoch = sendEpoch + 1
      nextEpochToRollback = nextEpoch
      guard let currentRoots = sendRoots[sendEpoch] else {
        throw TransportV2SessionError.rekeyFailed
      }
      let nextSecret = try TransportV2Crypto.deriveNextEpoch(
        rekeyRoot: currentRoots.rekeyRoot,
        h3: h3,
        direction: sendDirection,
        nextEpoch: nextEpoch
      )
      sendRoots[nextEpoch] = try TransportV2Crypto.deriveEpochRoots(epochSecret: nextSecret)
      try checkRekeyPreparation(requestID: requestID)

      let waiter = PendingSessionRekeyV2(
        transition: transition,
        epoch: nextEpoch,
        watermark: watermark
      )
      nextTransition &+= 1
      pendingRekey = waiter
      preparationDeadline.cancel()
      activeRekeyPreparations.remove(requestID)
      failedRekeyPreparations.remove(requestID)
      committed = true
      let completionDeadline = startRekeyDeadline(
        transition: transition,
        duration: config.deadlines.rekeyCompletion
      )
      defer { completionDeadline.cancel() }

      var streamWaiters: [RekeySignalV2] = []
      let activeStreams = Array(streams.values)
      for stream in activeStreams {
        if let signal = try await stream.beginSendRekey(
          transition: transition,
          nextEpoch: nextEpoch
        ) {
          streamWaiters.append(signal)
        }
      }
      try await sendControl(.sessionKeyUpdate, payload: waiter.payload)
      try await waiter.wait()
      for signal in streamWaiters { try await signal.wait() }
      pendingRekey = nil
      trimSendRoots()
    } catch {
      pendingRekey = nil
      if !committed {
        if let nextEpochToRollback { sendRoots.removeValue(forKey: nextEpochToRollback) }
        if error is CancellationError || Task.isCancelled { throw CancellationError() }
        if let sessionError = error as? TransportV2SessionError { throw sessionError }
        throw TransportV2SessionError.rekeyFailed
      }
      await failProtocol()
      throw TransportV2SessionError.rekeyFailed
    }
  }

  public func probeLiveness() async throws -> Duration {
    guard !closing, !closed else { throw TransportV2SessionError.closed }
    let nonce = nextPing
    guard nonce != 0 else { throw TransportV2SessionError.resourceExhausted }
    nextPing &+= 1
    let waiter = PingWaiterV2(started: ContinuousClock.now)
    pings[nonce] = waiter
    var payload = Data()
    payload.appendUInt64BE(nonce)
    do {
      try await sendControl(.ping, payload: payload)
      return try await waiter.wait(timeout: config.deadlines.liveness)
    } catch {
      pings.removeValue(forKey: nonce)
      if error is CancellationError { throw CancellationError() }
      throw TransportV2SessionError.livenessFailed
    }
  }

  public func waitClosed() async -> TransportV2SessionError {
    if let terminationError { return terminationError }
    return await withCheckedContinuation { continuation in
      if let terminationError {
        continuation.resume(returning: terminationError)
      } else {
        terminationWaiters.append(continuation)
      }
    }
  }

  public func close() async {
    if closed { return }
    let signal = initiateClose(
      goAwayReason: 1,
      closeReason: 1,
      carrierCode: 1,
      carrierReason: "session closed",
      terminalError: .closed
    )
    await signal.wait()
  }

  func sendGoAway(reason: UInt16, allowWhileClosing: Bool = false) async throws {
    guard reason != 0 else { throw TransportV2SessionError.protocolViolation }
    let lastAccepted = peerHighWatermark()
    if sentGoAway, sentGoAwayLastAccepted != lastAccepted {
      throw TransportV2SessionError.protocolViolation
    }
    sentGoAway = true
    sentGoAwayLastAccepted = lastAccepted
    try await sendControl(
      .goAway,
      payload: idReasonPayload(id: lastAccepted, reason: reason),
      allowWhileClosing: allowWhileClosing
    )
  }

  fileprivate func root(
    direction: TransportDirectionV2,
    epoch: UInt32
  ) throws -> EpochRootsV2 {
    let roots = direction == sendDirection ? sendRoots[epoch] : receiveRoots[epoch]
    guard let roots else { throw TransportV2SessionError.protocolViolation }
    return roots
  }

  fileprivate func sendStreamReset(id: UInt64) async {
    guard !closing, !closed else { return }
    do {
      try await sendStreamResetRecord(id: id)
    } catch {
      await failProtocol()
    }
  }

  private func sendStreamResetRecord(id: UInt64) async throws {
    try await sendControl(.streamReset, payload: idReasonPayload(id: id, reason: 6))
    if isPeerLogicalStreamID(id) {
      try peerLedger.localResetCommitted(id)
    } else if isLocalLogicalStreamID(id) {
      try outboundLedger.localResetCommitted(id)
    } else {
      throw TransportV2SessionError.protocolViolation
    }
  }

  private func commitOutboundReset(id: UInt64) async throws {
    guard isLocalLogicalStreamID(id) else {
      throw TransportV2SessionError.protocolViolation
    }
    if outboundLedger.state(of: id) == .usedOrTerminal { return }
    try await sendStreamResetRecord(id: id)
  }

  fileprivate func streamFinished(id: UInt64, inbound: Bool, internalRPC: Bool) {
    guard streams.removeValue(forKey: id) != nil, !internalRPC else { return }
    if inbound {
      inboundApplicationStreams = max(0, inboundApplicationStreams - 1)
    } else {
      outboundApplicationStreams = max(0, outboundApplicationStreams - 1)
    }
  }

  fileprivate func rpcClientForUse() async throws -> RPCClient {
    if let rpcClient { return rpcClient }
    let stream = try await openStream(
      kind: TransportV2ByteStream.reservedRPCStreamKind,
      metadata: .empty,
      internalRPC: true
    )
    let client = RPCClient(stream: TransportV2RPCStreamAdapter(stream: stream), path: rpcPath)
    await client.start()
    rpcClient = client
    return client
  }

  private func openStream(
    kind: String,
    metadata: StreamMetadataV2,
    internalRPC: Bool
  ) async throws -> TransportV2ByteStream {
    let waiterID = allocateLifecycleWaiterID()
    while rekeyInProgress {
      guard !closing, !closed else { throw TransportV2SessionError.closed }
      try await waitForRekeyGate(requestID: waiterID)
    }
    guard !closing, !closed else { throw TransportV2SessionError.closed }
    guard !sentGoAway, !receivedGoAway.wasReceived else {
      throw TransportV2SessionError.goingAway
    }
    activeOpenOperations += 1
    defer { finishOpenOperation() }
    guard internalRPC || kind != TransportV2ByteStream.reservedRPCStreamKind else {
      throw TransportV2SessionError.openRejected(1)
    }
    try Task.checkCancellation()
    let metadataRaw = try TransportV2MetadataCodec.encode(metadata)
    _ = try OpenPayloadV2(
      logicalStreamID: 1,
      fss2Hash: Data(repeating: 0, count: 32),
      kind: kind,
      metadata: metadataRaw
    ).encoded()
    if !internalRPC {
      guard outboundApplicationStreams < Int(config.maxInboundStreams) else {
        throw TransportV2SessionError.resourceExhausted
      }
      outboundApplicationStreams += 1
    }
    var releasePermit = !internalRPC
    defer {
      if releasePermit { outboundApplicationStreams -= 1 }
    }

    let id = nextLogicalStreamID
    let maximumID: UInt64 = config.role == .client ? 2_097_151 : 2_097_152
    guard id != 0, id <= maximumID else {
      try? await sendGoAway(reason: 5)
      throw TransportV2SessionError.resourceExhausted
    }
    guard localOpeningAllowedAfterGoAway(id) else {
      throw TransportV2SessionError.goingAway
    }
    try outboundLedger.validFSS2(id)
    nextLogicalStreamID = id == maximumID ? 0 : id + 2
    localOpenedHighWatermark = id
    let initialEpoch = sendEpoch
    guard let roots = sendRoots[initialEpoch] else {
      throw TransportV2SessionError.protocolViolation
    }
    let carrierStream: any TransportV2CarrierStream
    do {
      carrierStream = try await carrier.openStream()
    } catch {
      do {
        try await commitOutboundReset(id: id)
      } catch {
        await failProtocol()
      }
      throw error
    }
    guard localOpeningAllowedAfterGoAway(id) else {
      await carrierStream.reset(code: 6)
      try await commitOutboundReset(id: id)
      throw TransportV2SessionError.goingAway
    }
    do {
      return try await withTaskCancellationHandler {
        var preface = try SetupPrefaceV2(
          openerRole: openerRole,
          logicalStreamID: id,
          initialEpoch: initialEpoch
        )
        preface = try preface.withSetupMAC(
          TransportV2Crypto.computeSetupMAC(
            setupRoot: roots.setupRoot,
            h3: h3,
            preface: preface
          )
        )
        let rawPreface = try preface.encoded()
        try await TransportV2Handshake.writeAll(rawPreface, to: carrierStream)
        try Task.checkCancellation()
        guard localOpeningAllowedAfterGoAway(id) else {
          throw TransportV2SessionError.goingAway
        }
        let fss2Hash = Data(SHA256.hash(data: rawPreface))
        let openRaw = try OpenPayloadV2(
          logicalStreamID: id,
          fss2Hash: fss2Hash,
          kind: kind,
          metadata: metadataRaw
        ).encoded()
        let stream = TransportV2ByteStream(
          session: self,
          carrier: carrierStream,
          suite: config.suite,
          h3: h3,
          sendDirection: sendDirection,
          receiveDirection: receiveDirection,
          id: id,
          kind: kind,
          inbound: false,
          internalRPC: internalRPC,
          sendEpoch: initialEpoch,
          receiveEpoch: receiveEpoch,
          sendSequence: 0,
          receiveSequence: 0
        )
        streams[id] = stream
        try await stream.sendOpen(openRaw)
        let rejection = try await stream.receiveOpenResponse(
          expectedOpenHash: Data(SHA256.hash(data: openRaw))
        )
        try outboundLedger.validOpen(id)
        if let rejection {
          throw TransportV2SessionError.openRejected(rejection)
        }
        try Task.checkCancellation()
        guard localOpeningAllowedAfterGoAway(id) else {
          throw TransportV2SessionError.goingAway
        }
        releasePermit = false
        return stream
      } onCancel: {
        Task { await carrierStream.reset(code: 6) }
      }
    } catch {
      streams.removeValue(forKey: id)
      await carrierStream.reset(code: 6)
      do {
        switch outboundLedger.state(of: id) {
        case .openSeen:
          try await commitOutboundReset(id: id)
        case .usedOrTerminal:
          let wasRejected: Bool
          if let sessionError = error as? TransportV2SessionError,
            case .openRejected = sessionError
          {
            wasRejected = true
          } else {
            wasRejected = false
          }
          if Task.isCancelled || !wasRejected {
            try await sendStreamResetRecord(id: id)
          }
        case .unseen, .abandonedNoFSS2:
          throw TransportV2SessionError.protocolViolation
        }
      } catch {
        await failProtocol()
      }
      if Task.isCancelled { throw CancellationError() }
      if !localOpeningAllowedAfterGoAway(id) {
        throw TransportV2SessionError.goingAway
      }
      throw error
    }
  }

  private var openerRole: StreamOpenerRoleV2 {
    config.role == .client ? .client : .server
  }

  private var peerOpenerRole: StreamOpenerRoleV2 {
    config.role == .client ? .server : .client
  }

  private func finishReadyBoundary() async throws {
    switch config.role {
    case .server:
      try await sendControl(.sessionReady, payload: Data())
      let (type, _) = try await readControl()
      guard type == .sessionReadyACK else { throw TransportV2SessionError.protocolViolation }
    case .client:
      let (type, _) = try await readControl()
      guard type == .sessionReady else { throw TransportV2SessionError.protocolViolation }
      try await sendControl(.sessionReadyACK, payload: Data())
    }
  }

  private func startLoops() {
    controlTask = Task { [weak self] in await self?.controlLoop() }
    acceptTask = Task { [weak self] in await self?.acceptLoop() }
    touchActivity()
  }

  private func controlLoop() async {
    do {
      while !closed {
        let (type, payload) = try await readControl()
        try await handleControl(type, payload: payload)
      }
    } catch {
      if !closed, !closing { await failProtocol() }
    }
  }

  private func acceptLoop() async {
    do {
      while !closed {
        let stream = try await carrier.acceptStream()
        Task { [weak self] in await self?.acceptCarrierStream(stream) }
      }
    } catch {
      if !closed, !closing { await failProtocol() }
    }
  }

  private func acceptCarrierStream(_ carrierStream: any TransportV2CarrierStream) async {
    var ledgerID: UInt64?
    do {
      try await beginInboundResponder()
      defer { finishInboundResponder() }
      let reader = TransportV2CarrierReader(stream: carrierStream)
      let rawPreface = try await reader.readExact(TransportV2Crypto.setupPrefaceBytes)
      let preface = try SetupPrefaceV2(encoded: rawPreface)
      guard
        preface.openerRole == peerOpenerRole,
        preface.initialEpoch == receiveEpoch,
        let roots = receiveRoots[preface.initialEpoch],
        try TransportV2Crypto.verifySetupMAC(
          setupRoot: roots.setupRoot,
          h3: h3,
          preface: preface
        )
      else { throw TransportV2SessionError.protocolViolation }
      guard acceptsPeerStreamAfterGoAway(preface.logicalStreamID) else {
        await carrierStream.reset(code: 6)
        return
      }
      if peerLedger.state(of: preface.logicalStreamID) == .abandonedNoFSS2 {
        _ = try peerLedger.validFSS2ForAbandoned(preface.logicalStreamID)
        await carrierStream.reset(code: 6)
        return
      }
      try peerLedger.validFSS2(preface.logicalStreamID)
      ledgerID = preface.logicalStreamID
      let (type, openRaw, header) = try await readStreamRecord(
        reader: reader,
        logicalStreamID: preface.logicalStreamID,
        expectedEpoch: preface.initialEpoch,
        expectedSequence: 0
      )
      guard type == .open else { throw TransportV2SessionError.protocolViolation }
      let open = try OpenPayloadV2.decode(openRaw)
      guard
        open.logicalStreamID == preface.logicalStreamID,
        open.fss2Hash == Data(SHA256.hash(data: rawPreface))
      else { throw TransportV2SessionError.protocolViolation }
      try peerLedger.validOpen(preface.logicalStreamID)
      let metadata = try TransportV2MetadataCodec.decode(open.metadata)
      let internalRPC = open.kind == TransportV2ByteStream.reservedRPCStreamKind
      guard !internalRPC || metadata.values.isEmpty else {
        throw TransportV2SessionError.protocolViolation
      }
      if !internalRPC {
        guard inboundApplicationStreams < Int(config.maxInboundStreams) else {
          try await rejectOpen(
            carrierStream: carrierStream,
            reader: reader,
            id: preface.logicalStreamID,
            kind: open.kind,
            epoch: header.epoch,
            openRaw: openRaw,
            reason: openRejectResourceExhaustedReasonV2
          )
          return
        }
        inboundApplicationStreams += 1
      }
      let stream = TransportV2ByteStream(
        session: self,
        carrier: carrierStream,
        reader: reader,
        suite: config.suite,
        h3: h3,
        sendDirection: sendDirection,
        receiveDirection: receiveDirection,
        id: preface.logicalStreamID,
        kind: open.kind,
        inbound: true,
        internalRPC: internalRPC,
        sendEpoch: sendEpoch,
        receiveEpoch: header.epoch,
        sendSequence: 0,
        receiveSequence: 1
      )
      streams[preface.logicalStreamID] = stream
      try await stream.sendOpenACK(Data(SHA256.hash(data: openRaw)))
      guard await stream.isUsableAfterOpenACK() else { return }
      guard acceptsPeerStreamAfterGoAway(preface.logicalStreamID) else {
        await stream.reset()
        return
      }
      if internalRPC {
        await startRPCServer(stream)
      } else {
        await deliver(
          IncomingStreamV2(
            id: preface.logicalStreamID,
            kind: open.kind,
            metadata: metadata,
            stream: stream
          )
        )
      }
    } catch {
      if let ledgerID, let stream = streams[ledgerID] {
        await stream.peerReset(.streamReset)
      } else {
        await carrierStream.reset(code: 6)
      }
      if let ledgerID {
        do {
          try await sendStreamResetRecord(id: ledgerID)
        } catch {
          await failProtocol()
        }
      }
      if error is TransportV2ProtocolStateError {
        await failProtocol()
      }
    }
  }

  private func rejectOpen(
    carrierStream: any TransportV2CarrierStream,
    reader: TransportV2CarrierReader,
    id: UInt64,
    kind: String,
    epoch: UInt32,
    openRaw: Data,
    reason: UInt16
  ) async throws {
    let stream = TransportV2ByteStream(
      session: self,
      carrier: carrierStream,
      reader: reader,
      suite: config.suite,
      h3: h3,
      sendDirection: sendDirection,
      receiveDirection: receiveDirection,
      id: id,
      kind: kind,
      inbound: true,
      internalRPC: false,
      sendEpoch: sendEpoch,
      receiveEpoch: epoch,
      sendSequence: 0,
      receiveSequence: 1
    )
    var payload = Data(SHA256.hash(data: openRaw))
    payload.appendUInt16BE(reason)
    try await stream.sendOpenReject(payload)
    await carrierStream.close()
  }

  private func deliver(_ value: IncomingStreamV2) async {
    guard !closing, !closed else {
      await value.stream.reset()
      return
    }
    while !incomingWaiterOrder.isEmpty {
      let waiterID = incomingWaiterOrder.removeFirst()
      if let waiter = incomingWaiters.removeValue(forKey: waiterID) {
        waiter.resume(returning: value)
        return
      }
    }
    incoming.append(value)
  }

  private func startRPCServer(_ stream: TransportV2ByteStream) async {
    guard !rpcServerClaimed else {
      await stream.peerReset(.protocolViolation)
      return
    }
    rpcServerClaimed = true
    let router = config.rpcRouter ?? RPCRouter()
    do {
      let server = try RPCServer(
        stream: TransportV2RPCStreamAdapter(stream: stream),
        router: router,
        options: config.rpcServerOptions,
        path: rpcPath
      )
      rpcServerTask = Task { [weak self] in
        do {
          try await server.serve()
        } catch is CancellationError {
        } catch {
          await self?.failProtocol()
        }
      }
    } catch {
      await stream.peerReset(.protocolViolation)
      await failProtocol()
    }
  }

  private var rpcPath: FlowersecPath { path == .direct ? .direct : .tunnel }

  private func sendControl(
    _ type: InnerRecordTypeV2,
    payload: Data,
    allowWhileClosing: Bool = false
  ) async throws {
    guard !closed, allowWhileClosing || !closing else {
      throw TransportV2SessionError.closed
    }
    guard let roots = sendRoots[sendEpoch] else {
      throw TransportV2SessionError.protocolViolation
    }
    let inner = try TransportV2Crypto.encodeInnerRecord(type: type, payload: payload)
    guard !controlSendExhausted else { throw TransportV2SessionError.resourceExhausted }
    let material = try TransportV2Crypto.deriveControlMaterial(
      controlRoot: roots.controlRoot,
      h3: h3,
      direction: sendDirection,
      epoch: sendEpoch
    )
    let header = RecordHeaderV2(
      epoch: sendEpoch,
      sequence: controlSendSequence,
      ciphertextLength: UInt32(inner.count + TransportV2Crypto.aeadTagBytes)
    )
    if controlSendSequence == UInt64.max {
      controlSendExhausted = true
    } else {
      controlSendSequence += 1
    }
    let ciphertext = try TransportV2Crypto.sealRecord(
      suite: config.suite,
      key: material.recordKey,
      noncePrefix: material.noncePrefix,
      h3: h3,
      logicalStreamID: 0,
      direction: sendDirection,
      header: header,
      plaintext: inner
    )
    var raw = try header.encoded()
    raw.append(ciphertext)
    try await controlWriter.write(raw)
    touchActivity()
  }

  private func readControl() async throws -> (InnerRecordTypeV2, Data) {
    let rawHeader = try await controlReader.readExact(TransportV2Crypto.recordHeaderBytes)
    let header = try RecordHeaderV2(encoded: rawHeader)
    let cutsOver: Bool
    if header.epoch == controlReceiveEpoch {
      cutsOver = false
      guard !controlReceiveExhausted, header.sequence == controlReceiveSequence else {
        throw TransportV2SessionError.protocolViolation
      }
    } else if controlReceiveEpoch != UInt32.max,
      header.epoch == controlReceiveEpoch + 1,
      header.epoch <= receiveEpoch,
      header.sequence == 0
    {
      cutsOver = true
    } else {
      throw TransportV2SessionError.protocolViolation
    }
    let ciphertext = try await controlReader.readExact(Int(header.ciphertextLength))
    guard let roots = receiveRoots[header.epoch] else {
      throw TransportV2SessionError.protocolViolation
    }
    let material = try TransportV2Crypto.deriveControlMaterial(
      controlRoot: roots.controlRoot,
      h3: h3,
      direction: receiveDirection,
      epoch: header.epoch
    )
    let plaintext = try TransportV2Crypto.openRecord(
      suite: config.suite,
      key: material.recordKey,
      noncePrefix: material.noncePrefix,
      h3: h3,
      logicalStreamID: 0,
      direction: receiveDirection,
      header: header,
      ciphertext: ciphertext
    )
    if cutsOver {
      controlReceiveEpoch = header.epoch
      controlReceiveSequence = 1
      controlReceiveExhausted = false
      trimReceiveRoots()
    } else if controlReceiveSequence == UInt64.max {
      controlReceiveExhausted = true
    } else {
      controlReceiveSequence += 1
    }
    let record = try TransportV2Crypto.decodeInnerRecord(plaintext)
    touchActivity()
    return record
  }

  private func readStreamRecord(
    reader: TransportV2CarrierReader,
    logicalStreamID: UInt64,
    expectedEpoch: UInt32,
    expectedSequence: UInt64
  ) async throws -> (InnerRecordTypeV2, Data, RecordHeaderV2) {
    let rawHeader = try await reader.readExact(TransportV2Crypto.recordHeaderBytes)
    let header = try RecordHeaderV2(encoded: rawHeader)
    guard header.epoch == expectedEpoch, header.sequence == expectedSequence else {
      throw TransportV2SessionError.protocolViolation
    }
    let ciphertext = try await reader.readExact(Int(header.ciphertextLength))
    guard let roots = receiveRoots[header.epoch] else {
      throw TransportV2SessionError.protocolViolation
    }
    let material = try TransportV2Crypto.deriveStreamMaterial(
      streamRoot: roots.streamRoot,
      h3: h3,
      logicalStreamID: logicalStreamID,
      direction: receiveDirection,
      epoch: header.epoch
    )
    let plaintext = try TransportV2Crypto.openRecord(
      suite: config.suite,
      key: material.recordKey,
      noncePrefix: material.noncePrefix,
      h3: h3,
      logicalStreamID: logicalStreamID,
      direction: receiveDirection,
      header: header,
      ciphertext: ciphertext
    )
    let (type, payload) = try TransportV2Crypto.decodeInnerRecord(plaintext)
    return (type, payload, header)
  }

  private func handleControl(_ type: InnerRecordTypeV2, payload: Data) async throws {
    switch type {
    case .ping:
      try await sendControl(.pong, payload: payload)
    case .pong:
      let nonce = payload.readUInt64BE(at: 0)
      if let waiter = pings.removeValue(forKey: nonce) { await waiter.succeed() }
    case .streamReset:
      let id = payload.readUInt64BE(at: 0)
      guard id != 0, payload.readUInt16BE(at: 8) != 0 else {
        throw TransportV2SessionError.protocolViolation
      }
      if let stream = streams[id] { await stream.peerReset(.streamReset) }
      if isPeerLogicalStreamID(id) {
        try peerLedger.peerReset(id)
      } else if isLocalLogicalStreamID(id) {
        try outboundLedger.peerReset(id)
      } else {
        throw TransportV2SessionError.protocolViolation
      }
    case .sessionClose:
      guard payload.readUInt16BE(at: 0) != 0 else {
        throw TransportV2SessionError.protocolViolation
      }
      carrier.abort(code: 1, reason: "peer closed session")
      await terminate(error: .closed, code: 1, reason: "peer closed session")
    case .goAway:
      try receivedGoAway.accept(
        lastAccepted: payload.readUInt64BE(at: 0),
        reason: payload.readUInt16BE(at: 8),
        localRole: config.role,
        localHighWatermark: localHighWatermark()
      )
    case .sessionKeyUpdate:
      try await handleSessionKeyUpdate(payload)
    case .sessionKeyUpdateACK:
      try await handleSessionKeyUpdateACK(payload)
    default:
      throw TransportV2SessionError.protocolViolation
    }
  }

  private func failProtocol() async {
    guard !closed else { return }
    let signal = initiateClose(
      goAwayReason: 6,
      closeReason: 6,
      carrierCode: 6,
      carrierReason: "session protocol failure",
      terminalError: .protocolViolation
    )
    await signal.wait()
  }

  fileprivate func prepareReceiveEpoch(_ nextEpoch: UInt32) throws {
    if receiveRoots[nextEpoch] != nil { return }
    guard nextEpoch != 0, nextEpoch == receiveEpoch + 1, let current = receiveRoots[receiveEpoch]
    else { throw TransportV2SessionError.rekeyFailed }
    let secret = try TransportV2Crypto.deriveNextEpoch(
      rekeyRoot: current.rekeyRoot,
      h3: h3,
      direction: receiveDirection,
      nextEpoch: nextEpoch
    )
    receiveRoots[nextEpoch] = try TransportV2Crypto.deriveEpochRoots(epochSecret: secret)
  }

  private func handleSessionKeyUpdate(_ payload: Data) async throws {
    guard payload.count == 20 else { throw TransportV2SessionError.protocolViolation }
    let transition = payload.readUInt64BE(at: 0)
    let nextEpoch = payload.readUInt32BE(at: 8)
    let watermark = payload.readUInt64BE(at: 12)
    guard
      transition != 0,
      transition == receivedTransition + 1,
      receiveEpoch != UInt32.max,
      nextEpoch == receiveEpoch + 1,
      peerHighWatermark() == watermark
    else { throw TransportV2SessionError.protocolViolation }
    guard pendingReceiveRekeyTransition == nil else {
      throw TransportV2SessionError.protocolViolation
    }
    pendingReceiveRekeyTransition = transition
    let completionDeadline = Task { [weak self, duration = config.deadlines.rekeyCompletion] in
      do {
        try await Task.sleep(for: duration)
      } catch {
        return
      }
      await self?.expireReceiveRekey(transition: transition)
    }
    defer {
      completionDeadline.cancel()
      if pendingReceiveRekeyTransition == transition {
        pendingReceiveRekeyTransition = nil
      }
    }
    let freezeWaiterID = allocateLifecycleWaiterID()
    try await freezeInboundResponders(peerInitiated: true, waiterID: freezeWaiterID)
    defer { unfreezeInboundResponders(peerInitiated: true) }
    try prepareReceiveEpoch(nextEpoch)
    let activeStreams = Array(streams.values)
    for stream in activeStreams {
      try await stream.awaitReceiveRekey(transition: transition, nextEpoch: nextEpoch)
      guard !closed else { throw TransportV2SessionError.closed }
    }
    receiveEpoch = nextEpoch
    receivedTransition = transition
    trimReceiveRoots()
    for stream in activeStreams {
      await stream.publishReceiveRekey(transition: transition, nextEpoch: nextEpoch)
    }
    try await sendControl(.sessionKeyUpdateACK, payload: payload)
  }

  private func expireReceiveRekey(transition: UInt64) async {
    guard pendingReceiveRekeyTransition == transition, !closed else { return }
    await failProtocol()
  }

  private func handleSessionKeyUpdateACK(_ payload: Data) async throws {
    let disposition: RekeyACKDispositionV2
    do {
      disposition = try classifyRekeyACKV2(
        received: payload,
        pending: pendingRekey?.payload,
        lastAccepted: lastAcceptedSessionRekeyACK
      )
    } catch {
      throw TransportV2SessionError.protocolViolation
    }
    if disposition == .duplicate { return }
    guard let pendingRekey else { throw TransportV2SessionError.protocolViolation }
    sendEpoch = pendingRekey.epoch
    controlSendSequence = 0
    controlSendExhausted = false
    lastAcceptedSessionRekeyACK = payload
    await pendingRekey.succeed()
  }

  private func finishRekeyGate() {
    rekeyInProgress = false
    let waiters = rekeyWaiters
    rekeyWaiters.removeAll()
    for waiter in waiters.values { waiter.resume(returning: ()) }
  }

  private func finishOpenOperation() {
    activeOpenOperations = max(0, activeOpenOperations - 1)
    guard activeOpenOperations == 0 else { return }
    let waiters = openOperationWaiters
    openOperationWaiters.removeAll()
    for waiter in waiters.values { waiter.resume(returning: ()) }
  }

  private func beginInboundResponder() async throws {
    let waiterID = allocateLifecycleWaiterID()
    while localInboundRespondersFrozen || peerInboundRespondersFrozen {
      guard !closing, !closed else { throw TransportV2SessionError.closed }
      try await waitForInboundResponderChange(requestID: waiterID)
    }
    guard !closing, !closed else { throw TransportV2SessionError.closed }
    activeInboundResponders += 1
  }

  private func finishInboundResponder() {
    activeInboundResponders = max(0, activeInboundResponders - 1)
    notifyInboundResponderWaiters()
  }

  private func freezeInboundResponders(
    peerInitiated: Bool,
    waiterID: UInt64
  ) async throws {
    if peerInitiated {
      peerInboundRespondersFrozen = true
    } else {
      localInboundRespondersFrozen = true
    }
    do {
      while activeInboundResponders != 0 {
        guard !closing, !closed else { throw TransportV2SessionError.closed }
        try await waitForInboundResponderChange(requestID: waiterID)
      }
    } catch {
      unfreezeInboundResponders(peerInitiated: peerInitiated)
      throw error
    }
  }

  private func unfreezeInboundResponders(peerInitiated: Bool) {
    if peerInitiated {
      peerInboundRespondersFrozen = false
    } else {
      localInboundRespondersFrozen = false
    }
    notifyInboundResponderWaiters()
  }

  private func notifyInboundResponderWaiters() {
    let waiters = inboundResponderWaiters
    inboundResponderWaiters.removeAll()
    for waiter in waiters.values { waiter.resume(returning: ()) }
  }

  private func allocateLifecycleWaiterID() -> UInt64 {
    let id = nextLifecycleWaiterID
    nextLifecycleWaiterID &+= 1
    if nextLifecycleWaiterID == 0 { nextLifecycleWaiterID = 1 }
    return id == 0 ? allocateLifecycleWaiterID() : id
  }

  private func waitForRekeyGate(requestID: UInt64) async throws {
    try Task.checkCancellation()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
        } else if !rekeyInProgress {
          continuation.resume(returning: ())
        } else if closing || closed {
          continuation.resume(throwing: TransportV2SessionError.closed)
        } else {
          rekeyWaiters[requestID] = continuation
        }
      }
    } onCancel: {
      Task { await self.cancelLifecycleWaiter(requestID) }
    }
  }

  private func waitForActiveOpenOperations(requestID: UInt64) async throws {
    try Task.checkCancellation()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
        } else if activeOpenOperations == 0 {
          continuation.resume(returning: ())
        } else if closing || closed {
          continuation.resume(throwing: TransportV2SessionError.closed)
        } else {
          openOperationWaiters[requestID] = continuation
        }
      }
    } onCancel: {
      Task { await self.cancelLifecycleWaiter(requestID) }
    }
  }

  private func waitForInboundResponderChange(requestID: UInt64) async throws {
    try Task.checkCancellation()
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<Void, Error>) in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
        } else if !localInboundRespondersFrozen && !peerInboundRespondersFrozen {
          continuation.resume(returning: ())
        } else if closing || closed {
          continuation.resume(throwing: TransportV2SessionError.closed)
        } else {
          inboundResponderWaiters[requestID] = continuation
        }
      }
    } onCancel: {
      Task { await self.cancelLifecycleWaiter(requestID) }
    }
  }

  private func checkRekeyPreparation(requestID: UInt64) throws {
    try Task.checkCancellation()
    if failedRekeyPreparations.contains(requestID) {
      throw TransportV2SessionError.rekeyFailed
    }
  }

  private func cancelRekeyPreparation(requestID: UInt64) {
    guard activeRekeyPreparations.contains(requestID) else { return }
    failedRekeyPreparations.insert(requestID)
    cancelLifecycleWaiter(requestID, error: CancellationError())
  }

  private func cancelLifecycleWaiter(_ requestID: UInt64) {
    cancelLifecycleWaiter(requestID, error: CancellationError())
  }

  private func cancelLifecycleWaiter(_ requestID: UInt64, error: Error) {
    if let waiter = rekeyWaiters.removeValue(forKey: requestID) {
      waiter.resume(throwing: error)
    }
    if let waiter = openOperationWaiters.removeValue(forKey: requestID) {
      waiter.resume(throwing: error)
    }
    if let waiter = inboundResponderWaiters.removeValue(forKey: requestID) {
      waiter.resume(throwing: error)
    }
  }

  private func removeLifecycleWaiter(_ requestID: UInt64) {
    rekeyWaiters.removeValue(forKey: requestID)
    openOperationWaiters.removeValue(forKey: requestID)
    inboundResponderWaiters.removeValue(forKey: requestID)
  }

  private func startRekeyDeadline(
    transition: UInt64,
    duration: Duration
  ) -> Task<Void, Never> {
    Task { [weak self] in
      do {
        try await Task.sleep(for: duration)
        await self?.expireRekey(transition: transition)
      } catch {
        // Cancellation means the corresponding rekey phase completed in time.
      }
    }
  }

  private func startRekeyPreparationDeadline(
    requestID: UInt64,
    duration: Duration
  ) -> Task<Void, Never> {
    Task { [weak self] in
      do {
        try await Task.sleep(for: duration)
      } catch {
        return
      }
      await self?.expireRekeyPreparation(requestID: requestID)
    }
  }

  private func expireRekeyPreparation(requestID: UInt64) {
    guard activeRekeyPreparations.contains(requestID) else { return }
    failedRekeyPreparations.insert(requestID)
    cancelLifecycleWaiter(requestID, error: TransportV2SessionError.rekeyFailed)
  }

  private func expireRekey(transition: UInt64) async {
    guard let pendingRekey, pendingRekey.transition == transition else { return }
    await pendingRekey.signal.fail(TransportV2SessionError.rekeyFailed)
    await failProtocol()
  }

  private func cancelIncomingWaiter(_ waiterID: UInt64) {
    guard let waiter = incomingWaiters.removeValue(forKey: waiterID) else { return }
    incomingWaiterOrder.removeAll { $0 == waiterID }
    waiter.resume(throwing: CancellationError())
  }

  private func initiateClose(
    goAwayReason: UInt16,
    closeReason: UInt16,
    carrierCode: UInt16,
    carrierReason: String,
    terminalError: TransportV2SessionError
  ) -> TransportV2CloseSignal {
    if let closeSignal { return closeSignal }
    closing = true
    idleTask?.cancel()
    idleTask = nil
    closeGeneration &+= 1
    if closeGeneration == 0 { closeGeneration = 1 }
    let generation = closeGeneration
    let signal = TransportV2CloseSignal()
    closeSignal = signal
    rejectPendingOperationsForClosing(error: .closed)
    let closeFlush = config.deadlines.closeFlush
    closeDeadlineTask = Task { [weak self] in
      do {
        try await Task.sleep(for: closeFlush)
        await self?.expireClose(generation: generation, code: carrierCode, reason: carrierReason)
      } catch {
        // Cancellation means the close records completed within the bounded flush window.
      }
    }
    closeWorkTask = Task { [weak self] in
      await self?.writeCloseRecords(
        generation: generation,
        goAwayReason: goAwayReason,
        closeReason: closeReason,
        carrierCode: carrierCode,
        carrierReason: carrierReason,
        terminalError: terminalError
      )
    }
    return signal
  }

  private func rejectPendingOperationsForClosing(error: TransportV2SessionError) {
    let acceptWaiters = Array(incomingWaiters.values)
    incomingWaiters.removeAll()
    incomingWaiterOrder.removeAll()
    incoming.removeAll()
    for waiter in acceptWaiters {
      waiter.resume(throwing: error)
    }
    let pendingRekeyWaiters = rekeyWaiters
    rekeyWaiters.removeAll()
    for waiter in pendingRekeyWaiters.values { waiter.resume(throwing: error) }
    let pendingOpenWaiters = openOperationWaiters
    openOperationWaiters.removeAll()
    for waiter in pendingOpenWaiters.values { waiter.resume(throwing: error) }
    localInboundRespondersFrozen = false
    peerInboundRespondersFrozen = false
    notifyInboundResponderWaiters()
  }

  private func writeCloseRecords(
    generation: UInt64,
    goAwayReason: UInt16,
    closeReason: UInt16,
    carrierCode: UInt16,
    carrierReason: String,
    terminalError: TransportV2SessionError
  ) async {
    do {
      guard isCurrentClose(generation) else { return }
      try await sendGoAway(reason: goAwayReason, allowWhileClosing: true)
      guard isCurrentClose(generation) else { return }
      var payload = Data()
      payload.appendUInt16BE(closeReason)
      try await sendControl(.sessionClose, payload: payload, allowWhileClosing: true)
    } catch {
      // The versioned close deadline and carrier shutdown remain authoritative.
    }
    await finishClose(
      generation: generation,
      error: terminalError,
      code: carrierCode,
      reason: carrierReason
    )
  }

  private func finishClose(
    generation: UInt64,
    error: TransportV2SessionError,
    code: UInt16,
    reason: String
  ) async {
    guard isCurrentClose(generation) else { return }
    await terminate(error: error, code: code, reason: reason)
  }

  private func expireClose(generation: UInt64, code: UInt16, reason: String) async {
    guard closing, closeGeneration == generation, closeSignal != nil else { return }
    closeDeadlineTask = nil
    carrier.abort(code: code, reason: reason)
  }

  private func isCurrentClose(_ generation: UInt64) -> Bool {
    closing && !closed && closeGeneration == generation
  }

  fileprivate func touchActivity() {
    guard let timeout = config.idleTimeout, !closing, !closed else { return }
    activityGeneration &+= 1
    if activityGeneration == 0 { activityGeneration = 1 }
    let generation = activityGeneration
    idleTask?.cancel()
    idleTask = Task { [weak self] in
      do {
        try await Task.sleep(for: timeout)
        await self?.expireIdle(generation: generation)
      } catch {
        // Cancellation means authenticated activity reset or stopped the watchdog.
      }
    }
  }

  private func expireIdle(generation: UInt64) {
    guard activityGeneration == generation, !closing, !closed else { return }
    idleTask = nil
    _ = initiateClose(
      goAwayReason: 4,
      closeReason: 4,
      carrierCode: 1,
      carrierReason: "session idle timeout",
      terminalError: .closed
    )
  }

  private func terminate(
    error: TransportV2SessionError,
    code: UInt16,
    reason: String
  ) async {
    guard !closed else { return }
    closing = true
    closed = true
    terminationError = error
    let waiters = terminationWaiters
    terminationWaiters.removeAll()
    for waiter in waiters { waiter.resume(returning: error) }
    controlTask?.cancel()
    acceptTask?.cancel()
    rpcServerTask?.cancel()
    idleTask?.cancel()
    controlTask = nil
    acceptTask = nil
    rpcServerTask = nil
    idleTask = nil
    rejectPendingOperationsForClosing(error: error)
    if let rpcClient {
      await rpcClient.close()
      self.rpcClient = nil
    }
    let pingWaiters = Array(pings.values)
    pings.removeAll()
    for waiter in pingWaiters { await waiter.fail(error) }
    let currentStreams = Array(streams.values)
    streams.removeAll()
    for stream in currentStreams { await stream.peerReset(error) }
    if let pendingRekey { await pendingRekey.signal.fail(error) }
    pendingRekey = nil
    lastAcceptedSessionRekeyACK = nil
    sendRoots.removeAll(keepingCapacity: false)
    receiveRoots.removeAll(keepingCapacity: false)
    await carrier.close(code: code, reason: reason)
    closeDeadlineTask?.cancel()
    closeDeadlineTask = nil
    closeWorkTask = nil
    await closeSignal?.finish()
  }

  private func idReasonPayload(id: UInt64, reason: UInt16) -> Data {
    var payload = Data()
    payload.appendUInt64BE(id)
    payload.appendUInt16BE(reason)
    return payload
  }

  private func peerHighWatermark() -> UInt64 {
    peerLedger.frontier
  }

  private func localHighWatermark() -> UInt64 {
    localOpenedHighWatermark
  }

  private func isPeerLogicalStreamID(_ id: UInt64) -> Bool {
    id != 0
      && ((config.role == .client && id.isMultiple(of: 2))
        || (config.role == .server && !id.isMultiple(of: 2)))
  }

  private func isLocalLogicalStreamID(_ id: UInt64) -> Bool {
    id != 0 && !isPeerLogicalStreamID(id)
  }

  private func localOpeningAllowedAfterGoAway(_ id: UInt64) -> Bool {
    !closing && !closed && !sentGoAway && receivedGoAway.allows(id)
  }

  private func acceptsPeerStreamAfterGoAway(_ id: UInt64) -> Bool {
    !sentGoAway || id <= sentGoAwayLastAccepted
  }

  private func trimSendRoots() {
    for epoch in sendRoots.keys where epoch < sendEpoch {
      sendRoots.removeValue(forKey: epoch)
    }
  }

  private func trimReceiveRoots() {
    let oldestRetained = min(controlReceiveEpoch, receiveEpoch == 0 ? 0 : receiveEpoch - 1)
    for epoch in receiveRoots.keys where epoch < oldestRetained {
      receiveRoots.removeValue(forKey: epoch)
    }
  }

  func epochRootCountsForTesting() -> (send: Int, receive: Int) {
    (sendRoots.count, receiveRoots.count)
  }

  func goAwayStateForTesting() -> (
    sentLastAccepted: UInt64?, receivedLastAccepted: UInt64?
  ) {
    (
      sentGoAway ? sentGoAwayLastAccepted : nil,
      receivedGoAway.lastAccepted
    )
  }

  func incomingWaiterCountForTesting() -> Int { incomingWaiters.count }

  func lifecycleWaiterCountsForTesting() -> (
    rekeyGate: Int,
    activeOpen: Int,
    inboundResponders: Int,
    pings: Int,
    rekeyInProgress: Bool,
    localRespondersFrozen: Bool
  ) {
    (
      rekeyWaiters.count,
      openOperationWaiters.count,
      inboundResponderWaiters.count,
      pings.count,
      rekeyInProgress,
      localInboundRespondersFrozen
    )
  }

  func sendEpochForTesting() -> UInt32 { sendEpoch }
}

private actor TransportV2ByteStream: ByteStreamV2 {
  static let reservedRPCStreamKind = "flowersec.rpc.v2"

  nonisolated let id: UInt64
  nonisolated let kind: String

  private let session: TransportV2Session
  private let carrier: any TransportV2CarrierStream
  private let reader: TransportV2CarrierReader
  private let writer: TransportV2CarrierWriter
  private let readPermit = TransportV2ReadPermit()
  private let writePermit = TransportV2ReadPermit()
  private let suite: TransportCipherSuiteV2
  private let h3: Data
  private let sendDirection: TransportDirectionV2
  private let receiveDirection: TransportDirectionV2
  private let inbound: Bool
  private let internalRPC: Bool
  private var sendEpoch: UInt32
  private var receiveEpoch: UInt32
  private var sendSequence: UInt64
  private var receiveSequence: UInt64
  private var sendExhausted = false
  private var receiveExhausted = false
  private var receivePriorEpoch: UInt32 = 0
  private var receivePriorSequence: UInt64 = 0
  private var receivePriorACK = false
  private var readBuffer = Data()
  private var localFIN = false
  private var remoteFIN = false
  private var terminal: TransportV2SessionError?
  private var pendingSendRekey: PendingStreamRekeyV2?
  private var lastAcceptedSendRekeyACK: StreamKeyUpdateACKPayloadV2?
  private var pendingReceiveTransition: UInt64 = 0
  private var pendingReceiveEpoch: UInt32 = 0
  private var pendingReceiveACKed = false
  private var pendingReceiveSignal: RekeySignalV2?

  init(
    session: TransportV2Session,
    carrier: any TransportV2CarrierStream,
    reader: TransportV2CarrierReader? = nil,
    suite: TransportCipherSuiteV2,
    h3: Data,
    sendDirection: TransportDirectionV2,
    receiveDirection: TransportDirectionV2,
    id: UInt64,
    kind: String,
    inbound: Bool,
    internalRPC: Bool,
    sendEpoch: UInt32,
    receiveEpoch: UInt32,
    sendSequence: UInt64,
    receiveSequence: UInt64
  ) {
    self.session = session
    self.carrier = carrier
    self.reader = reader ?? TransportV2CarrierReader(stream: carrier)
    writer = TransportV2CarrierWriter(stream: carrier)
    self.suite = suite
    self.h3 = h3
    self.sendDirection = sendDirection
    self.receiveDirection = receiveDirection
    self.id = id
    self.kind = kind
    self.inbound = inbound
    self.internalRPC = internalRPC
    self.sendEpoch = sendEpoch
    self.receiveEpoch = receiveEpoch
    self.sendSequence = sendSequence
    self.receiveSequence = receiveSequence
  }

  func sendOpen(_ payload: Data) async throws { try await writeRecord(.open, payload: payload) }

  func sendOpenACK(_ payload: Data) async throws {
    try await writeRecord(.openACK, payload: payload)
  }

  func sendOpenReject(_ payload: Data) async throws {
    try await writeRecord(.openReject, payload: payload)
  }

  func receiveOpenResponse(expectedOpenHash: Data) async throws -> UInt16? {
    let (type, payload) = try await readRecord()
    switch type {
    case .openACK:
      guard payload == expectedOpenHash else {
        throw TransportV2SessionError.protocolViolation
      }
      return nil
    case .openReject:
      return try validateOpenRejectV2(payload: payload, expectedOpenHash: expectedOpenHash)
    default:
      throw TransportV2SessionError.protocolViolation
    }
  }

  public func read(maxBytes: Int) async throws -> Data? {
    guard maxBytes > 0 else { return Data() }
    while readBuffer.isEmpty {
      if remoteFIN { return nil }
      if let terminal { throw terminal }
      do {
        _ = try await processNextRecord(stopWhenApplicationReadable: true)
      } catch let error as TransportV2SessionError {
        terminal = error
        throw error
      } catch {
        terminal = .streamReset
        throw TransportV2SessionError.streamReset
      }
    }
    let count = min(maxBytes, readBuffer.count)
    let output = Data(readBuffer.prefix(count))
    readBuffer.removeFirst(count)
    return output
  }

  public func write(_ data: Data) async throws -> Int {
    guard terminal == nil else { throw terminal! }
    guard !localFIN else { throw TransportV2SessionError.streamReset }
    guard !data.isEmpty else { return 0 }
    var offset = 0
    while offset < data.count {
      try Task.checkCancellation()
      let count = min(TransportV2Crypto.maxDataBytes, data.count - offset)
      try await writeRecord(.data, payload: Data(data[offset..<(offset + count)]))
      offset += count
    }
    return data.count
  }

  public func closeWrite() async throws {
    guard terminal == nil else { throw terminal! }
    guard !localFIN else { return }
    try await writeRecord(.fin, payload: Data())
    localFIN = true
    try await carrier.closeWrite()
    await releaseIfFinished()
  }

  public func reset() async {
    guard terminal == nil else { return }
    terminal = .streamReset
    if let pendingSendRekey {
      self.pendingSendRekey = nil
      await pendingSendRekey.signal.fail(TransportV2SessionError.streamReset)
    }
    if let pendingReceiveSignal {
      await pendingReceiveSignal.fail(TransportV2SessionError.streamReset)
    }
    await session.sendStreamReset(id: id)
    await carrier.reset(code: 6)
    await session.streamFinished(id: id, inbound: inbound, internalRPC: internalRPC)
  }

  public func close() async { await reset() }

  public func terminalError() async -> (any Error & Sendable)? { terminal }

  fileprivate func isUsableAfterOpenACK() -> Bool { terminal == nil }

  fileprivate func peerReset(_ error: TransportV2SessionError) async {
    guard terminal == nil else { return }
    terminal = error
    if let pendingSendRekey {
      self.pendingSendRekey = nil
      await pendingSendRekey.signal.fail(error)
    }
    if let pendingReceiveSignal { await pendingReceiveSignal.fail(error) }
    carrier.abort(code: 6)
    await session.streamFinished(id: id, inbound: inbound, internalRPC: internalRPC)
  }

  fileprivate func beginSendRekey(
    transition: UInt64,
    nextEpoch: UInt32
  ) async throws -> RekeySignalV2? {
    guard terminal == nil, !localFIN else { return nil }
    guard pendingSendRekey == nil, nextEpoch == sendEpoch + 1 else {
      throw TransportV2SessionError.rekeyFailed
    }
    let pending = PendingStreamRekeyV2(transition: transition, epoch: nextEpoch)
    pendingSendRekey = pending
    var payload = Data()
    payload.appendUInt64BE(transition)
    payload.appendUInt32BE(nextEpoch)
    try await writeRecord(.streamKeyUpdate, payload: payload)
    Task { [weak self] in await self?.driveSendRekey(pending) }
    return pending.signal
  }

  fileprivate func awaitReceiveRekey(
    transition: UInt64,
    nextEpoch: UInt32
  ) async throws {
    while terminal == nil && !remoteFIN {
      if pendingReceiveTransition != 0 {
        guard
          pendingReceiveTransition == transition,
          pendingReceiveEpoch == nextEpoch
        else { throw TransportV2SessionError.rekeyFailed }
        if !pendingReceiveACKed {
          guard let pendingReceiveSignal else {
            throw TransportV2SessionError.rekeyFailed
          }
          try await pendingReceiveSignal.wait()
        }
        return
      }
      _ = try await processNextRecord(
        stopBeforeReceiveRekey: (transition: transition, epoch: nextEpoch)
      )
    }
  }

  fileprivate func publishReceiveRekey(transition: UInt64, nextEpoch: UInt32) {
    if pendingReceiveTransition == transition && pendingReceiveEpoch == nextEpoch
      && pendingReceiveACKed
    {
      pendingReceiveTransition = 0
      pendingReceiveEpoch = 0
      pendingReceiveACKed = false
      pendingReceiveSignal = nil
    }
  }

  private func releaseIfFinished() async {
    if localFIN && remoteFIN {
      await session.streamFinished(id: id, inbound: inbound, internalRPC: internalRPC)
    }
  }

  private func driveSendRekey(_ pending: PendingStreamRekeyV2) async {
    do {
      while pendingSendRekey === pending, terminal == nil {
        guard try await processNextRecord(onlyWhileSendRekey: pending) else { return }
      }
    } catch {
      await pending.signal.fail(TransportV2SessionError.rekeyFailed)
      await peerReset(.rekeyFailed)
    }
  }

  private func processNextRecord(
    onlyWhileSendRekey expectedPending: PendingStreamRekeyV2? = nil,
    stopBeforeReceiveRekey receiveRekey: (transition: UInt64, epoch: UInt32)? = nil,
    stopWhenApplicationReadable: Bool = false
  ) async throws -> Bool {
    await readPermit.acquire()
    if terminal != nil || remoteFIN {
      await readPermit.release()
      return false
    }
    if stopWhenApplicationReadable, !readBuffer.isEmpty {
      await readPermit.release()
      return false
    }
    if let expectedPending, pendingSendRekey !== expectedPending {
      await readPermit.release()
      return false
    }
    if let receiveRekey, pendingReceiveTransition != 0 {
      guard
        pendingReceiveTransition == receiveRekey.transition,
        pendingReceiveEpoch == receiveRekey.epoch
      else {
        await readPermit.release()
        throw TransportV2SessionError.rekeyFailed
      }
      await readPermit.release()
      return false
    }
    do {
      let (type, payload) = try await readRecordUnlocked()
      switch type {
      case .data:
        readBuffer.append(payload)
      case .fin:
        remoteFIN = true
        await releaseIfFinished()
      case .streamKeyUpdate:
        try await receiveStreamKeyUpdate(payload)
      case .streamKeyUpdateACK:
        try await receiveStreamKeyUpdateACK(payload)
      default:
        throw TransportV2SessionError.protocolViolation
      }
      await readPermit.release()
      return true
    } catch {
      await readPermit.release()
      throw error
    }
  }

  private func receiveStreamKeyUpdate(_ payload: Data) async throws {
    guard
      payload.count == 12,
      receiveEpoch != UInt32.max,
      pendingReceiveTransition == 0
    else { throw TransportV2SessionError.rekeyFailed }
    let transition = payload.readUInt64BE(at: 0)
    let nextEpoch = payload.readUInt32BE(at: 8)
    guard transition != 0, nextEpoch == receiveEpoch + 1 else {
      throw TransportV2SessionError.rekeyFailed
    }
    pendingReceiveTransition = transition
    pendingReceiveEpoch = nextEpoch
    let receiveSignal = RekeySignalV2()
    pendingReceiveSignal = receiveSignal
    try await session.prepareReceiveEpoch(nextEpoch)
    receivePriorEpoch = receiveEpoch
    receivePriorSequence = receiveSequence
    receivePriorACK = true
    receiveEpoch = nextEpoch
    receiveSequence = 0
    receiveExhausted = false
    let ack = StreamKeyUpdateACKPayloadV2(
      logicalStreamID: id,
      transition: transition,
      epoch: nextEpoch
    )
    try await writeRecord(.streamKeyUpdateACK, payload: ack.encoded())
    pendingReceiveACKed = true
    await receiveSignal.succeed()
  }

  private func receiveStreamKeyUpdateACK(_ payload: Data) async throws {
    let ack: StreamKeyUpdateACKPayloadV2
    do {
      ack = try StreamKeyUpdateACKPayloadV2(encoded: payload)
    } catch {
      throw TransportV2SessionError.rekeyFailed
    }
    await writePermit.acquire()
    do {
      let expected = pendingSendRekey.map {
        StreamKeyUpdateACKPayloadV2(
          logicalStreamID: id,
          transition: $0.transition,
          epoch: $0.epoch
        )
      }
      let disposition = try classifyRekeyACKV2(
        received: ack,
        pending: expected,
        lastAccepted: lastAcceptedSendRekeyACK
      )
      if disposition == .duplicate {
        await writePermit.release()
        return
      }
      guard let pending = pendingSendRekey else {
        throw TransportV2SessionError.rekeyFailed
      }
      sendEpoch = pending.epoch
      sendSequence = 0
      sendExhausted = false
      pendingSendRekey = nil
      lastAcceptedSendRekeyACK = ack
      await writePermit.release()
      await pending.signal.succeed()
    } catch {
      await writePermit.release()
      throw error
    }
  }

  private func writeRecord(_ type: InnerRecordTypeV2, payload: Data) async throws {
    while true {
      try Task.checkCancellation()
      await writePermit.acquire()
      if type == .data || type == .fin, let pendingSendRekey {
        await writePermit.release()
        try await pendingSendRekey.signal.waitAsObserver()
        continue
      }
      do {
        try await writeRecordLocked(type, payload: payload)
        await writePermit.release()
        return
      } catch {
        await writePermit.release()
        throw error
      }
    }
  }

  private func writeRecordLocked(_ type: InnerRecordTypeV2, payload: Data) async throws {
    guard let terminal else {
      guard !sendExhausted else { throw TransportV2SessionError.resourceExhausted }
      let roots = try await session.root(direction: sendDirection, epoch: sendEpoch)
      let inner = try TransportV2Crypto.encodeInnerRecord(type: type, payload: payload)
      let material = try TransportV2Crypto.deriveStreamMaterial(
        streamRoot: roots.streamRoot,
        h3: h3,
        logicalStreamID: id,
        direction: sendDirection,
        epoch: sendEpoch
      )
      let header = RecordHeaderV2(
        epoch: sendEpoch,
        sequence: sendSequence,
        ciphertextLength: UInt32(inner.count + TransportV2Crypto.aeadTagBytes)
      )
      if sendSequence == UInt64.max {
        sendExhausted = true
      } else {
        sendSequence += 1
      }
      let ciphertext = try TransportV2Crypto.sealRecord(
        suite: suite,
        key: material.recordKey,
        noncePrefix: material.noncePrefix,
        h3: h3,
        logicalStreamID: id,
        direction: sendDirection,
        header: header,
        plaintext: inner
      )
      var raw = try header.encoded()
      raw.append(ciphertext)
      try await writer.write(raw)
      await session.touchActivity()
      return
    }
    throw terminal
  }

  private func readRecord() async throws -> (InnerRecordTypeV2, Data) {
    await readPermit.acquire()
    do {
      let record = try await readRecordUnlocked()
      await readPermit.release()
      return record
    } catch {
      await readPermit.release()
      throw error
    }
  }

  private func readRecordUnlocked() async throws -> (InnerRecordTypeV2, Data) {
    let rawHeader = try await reader.readExact(TransportV2Crypto.recordHeaderBytes)
    let header = try RecordHeaderV2(encoded: rawHeader)
    let priorACK =
      receivePriorACK && header.epoch == receivePriorEpoch
      && header.sequence == receivePriorSequence
    guard
      priorACK
        || (!receiveExhausted && header.epoch == receiveEpoch
          && header.sequence == receiveSequence)
    else {
      throw TransportV2SessionError.protocolViolation
    }
    let ciphertext = try await reader.readExact(Int(header.ciphertextLength))
    let roots = try await session.root(direction: receiveDirection, epoch: header.epoch)
    let material = try TransportV2Crypto.deriveStreamMaterial(
      streamRoot: roots.streamRoot,
      h3: h3,
      logicalStreamID: id,
      direction: receiveDirection,
      epoch: header.epoch
    )
    let plaintext = try TransportV2Crypto.openRecord(
      suite: suite,
      key: material.recordKey,
      noncePrefix: material.noncePrefix,
      h3: h3,
      logicalStreamID: id,
      direction: receiveDirection,
      header: header,
      ciphertext: ciphertext
    )
    let record = try TransportV2Crypto.decodeInnerRecord(plaintext)
    if priorACK {
      receivePriorACK = false
      guard record.0 == .streamKeyUpdateACK else {
        throw TransportV2SessionError.protocolViolation
      }
    } else {
      receivePriorACK = false
      if receiveSequence == UInt64.max {
        receiveExhausted = true
      } else {
        receiveSequence += 1
      }
    }
    await session.touchActivity()
    return record
  }

}

enum TransportV2ProtocolStateError: Error {
  case invalidTransition
  case duplicateStreamID
  case ledgerCapacity
}

enum TransportV2LedgerState: UInt8, Equatable {
  case unseen
  case abandonedNoFSS2
  case openSeen
  case usedOrTerminal
}

enum TransportV2LateSetupAction: Equatable {
  case reset
}

struct TransportV2StreamLedger {
  private static let maximumSlots = 1_048_576

  private let openerRole: StreamOpenerRoleV2
  private var states = [UInt8](repeating: 0, count: maximumSlots / 4)
  private(set) var frontier: UInt64 = 0

  init(openerRole: StreamOpenerRoleV2) {
    self.openerRole = openerRole
  }

  func state(of id: UInt64) -> TransportV2LedgerState {
    guard let index = slotIndex(id) else { return .unseen }
    let shift = UInt8((index % 4) * 2)
    return TransportV2LedgerState(rawValue: (states[index / 4] >> shift) & 0x03) ?? .unseen
  }

  mutating func peerReset(_ id: UInt64) throws {
    try validate(id)
    switch state(of: id) {
    case .unseen:
      setState(.abandonedNoFSS2, for: id)
    case .openSeen:
      setState(.usedOrTerminal, for: id)
    case .abandonedNoFSS2, .usedOrTerminal:
      break
    }
    advanceFrontier()
  }

  mutating func validFSS2(_ id: UInt64) throws {
    try validate(id)
    guard state(of: id) == .unseen else {
      throw TransportV2ProtocolStateError.duplicateStreamID
    }
    setState(.openSeen, for: id)
  }

  mutating func validFSS2ForAbandoned(_ id: UInt64) throws -> TransportV2LateSetupAction {
    try validate(id)
    guard state(of: id) == .abandonedNoFSS2 else {
      if state(of: id) == .openSeen || state(of: id) == .usedOrTerminal {
        throw TransportV2ProtocolStateError.duplicateStreamID
      }
      throw TransportV2ProtocolStateError.invalidTransition
    }
    setState(.usedOrTerminal, for: id)
    advanceFrontier()
    return .reset
  }

  mutating func validOpen(_ id: UInt64) throws {
    try validate(id)
    guard state(of: id) == .openSeen else {
      throw TransportV2ProtocolStateError.invalidTransition
    }
    setState(.usedOrTerminal, for: id)
    advanceFrontier()
  }

  mutating func localResetCommitted(_ id: UInt64) throws {
    try validate(id)
    switch state(of: id) {
    case .openSeen:
      setState(.usedOrTerminal, for: id)
    case .usedOrTerminal:
      return
    case .unseen, .abandonedNoFSS2:
      throw TransportV2ProtocolStateError.invalidTransition
    }
    advanceFrontier()
  }

  private func validate(_ id: UInt64) throws {
    guard slotIndex(id) != nil else {
      throw TransportV2ProtocolStateError.ledgerCapacity
    }
  }

  private func slotIndex(_ id: UInt64) -> Int? {
    let valid: Bool
    let ordinal: UInt64
    switch openerRole {
    case .client:
      valid = id != 0 && !id.isMultiple(of: 2)
      ordinal = id / 2 + 1
    case .server:
      valid = id != 0 && id.isMultiple(of: 2)
      ordinal = id / 2
    }
    guard valid, ordinal != 0, ordinal <= UInt64(Self.maximumSlots) else { return nil }
    return Int(ordinal - 1)
  }

  private mutating func setState(_ state: TransportV2LedgerState, for id: UInt64) {
    guard let index = slotIndex(id) else { return }
    let shift = UInt8((index % 4) * 2)
    let mask = UInt8(0x03 << shift)
    states[index / 4] = (states[index / 4] & ~mask) | (state.rawValue << shift)
  }

  private mutating func advanceFrontier() {
    var next = frontier == 0 && openerRole == .client ? UInt64(1) : frontier + 2
    while slotIndex(next) != nil {
      let state = state(of: next)
      guard state == .abandonedNoFSS2 || state == .usedOrTerminal else { return }
      frontier = next
      guard next <= UInt64.max - 2 else { return }
      next += 2
    }
  }
}

struct StreamKeyUpdateACKPayloadV2: Equatable {
  let logicalStreamID: UInt64
  let transition: UInt64
  let epoch: UInt32

  init(logicalStreamID: UInt64, transition: UInt64, epoch: UInt32) {
    self.logicalStreamID = logicalStreamID
    self.transition = transition
    self.epoch = epoch
  }

  init(encoded: Data) throws {
    guard encoded.count == 20 else {
      throw TransportV2ProtocolStateError.invalidTransition
    }
    logicalStreamID = encoded.readUInt64BE(at: 0)
    transition = encoded.readUInt64BE(at: 8)
    epoch = encoded.readUInt32BE(at: 16)
    guard logicalStreamID != 0, transition != 0, epoch != 0 else {
      throw TransportV2ProtocolStateError.invalidTransition
    }
  }

  func encoded() -> Data {
    var output = Data()
    output.appendUInt64BE(logicalStreamID)
    output.appendUInt64BE(transition)
    output.appendUInt32BE(epoch)
    return output
  }
}

enum RekeyACKDispositionV2: Equatable {
  case accepted
  case duplicate
}

func classifyRekeyACKV2<Value: Equatable>(
  received: Value,
  pending: Value?,
  lastAccepted: Value?
) throws -> RekeyACKDispositionV2 {
  if pending == received { return .accepted }
  if lastAccepted == received { return .duplicate }
  throw TransportV2ProtocolStateError.invalidTransition
}

func validateOpenRejectV2(payload: Data, expectedOpenHash: Data) throws -> UInt16 {
  guard payload.count == 34, Data(payload.prefix(32)) == expectedOpenHash else {
    throw TransportV2SessionError.protocolViolation
  }
  let reason = payload.readUInt16BE(at: 32)
  guard reason != 0 else { throw TransportV2SessionError.protocolViolation }
  return reason
}

struct ReceivedGoAwayStateV2 {
  private(set) var lastAccepted: UInt64?

  var wasReceived: Bool { lastAccepted != nil }

  mutating func accept(
    lastAccepted: UInt64,
    reason: UInt16,
    localRole: SessionRoleV2,
    localHighWatermark: UInt64
  ) throws {
    let validBoundary =
      lastAccepted == 0
      || (lastAccepted <= localHighWatermark
        && ((localRole == .client && !lastAccepted.isMultiple(of: 2))
          || (localRole == .server && lastAccepted.isMultiple(of: 2))))
    guard reason != 0, validBoundary else {
      throw TransportV2ProtocolStateError.invalidTransition
    }
    if let existing = self.lastAccepted, existing != lastAccepted {
      throw TransportV2ProtocolStateError.invalidTransition
    }
    self.lastAccepted = lastAccepted
  }

  func allows(_ id: UInt64) -> Bool {
    guard let lastAccepted else { return true }
    return id <= lastAccepted
  }
}

private actor TransportV2CarrierReader {
  private let stream: any TransportV2CarrierStream

  init(stream: any TransportV2CarrierStream) { self.stream = stream }

  func readExact(_ count: Int) async throws -> Data {
    var output = Data()
    while output.count < count {
      guard let chunk = try await stream.read(maxBytes: count - output.count), !chunk.isEmpty else {
        throw TransportV2SessionError.closed
      }
      output.append(chunk)
    }
    return output
  }
}

private actor TransportV2CarrierWriter {
  private let stream: any TransportV2CarrierStream

  init(stream: any TransportV2CarrierStream) { self.stream = stream }

  func write(_ data: Data) async throws {
    try await TransportV2Handshake.writeAll(data, to: stream)
  }
}

private actor PingWaiterV2 {
  private let started: ContinuousClock.Instant
  private var result: Result<Duration, Error>?
  private var continuations: [UInt64: CheckedContinuation<Duration, Error>] = [:]
  private var nextContinuationID: UInt64 = 1

  init(started: ContinuousClock.Instant) { self.started = started }

  func wait(timeout: Duration) async throws -> Duration {
    try Task.checkCancellation()
    if let result { return try result.get() }
    let continuationID = nextContinuationID
    nextContinuationID &+= 1
    if nextContinuationID == 0 { nextContinuationID = 1 }
    let deadline = Task { [weak self] in
      do {
        try await Task.sleep(for: timeout)
      } catch {
        return
      }
      await self?.fail(TransportV2SessionError.livenessFailed)
    }
    defer { deadline.cancel() }
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
        } else if let result {
          continuation.resume(with: result)
        } else {
          continuations[continuationID] = continuation
        }
      }
    } onCancel: {
      Task { await self.cancel(continuationID) }
    }
  }

  func succeed() {
    finish(.success(started.duration(to: ContinuousClock.now)))
  }

  func fail(_ error: Error) { finish(.failure(error)) }

  private func finish(_ result: Result<Duration, Error>) {
    guard self.result == nil else { return }
    self.result = result
    let pending = Array(continuations.values)
    continuations.removeAll()
    for continuation in pending { continuation.resume(with: result) }
  }

  private func cancel(_ continuationID: UInt64) {
    guard let continuation = continuations.removeValue(forKey: continuationID) else { return }
    continuation.resume(throwing: CancellationError())
  }
}

private actor TransportV2CloseSignal {
  private var completed = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func wait() async {
    if completed { return }
    await withCheckedContinuation { waiters.append($0) }
  }

  func finish() {
    guard !completed else { return }
    completed = true
    let pending = waiters
    waiters.removeAll()
    for waiter in pending { waiter.resume() }
  }
}

private actor TransportV2ReadPermit {
  private var held = false
  private var waiters: [CheckedContinuation<Void, Never>] = []

  func acquire() async {
    if !held {
      held = true
      return
    }
    await withCheckedContinuation { waiters.append($0) }
  }

  func release() {
    if waiters.isEmpty {
      held = false
    } else {
      waiters.removeFirst().resume()
    }
  }
}

private actor RekeySignalV2 {
  private var result: Result<Void, Error>?
  private var waiters: [CheckedContinuation<Void, Error>] = []
  private var observers: [UInt64: CheckedContinuation<Void, Error>] = [:]
  private var nextObserverID: UInt64 = 1

  func wait() async throws {
    try await withTaskCancellationHandler {
      if let result { return try result.get() }
      return try await withCheckedThrowingContinuation { waiters.append($0) }
    } onCancel: {
      Task { await self.fail(CancellationError()) }
    }
  }

  func waitAsObserver() async throws {
    try Task.checkCancellation()
    if let result { return try result.get() }
    let observerID = nextObserverID
    nextObserverID &+= 1
    if nextObserverID == 0 { nextObserverID = 1 }
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        if Task.isCancelled {
          continuation.resume(throwing: CancellationError())
        } else if let result {
          continuation.resume(with: result)
        } else {
          observers[observerID] = continuation
        }
      }
    } onCancel: {
      Task { await self.cancelObserver(observerID) }
    }
  }

  func succeed() { finish(.success(())) }
  func fail(_ error: Error) { finish(.failure(error)) }

  private func finish(_ result: Result<Void, Error>) {
    guard self.result == nil else { return }
    self.result = result
    let pending = waiters
    waiters.removeAll()
    for waiter in pending { waiter.resume(with: result) }
    let pendingObservers = Array(observers.values)
    observers.removeAll()
    for observer in pendingObservers { observer.resume(with: result) }
  }

  private func cancelObserver(_ observerID: UInt64) {
    guard let observer = observers.removeValue(forKey: observerID) else { return }
    observer.resume(throwing: CancellationError())
  }
}

private final class PendingStreamRekeyV2: @unchecked Sendable {
  let transition: UInt64
  let epoch: UInt32
  let signal = RekeySignalV2()

  init(transition: UInt64, epoch: UInt32) {
    self.transition = transition
    self.epoch = epoch
  }
}

private final class PendingSessionRekeyV2: @unchecked Sendable {
  let transition: UInt64
  let epoch: UInt32
  let watermark: UInt64
  let signal = RekeySignalV2()

  init(transition: UInt64, epoch: UInt32, watermark: UInt64) {
    self.transition = transition
    self.epoch = epoch
    self.watermark = watermark
  }

  var payload: Data {
    var payload = Data()
    payload.appendUInt64BE(transition)
    payload.appendUInt32BE(epoch)
    payload.appendUInt64BE(watermark)
    return payload
  }

  func wait() async throws { try await signal.wait() }
  func succeed() async { await signal.succeed() }
}

private final class TransportV2RPCReference: RPCPeerV2, @unchecked Sendable {
  private let lock = NSLock()
  private weak var session: TransportV2Session?

  func bind(_ session: TransportV2Session) {
    lock.withLock { self.session = session }
  }

  func call<Request: Encodable & Sendable, Response: Decodable & Sendable>(
    _ typeID: UInt32,
    _ request: Request,
    as responseType: Response.Type,
    timeout: Duration
  ) async throws -> Response {
    guard let session = boundSession() else { throw TransportV2SessionError.closed }
    let client = try await session.rpcClientForUse()
    return try await client.call(typeID, request, timeout: timeout)
  }

  func notify<Payload: Encodable & Sendable>(
    _ typeID: UInt32,
    _ payload: Payload
  ) async throws {
    guard let session = boundSession() else { throw TransportV2SessionError.closed }
    let client = try await session.rpcClientForUse()
    try await client.notify(typeID, payload)
  }

  private func boundSession() -> TransportV2Session? { lock.withLock { session } }
}

private final class TransportV2RPCStreamAdapter: FlowersecRPCStream, @unchecked Sendable {
  private let stream: any ByteStreamV2

  init(stream: any ByteStreamV2) { self.stream = stream }

  func write(_ data: Data) async throws {
    _ = try await stream.write(data)
  }

  func readExact(_ length: Int) async throws -> Data {
    guard length >= 0 else { throw TransportV2SessionError.protocolViolation }
    var output = Data()
    while output.count < length {
      guard let chunk = try await stream.read(maxBytes: length - output.count), !chunk.isEmpty
      else {
        throw TransportV2SessionError.closed
      }
      output.append(chunk)
    }
    return output
  }

  func close() async { await stream.close() }

  func reset() async throws { await stream.reset() }
}

private enum TransportV2MetadataCodec {
  static func encode(_ metadata: StreamMetadataV2) throws -> Data {
    var output = Data()
    try appendObject(metadata.values, to: &output)
    return output
  }

  static func decode(_ data: Data) throws -> StreamMetadataV2 {
    let raw = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    guard let object = raw as? [String: Any] else {
      throw TransportV2SessionError.protocolViolation
    }
    return try StreamMetadataV2(try object.mapValues(decodeValue))
  }

  private static func decodeValue(_ value: Any) throws -> JSONValueV2 {
    if value is NSNull { return .null }
    if let number = value as? NSNumber {
      if CFGetTypeID(number) == CFBooleanGetTypeID() { return .bool(number.boolValue) }
      return .integer(number.int64Value)
    }
    if let string = value as? String { return .string(string) }
    if let array = value as? [Any] { return .array(try array.map(decodeValue)) }
    guard let object = value as? [String: Any] else {
      throw TransportV2SessionError.protocolViolation
    }
    return .object(try object.mapValues(decodeValue))
  }

  private static func appendObject(
    _ object: [String: JSONValueV2],
    to output: inout Data
  ) throws {
    output.append(0x7B)
    let keys = object.keys.sorted {
      Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16))
    }
    for (index, key) in keys.enumerated() {
      if index != 0 { output.append(0x2C) }
      appendString(key, to: &output)
      output.append(0x3A)
      guard let value = object[key] else { throw TransportV2SessionError.protocolViolation }
      try appendValue(value, to: &output)
    }
    output.append(0x7D)
  }

  private static func appendValue(_ value: JSONValueV2, to output: inout Data) throws {
    switch value {
    case .null:
      output.append(Data("null".utf8))
    case .bool(let value):
      output.append(Data(value ? "true".utf8 : "false".utf8))
    case .integer(let value):
      output.append(Data(String(value).utf8))
    case .string(let value):
      appendString(value.precomposedStringWithCanonicalMapping, to: &output)
    case .array(let values):
      output.append(0x5B)
      for (index, child) in values.enumerated() {
        if index != 0 { output.append(0x2C) }
        try appendValue(child, to: &output)
      }
      output.append(0x5D)
    case .object(let object):
      try appendObject(object, to: &output)
    }
  }

  private static func appendString(_ value: String, to output: inout Data) {
    output.append(0x22)
    for scalar in value.unicodeScalars {
      switch scalar.value {
      case 0x22:
        output.append(Data("\\\"".utf8))
      case 0x5C:
        output.append(Data("\\\\".utf8))
      case 0x08:
        output.append(Data("\\b".utf8))
      case 0x09:
        output.append(Data("\\t".utf8))
      case 0x0A:
        output.append(Data("\\n".utf8))
      case 0x0C:
        output.append(Data("\\f".utf8))
      case 0x0D:
        output.append(Data("\\r".utf8))
      case 0...0x1F:
        output.append(Data(String(format: "\\u%04x", scalar.value).utf8))
      default:
        output.append(Data(String(scalar).utf8))
      }
    }
    output.append(0x22)
  }
}
