import Foundation
import Flowersec

/// The application chooses and authorizes this TCP destination independently
/// of peer metadata. The SDK creates the socket and transfers its complete
/// native lifetime into the bridge before any application bytes are consumed.
func runNativeDuplexWorkflow(stream: any ByteStream, environment: TransportEnvironment,
  numericAddress: String, port: Int) async throws -> DuplexBridgeResult {
  let tcp = try await environment.connectDuplexTCP(
    numericAddress: numericAddress, port: port, chunkBytes: 16_384, timeout: .seconds(10))
  let bridge: DuplexBridge
  do {
    bridge = try DuplexBridge(stream, tcp,
      options: DuplexBridgeOptions(chunkBytes: 16_384, deadline: .seconds(60)))
  } catch {
    try? tcp.close()
    throw error
  }
  do {
    try bridge.start()
    let result = try await bridge.wait()
    // A native queue/FIN completion is separate from the opposite Flowersec
    // authentication-backed send drain, and both are separate from work done.
    print("tcp-send-finished=\(result.aToB.nativeSendFinished)")
    print("flowersec-send-drained=\(result.bToA.sendDrained)")
    print("bridge-outcome=\(result.outcome.rawValue)")
    print("bridge-cleanup-complete=\(result.cleanupStatus.complete)")
    return result
  } catch {
    // This workflow explicitly cancels its owned operation when its caller
    // abandons the workflow. Canceling Wait alone never aborts the bridge.
    bridge.abort()
    throw error
  }
}
