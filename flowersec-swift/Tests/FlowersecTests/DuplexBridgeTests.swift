import Foundation
import XCTest
@testable import Flowersec

final class DuplexBridgeTests: XCTestCase {
  func testRejectsArbitraryByteStreamBeforeIO() throws {
    let left = DuplexProbeByteStream()
    let right = DuplexProbeByteStream()
    XCTAssertThrowsError(try DuplexBridge(left, right)) { error in
      XCTAssertEqual(error as? DuplexBridgeFailure, .ownerUnavailable)
    }
    XCTAssertEqual(left.readCount, 0)
    XCTAssertEqual(left.writeCount, 0)
    XCTAssertEqual(left.closeCount, 0)
    XCTAssertEqual(right.readCount, 0)
    XCTAssertEqual(right.writeCount, 0)
    XCTAssertEqual(right.closeCount, 0)
  }

  func testOptionsRejectUnboundedOrZeroCapacity() {
    XCTAssertThrowsError(try DuplexBridgeOptions(chunkBytes: 0))
    XCTAssertThrowsError(try DuplexBridgeOptions(chunkBytes: 1_048_577))
    XCTAssertThrowsError(try DuplexBridgeOptions(deadline: .zero))
    XCTAssertThrowsError(try DuplexBridgeOptions(deadline: .seconds(86_401)))
    XCTAssertThrowsError(try DuplexBridgeOptions(cleanupTimeout: .zero))
    XCTAssertThrowsError(try DuplexBridgeOptions(cleanupTimeout: .seconds(31)))
  }
}

private final class DuplexProbeByteStream: ByteStream, @unchecked Sendable {
  private let gate = NSLock()
  private var reads = 0
  private var writes = 0
  private var closes = 0
  var kind: String { "probe" }
  var readCount: Int { gate.withLock { reads } }
  var writeCount: Int { gate.withLock { writes } }
  var closeCount: Int { gate.withLock { closes } }
  func read(maxBytes: Int) async throws -> Data? { gate.withLock { reads += 1 }; return nil }
  func write(_ data: Data) async throws -> Int { gate.withLock { writes += 1 }; return data.count }
  func closeWrite() async throws { gate.withLock { closes += 1 } }
  func finish() async throws { gate.withLock { closes += 1 } }
  func reset() async throws { gate.withLock { closes += 1 } }
  func close() async throws { gate.withLock { closes += 1 } }
  func terminalError() async -> SessionError? { nil }
}
