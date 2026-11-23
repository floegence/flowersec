import Foundation

protocol FlowersecYamuxChannel: Sendable {
  func write(_ data: Data) async throws
  func readExact(_ length: Int) async throws -> Data
  func close() async
}
