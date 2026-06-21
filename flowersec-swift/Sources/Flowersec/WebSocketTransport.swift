import Foundation

actor FlowersecWebSocketBinaryTransport {
  private let session: URLSession
  private let task: URLSessionWebSocketTask

  init(url: URL, origin: String?, connectTimeout: Duration) {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    configuration.httpCookieAcceptPolicy = .never
    configuration.httpCookieStorage = nil
    configuration.httpShouldSetCookies = false
    configuration.timeoutIntervalForRequest = connectTimeout.timeInterval
    configuration.timeoutIntervalForResource = 30
    self.session = URLSession(configuration: configuration)

    var request = URLRequest(url: url)
    request.cachePolicy = .reloadIgnoringLocalCacheData
    request.timeoutInterval = connectTimeout.timeInterval
    if let origin {
      request.setValue(origin, forHTTPHeaderField: "Origin")
    }
    request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
    request.setValue("no-cache", forHTTPHeaderField: "Pragma")
    self.task = session.webSocketTask(with: request)
  }

  func resume() {
    task.resume()
  }

  func writeBinary(_ data: Data) async throws {
    do {
      try await task.send(.data(data))
    } catch {
      throw FlowersecError.webSocket(error.localizedDescription)
    }
  }

  func writeText(_ text: String) async throws {
    do {
      try await task.send(.string(text))
    } catch {
      throw FlowersecError.webSocket(error.localizedDescription)
    }
  }

  func readBinary() async throws -> Data {
    do {
      let message = try await task.receive()
      switch message {
      case .data(let data):
        return data
      case .string:
        throw FlowersecError.webSocket("The peer returned a text WebSocket frame.")
      @unknown default:
        throw FlowersecError.webSocket(
          "The peer returned an unknown WebSocket frame."
        )
      }
    } catch let error as FlowersecError {
      throw error
    } catch {
      throw FlowersecError.webSocket(error.localizedDescription)
    }
  }

  func close() {
    task.cancel(with: .goingAway, reason: nil)
    session.invalidateAndCancel()
  }
}

extension Duration {
  fileprivate var timeInterval: TimeInterval {
    let parts = components
    return TimeInterval(parts.seconds) + TimeInterval(parts.attoseconds) / 1_000_000_000_000_000_000
  }
}
