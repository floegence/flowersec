import Foundation

func packageRoot(file: StaticString = #filePath) -> URL {
  URL(fileURLWithPath: "\(file)")
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
}
