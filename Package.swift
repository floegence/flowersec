// swift-tools-version: 6.1

import PackageDescription

let package = Package(
  name: "Flowersec",
  platforms: [
    .macOS(.v15),
    .iOS("26.0"),
  ],
  products: [
    .library(name: "Flowersec", targets: ["Flowersec"])
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.0"),
    .package(url: "https://github.com/swift-server/async-http-client.git", exact: "1.30.3"),
    .package(url: "https://github.com/apple/swift-nio.git", exact: "2.82.0"),
    .package(url: "https://github.com/apple/swift-nio-ssl.git", exact: "2.30.0"),
  ],
  targets: [
    .target(
      name: "Flowersec",
      dependencies: [
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "AsyncHTTPClient", package: "async-http-client"),
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOHTTP1", package: "swift-nio"),
        .product(name: "NIOPosix", package: "swift-nio"),
        .product(name: "NIOWebSocket", package: "swift-nio"),
        .product(name: "NIOSSL", package: "swift-nio-ssl"),
      ],
      path: "flowersec-swift/Sources/Flowersec"
    ),
    .executableTarget(
      name: "FlowersecInteropHarness",
      dependencies: [
        "Flowersec",
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOHTTP1", package: "swift-nio"),
        .product(name: "NIOPosix", package: "swift-nio"),
        .product(name: "NIOWebSocket", package: "swift-nio"),
      ],
      path: "flowersec-swift/InteropHarness"
    ),
    .testTarget(
      name: "FlowersecTests",
      dependencies: ["Flowersec"],
      path: "flowersec-swift/Tests/FlowersecTests"
    ),
  ]
)
