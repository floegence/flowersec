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
    .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.0")
  ],
  targets: [
    .target(
      name: "Flowersec",
      dependencies: [
        .product(name: "Crypto", package: "swift-crypto")
      ],
      path: "flowersec-swift/Sources/Flowersec"
    ),
    .testTarget(
      name: "FlowersecTests",
      dependencies: ["Flowersec"],
      path: "flowersec-swift/Tests/FlowersecTests"
    ),
  ]
)
