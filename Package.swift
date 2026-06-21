// swift-tools-version: 6.0

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
  targets: [
    .target(
      name: "Flowersec",
      path: "flowersec-swift/Sources/Flowersec"
    ),
    .testTarget(
      name: "FlowersecTests",
      dependencies: ["Flowersec"],
      path: "flowersec-swift/Tests/FlowersecTests"
    ),
  ]
)
