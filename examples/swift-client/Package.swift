// swift-tools-version: 6.1

import PackageDescription

let package = Package(
  name: "FlowersecSwiftClientExample",
  platforms: [.macOS(.v15)],
  dependencies: [
    .package(name: "Flowersec", path: "../..")
  ],
  targets: [
    .executableTarget(
      name: "FlowersecSwiftClientExample",
      dependencies: [
        .product(name: "Flowersec", package: "Flowersec")
      ]
    )
  ]
)
