// swift-tools-version: 6.1

import PackageDescription

// Test-only package for the fixed protocol vectors. The SDK product does not link sodium.
let package = Package(
  name: "FlowersecProtocolChecks",
  platforms: [.macOS(.v15)],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.1"),
    .package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.11.0"),
  ],
  targets: [
    .target(
      name: "Flowersec",
      dependencies: [
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "Clibsodium", package: "swift-sodium"),
      ],
      path: "Sources/Flowersec",
      sources: ["ProfileDHV4Reference.swift", "StrictEd25519V4Reference.swift", "TransportV4Registry.generated.swift"],
      linkerSettings: [.linkedLibrary("sodium", .when(platforms: [.macOS]))]
    ),
    .testTarget(
      name: "ProtocolVectorTests",
      dependencies: ["Flowersec", .product(name: "Clibsodium", package: "swift-sodium"), .product(name: "Crypto", package: "swift-crypto")],
      path: "Tests/FlowersecTests",
      sources: ["PackageTestSupport.swift", "TransportV4RecordTests.swift", "TransportV4ReadyTests.swift",
                "TransportV4RekeyTests.swift", "TransportV4ProfileDHTests.swift", "TransportV4StrictSignatureTests.swift", "TransportV4SignatureTests.swift"]
    ),
  ]
)
