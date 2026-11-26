// swift-tools-version: 6.1

import PackageDescription

let researchSources = ["ProfileDHV4Reference.swift", "StrictEd25519V4Reference.swift",
  "TransportV4Registry.generated.swift", "TransportV4APIResults.generated.swift"]
let researchTests = ["ApplicationSupport", "ApplicationTests", "CBORSupport", "CBORTests",
  "CompositionSupport", "CompositionTests", "CryptoUsageTests", "DomainSupport", "DomainTests",
  "IDNASupport", "IDNATests", "OracleSupport", "OracleTests", "ProfileDHTests", "ReadyTests",
  "RecordTests", "RekeyCreditTests", "RekeyTests", "RelationsSupport", "ResourceCostSupport",
  "ResourceSupport", "ResourceTests", "RulesSupport", "RulesTests", "ShapeSupport", "ShapeTests",
  "SignatureTests", "StrictSignatureTests", "TextSupport", "TextTests", "TimeSupport", "TimeTests",
  "VariantsSupport"].map { "TransportV4\($0).swift" }

// Flowersec release major: 7
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
    .package(url: "https://github.com/apple/swift-crypto.git", from: "5.1.2"),
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.82.0"),
    .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.30.0"),
  ],
  targets: [
    .target(
      name: "CFlowersecIDNA",
      path: "flowersec-swift/Sources/CFlowersecIDNA",
      linkerSettings: [
        .linkedLibrary("icucore", .when(platforms: [.macOS, .iOS])),
        .linkedLibrary("icuuc", .when(platforms: [.linux])),
      ]
    ),
    .target(
      name: "Flowersec",
      dependencies: [
        "CFlowersecIDNA",
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOHTTP1", package: "swift-nio"),
        .product(name: "NIOPosix", package: "swift-nio"),
        .product(name: "NIOWebSocket", package: "swift-nio"),
        .product(name: "NIOSSL", package: "swift-nio-ssl"),
      ],
      path: "flowersec-swift/Sources/Flowersec",
      exclude: researchSources
    ),
    .testTarget(
      name: "FlowersecTests",
      dependencies: [
        "Flowersec",
        .product(name: "NIOFoundationCompat", package: "swift-nio"),
      ],
      path: "flowersec-swift/Tests/FlowersecTests",
      exclude: researchTests,
      resources: [.copy("Fixtures")]
    ),
  ]
)
