// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "OneBigHead",
    platforms: [
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "OneBigHead",
            targets: ["OneBigHead"]
        )
    ],
    dependencies: [
        .package(
            url: "https://github.com/google/GoogleSignIn-iOS",
            from: "8.0.0"
        ),
        .package(
            url: "https://github.com/AzureAD/microsoft-authentication-library-for-objc",
            from: "1.3.0"
        )
    ],
    targets: [
        .target(
            name: "OneBigHead",
            dependencies: [
                .product(name: "GoogleSignIn", package: "GoogleSignIn-iOS"),
                .product(name: "MSAL", package: "microsoft-authentication-library-for-objc")
            ],
            path: "OneBigHead"
        ),
        .testTarget(
            name: "OneBigHeadTests",
            dependencies: ["OneBigHead"],
            path: "OneBigHeadTests"
        )
    ]
)
