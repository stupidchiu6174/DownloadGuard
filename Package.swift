// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "DownloadGuard",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "DownloadGuard", targets: ["DownloadGuard"]),
        .library(name: "DownloadGuardCore", targets: ["DownloadGuardCore"]),
        .executable(name: "liri-scan", targets: ["liri-scan"]),
        .executable(name: "DownloadGuardApp", targets: ["DownloadGuardApp"]),
    ],
    targets: [
        .target(name: "DownloadGuard", dependencies: ["DownloadGuardCore"], swiftSettings: [.swiftLanguageMode(.v5)]),
        .target(name: "DownloadGuardCore", swiftSettings: [.swiftLanguageMode(.v5)]),
        // 輔助程式:MCP 伺服器(掃描 / 白名單)與命令列掃描
        .executableTarget(name: "liri-scan", dependencies: ["DownloadGuardCore"], swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(name: "DownloadGuardApp", dependencies: ["DownloadGuard"], swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "DownloadGuardCoreTests", dependencies: ["DownloadGuardCore"], swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
