import Foundation

/// 掃描判定。順序有意義:越後面越嚴重(用來取兩個判定中比較嚴重的那個)。
public enum Verdict: String, Codable, Sendable, Comparable, CaseIterable {
    case safe, unknown, suspicious, malicious

    public var label: String {
        switch self {
        case .safe: return "安全"
        case .unknown: return "無法判定"
        case .suspicious: return "可疑"
        case .malicious: return "惡意"
        }
    }

    private var rank: Int { Verdict.allCases.firstIndex(of: self)! }
    public static func < (a: Verdict, b: Verdict) -> Bool { a.rank < b.rank }
}

/// 依「打開它會發生什麼事」分類,不是依副檔名:一個 .jpg 如果其實是 Mach-O,就歸在 executable。
public enum FileCategory: String, Codable, Sendable {
    case executable, appBundle, diskImage, installerPackage, archive, script, document, media, folder, other

    /// 打開或執行後可能跑程式碼的類別
    public var canRunCode: Bool {
        switch self {
        case .executable, .appBundle, .diskImage, .installerPackage, .archive, .script, .folder: return true
        case .document, .media, .other: return false
        }
    }
}

public struct SignatureInfo: Codable, Sendable, Equatable {
    public enum Status: String, Codable, Sendable { case unsigned, adhoc, valid, invalid }
    public var status: Status
    public var teamID: String?
    public var identifier: String?
    public var authorities: [String] = []
    /// Gatekeeper(spctl)是否接受;nil = 沒檢查(不適用的類型)
    public var gatekeeperAccepted: Bool?
    /// spctl 回報的來源,例如 "Notarized Developer ID"、"Apple System"
    public var gatekeeperSource: String?

    public var isNotarized: Bool {
        gatekeeperAccepted == true &&
            (gatekeeperSource?.contains("Notarized") == true || gatekeeperSource?.contains("Apple") == true)
    }
}

public struct FileFacts: Codable, Sendable {
    public var path: String
    public var name: String
    public var ext: String
    public var size: Int64
    public var sha256: String?
    /// `file -b` 的輸出(資料夾為 "directory")
    public var fileType: String
    public var category: FileCategory
    /// 副檔名看起來是文件/影音,實際內容卻是程式或腳本
    public var disguised: Bool
    /// com.apple.quarantine 原始值(下載的 App 會寫入)
    public var quarantine: String?
    /// 下載來源(kMDItemWhereFroms):通常 [下載網址, 來源網頁]
    public var whereFroms: [String]
    public var signature: SignatureInfo?
    /// 壓縮檔 / 磁碟映像 / 資料夾內的檔案清單(有上限)
    public var contents: [String]?
    /// 磁碟映像或資料夾裡面的 App 的簽章(路徑 → 簽章)
    public var nestedSignatures: [String: SignatureInfo]?
    /// 檢查過程中失敗但不致命的步驟
    public var notes: [String] = []

    public var downloadHost: String? { whereFroms.first.flatMap { URL(string: $0)?.host?.lowercased() } }
    public var referrerHost: String? {
        whereFroms.dropFirst().first.flatMap { URL(string: $0)?.host?.lowercased() }
    }
}

/// 本機規則(不經過 Claude)找到的警訊
public struct Signal: Codable, Sendable, Equatable {
    public enum Severity: String, Codable, Sendable { case info, warning, critical }
    public var severity: Severity
    public var message: String
}

/// 掃描的 Claude 建議加入白名單的規則(要使用者按一下才生效)
public struct WhitelistSuggestion: Codable, Sendable, Equatable {
    public enum Kind: String, Codable, Sendable { case domain, teamID, sha256 }
    public var kind: Kind
    public var value: String
    public var reason: String?

    public var label: String {
        switch kind {
        case .domain: return "網域 \(value)"
        case .teamID: return "開發者 \(value)"
        case .sha256: return "這個檔案(SHA-256 \(value.prefix(12))…)"
        }
    }
}

/// Claude 透過 submit_verdict 回報的結果
public struct ClaudeVerdict: Codable, Sendable {
    public var verdict: Verdict
    public var confidence: Double?
    public var summary: String
    public var reasons: [String]
    public var suggestion: WhitelistSuggestion?
}

public struct ScanOutcome: Codable, Sendable, Identifiable {
    public enum Source: String, Codable, Sendable { case whitelist, claude, localOnly }

    public var id: UUID
    public var date: Date
    public var path: String
    public var name: String
    public var sha256: String?
    public var downloadURL: String?
    public var teamID: String?
    public var source: Source
    /// 命中的白名單規則(source == .whitelist 時)
    public var whitelistRule: String?
    public var claude: ClaudeVerdict?
    public var signals: [Signal]
    /// 最終判定:Claude 和本機規則取比較嚴重的那個(本機規則最多拉到「可疑」)
    public var verdict: Verdict
    public var summary: String
    public var error: String?
    public var costUSD: Double?
    public var durationSeconds: Double
    /// 被移到隔離區之後的位置
    public var quarantinedPath: String?
}
