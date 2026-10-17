import Foundation

/// 下載掃描用到的位置
public enum GuardPaths {
    static let home = FileManager.default.homeDirectoryForCurrentUser

    /// 資料:白名單、掃描紀錄、隔離區、每次掃描的暫存
    public static var support: URL {
        if let override = ProcessInfo.processInfo.environment["LIRI_GUARD_HOME"] {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("LiriOS/DownloadGuard", isDirectory: true)
    }

    public static var whitelist: URL { support.appendingPathComponent("whitelist.json") }
    public static var history: URL { support.appendingPathComponent("history.jsonl") }
    /// 判定為惡意(或你按了「隔離」)的檔案放這裡,可以從紀錄視窗還原
    public static var quarantine: URL { support.appendingPathComponent("Quarantine", isDirectory: true) }
    public static var scans: URL { support.appendingPathComponent("scans", isDirectory: true) }

    /// 小黑屋:下載先放這裡,掃描通過才搬進「下載項目」
    public static var holding: URL { home.appendingPathComponent("小黑屋", isDirectory: true) }
    public static var downloads: URL {
        FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
    }
}
