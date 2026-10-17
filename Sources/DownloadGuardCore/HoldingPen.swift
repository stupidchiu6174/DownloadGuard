import Foundation

/// 小黑屋:下載先關在 ~/小黑屋,掃描通過才搬進「下載項目」。
///
/// 放行的檔案會加上 com.quewuyin.lirios.released 標記,之後在「下載項目」裡被碰到也不會再抓回來。
/// macOS 原本的隔離標記(com.apple.quarantine)保留,打開時 Gatekeeper 照樣檢查。
public enum HoldingPen {
    public static let releasedAttribute = "com.quewuyin.lirios.released"

    public static func isReleased(_ url: URL) -> Bool {
        getxattr(url.path, releasedAttribute, nil, 0, 0, XATTR_NOFOLLOW) > 0
    }

    public static func hasQuarantine(_ url: URL) -> Bool {
        getxattr(url.path, "com.apple.quarantine", nil, 0, 0, XATTR_NOFOLLOW) > 0
    }

    /// 從「下載項目」關進小黑屋
    @discardableResult
    public static func admit(_ url: URL, holding: URL = GuardPaths.holding) throws -> URL {
        try move(url, into: holding)
    }

    /// 放行:搬進「下載項目」並加上已放行標記
    @discardableResult
    public static func release(_ url: URL, to downloads: URL = GuardPaths.downloads) throws -> URL {
        let dest = try move(url, into: downloads)
        let mark = Array("1".utf8)
        setxattr(dest.path, releasedAttribute, mark, mark.count, 0, XATTR_NOFOLLOW)
        return dest
    }

    /// 移到隔離區(App 資料夾裡,不在你平常會點開的地方)
    @discardableResult
    public static func quarantine(_ url: URL, to dir: URL = GuardPaths.quarantine) throws -> URL {
        try move(url, into: dir)
    }

    /// 從隔離區放回小黑屋(之後可以再放行)
    @discardableResult
    public static func restore(_ url: URL, holding: URL = GuardPaths.holding) throws -> URL {
        try move(url, into: holding)
    }

    static func move(_ url: URL, into dir: URL) throws -> URL {
        let fm = FileManager.default
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let dest = uniqueDestination(in: dir, name: url.lastPathComponent)
        try fm.moveItem(at: url, to: dest)
        return dest
    }

    /// 同名就加「 2」「 3」…,和 Finder 一樣
    public static func uniqueDestination(in dir: URL, name: String) -> URL {
        let fm = FileManager.default
        var dest = dir.appendingPathComponent(name)
        guard fm.fileExists(atPath: dest.path) else { return dest }
        let base = (name as NSString).deletingPathExtension
        let ext = (name as NSString).pathExtension
        var n = 2
        repeat {
            dest = dir.appendingPathComponent(ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)")
            n += 1
        } while fm.fileExists(atPath: dest.path)
        return dest
    }
}
