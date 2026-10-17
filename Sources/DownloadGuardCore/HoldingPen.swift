import Foundation

/// 小黑屋:下載完成就關進 ~/小黑屋,掃描通過才送回原本要存的資料夾。
///
/// - 關進來時記下原本的資料夾(com.quewuyin.lirios.origin),放行時送回去;記錄不見或資料夾已刪就送「下載項目」
/// - 關著的期間拿掉執行權限(原本的權限記在 com.quewuyin.lirios.mode),放行時還原,
///   不小心在小黑屋裡點兩下也跑不起來。.app 不動權限:它們本來就有 macOS 下載標記,Gatekeeper 會擋
/// - 放行的項目加上 com.quewuyin.lirios.released,之後在任何資料夾被碰到都不會再抓回來
/// - macOS 原本的隔離標記(com.apple.quarantine)保留,打開時 Gatekeeper 照樣檢查
public enum HoldingPen {
    public static let releasedAttribute = "com.quewuyin.lirios.released"
    static let originAttribute = "com.quewuyin.lirios.origin"
    static let modeAttribute = "com.quewuyin.lirios.mode"

    public static func isReleased(_ url: URL) -> Bool {
        getxattr(url.path, releasedAttribute, nil, 0, 0, XATTR_NOFOLLOW) > 0
    }

    public static func hasQuarantine(_ url: URL) -> Bool {
        getxattr(url.path, "com.apple.quarantine", nil, 0, 0, XATTR_NOFOLLOW) > 0
    }

    /// 關進小黑屋時記下的原本資料夾
    public static func origin(of url: URL) -> URL? {
        FileInspector.xattrString(url.path, originAttribute).map { URL(fileURLWithPath: $0, isDirectory: true) }
    }

    /// 從原本的資料夾關進小黑屋
    @discardableResult
    public static func admit(_ url: URL, holding: URL = GuardPaths.holding) throws -> URL {
        let origin = url.deletingLastPathComponent().path
        let dest = try move(url, into: holding)
        setString(dest.path, originAttribute, origin)
        lockExecution(dest)
        return dest
    }

    /// 放行:送回原本的資料夾(沒有記錄就送 fallback),還原權限並加上已放行標記
    @discardableResult
    public static func release(_ url: URL, fallback: URL = GuardPaths.downloads) throws -> URL {
        var target = fallback
        var isDir: ObjCBool = false
        if let origin = origin(of: url),
           FileManager.default.fileExists(atPath: origin.path, isDirectory: &isDir), isDir.boolValue {
            target = origin
        }
        unlockExecution(url)
        let dest = try move(url, into: target)
        removexattr(dest.path, originAttribute, XATTR_NOFOLLOW)
        setString(dest.path, releasedAttribute, "1")
        return dest
    }

    /// 移到隔離區(App 資料夾裡,不在你平常會點開的地方)
    @discardableResult
    public static func quarantine(_ url: URL, to dir: URL = GuardPaths.quarantine) throws -> URL {
        let dest = try move(url, into: dir)
        lockExecution(dest)
        return dest
    }

    /// 從隔離區放回小黑屋(之後可以再放行;原本的資料夾記錄跟著檔案走)
    @discardableResult
    public static func restore(_ url: URL, holding: URL = GuardPaths.holding) throws -> URL {
        try move(url, into: holding)
    }

    // MARK: - 執行權限

    static func lockExecution(_ url: URL) {
        var st = stat()
        guard lstat(url.path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return }
        let mode = st.st_mode & 0o7777
        guard mode & 0o111 != 0 else { return }
        if FileInspector.xattrString(url.path, modeAttribute) == nil {
            setString(url.path, modeAttribute, String(mode, radix: 8))
        }
        chmod(url.path, mode & ~0o111)
    }

    static func unlockExecution(_ url: URL) {
        guard let saved = FileInspector.xattrString(url.path, modeAttribute),
              let mode = mode_t(saved, radix: 8) else { return }
        chmod(url.path, mode)
        removexattr(url.path, modeAttribute, XATTR_NOFOLLOW)
    }

    // MARK: -

    static func setString(_ path: String, _ name: String, _ value: String) {
        let bytes = Array(value.utf8)
        setxattr(path, name, bytes, bytes.count, 0, XATTR_NOFOLLOW)
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
