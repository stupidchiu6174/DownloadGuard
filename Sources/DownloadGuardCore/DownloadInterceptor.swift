import Foundation
import CoreServices

/// 監看整個家目錄(含子資料夾),抓「剛下載完成」的項目,不管它被存在哪個資料夾。
///
/// 怎麼認出下載:macOS 會替瀏覽器、AirDrop、郵件附件存下來的檔案加上兩個標記——
/// com.apple.quarantine(誰下載的、什麼時候)與 kMDItemWhereFroms(下載網址)。
/// 只有兩個都有、隔離標記的時間是最近幾分鐘、而且還沒被放行過的,才算新下載:
/// - 只看 quarantine 會誤抓沙盒 App 自己存的檔案(它們也會被加上 quarantine,但沒有下載網址)
/// - 不看時間的話,你把舊的下載檔搬到別的資料夾也會被抓
public final class DownloadInterceptor {
    public let root: URL
    /// 不監看的資料夾(絕對路徑;子資料夾一併略過)
    public var excluded: [String]
    /// 隔離標記的時間要在這段時間內才算新下載
    public var recentWindow: TimeInterval = 15 * 60
    public var settleDelay: TimeInterval = 0.8
    /// 下載完成時呼叫(主執行緒)
    public var onDownload: (URL) -> Void

    private var stream: FSEventStreamRef?
    private let queue = DispatchQueue(label: "lirios.downloadguard.interceptor")
    private var pending: Set<String> = []

    /// 套件型的項目:裡面的檔案不單獨處理,整包一起算
    static let bundleExtensions: Set<String> = ["app", "bundle", "framework", "plugin", "pkg", "mpkg", "photoslibrary",
                                                "fcpbundle", "logicx", "band", "rtfd", "pages", "numbers", "key",
                                                "xcodeproj", "xcworkspace", "playground", "sparsebundle", "download"]
    /// 這些名稱的資料夾整個略過(套件管理器、建置輸出、版本控制)
    static let skippedFolderNames: Set<String> = ["node_modules", ".git", ".build", "build", "DerivedData", "venv",
                                                  ".venv", "__pycache__", "site-packages", "Library", "Temp"]

    public init(root: URL, excluded: [URL], onDownload: @escaping (URL) -> Void) {
        self.root = DownloadWatcher.realURL(root)
        self.excluded = excluded.map { DownloadWatcher.realURL($0).path }
        self.onDownload = onDownload
    }

    deinit { stop() }

    public static func defaultExclusions(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> [URL] {
        [GuardPaths.holding, GuardPaths.support,
         home.appendingPathComponent("Library"), home.appendingPathComponent(".Trash"),
         home.appendingPathComponent("Unity user templates")]
    }

    public func start() {
        guard stream == nil else { return }
        var context = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                           retain: nil, release: nil, copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, paths, flags, _ in
            guard let info else { return }
            let me = Unmanaged<DownloadInterceptor>.fromOpaque(info).takeUnretainedValue()
            let list = unsafeBitCast(paths, to: NSArray.self) as? [String] ?? []
            for i in 0..<min(count, list.count) { me.received(list[i], flags: flags[i]) }
        }
        let flags = FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes
                                             | kFSEventStreamCreateFlagNoDefer)
        guard let s = FSEventStreamCreate(nil, callback, &context, [root.path] as CFArray,
                                          FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 0.3, flags)
        else { return }
        FSEventStreamSetDispatchQueue(s, queue)
        FSEventStreamStart(s)
        stream = s
    }

    public func stop() {
        guard let s = stream else { return }
        FSEventStreamStop(s)
        FSEventStreamInvalidate(s)
        FSEventStreamRelease(s)
        stream = nil
    }

    // MARK: - 事件

    private func received(_ path: String, flags: FSEventStreamEventFlags) {
        // 下載完成時瀏覽器會「改名」(.crdownload → 正式檔名)或「建立」,標記則是延伸屬性變動
        let interesting = FSEventStreamEventFlags(kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemRenamed
                                                  | kFSEventStreamEventFlagItemXattrMod
                                                  | kFSEventStreamEventFlagItemModified)
        guard flags & interesting != 0, let item = candidate(for: path), !pending.contains(item) else { return }
        pending.insert(item)
        settle(item, last: Self.snapshot(item), attempts: 0)
    }

    /// 事件路徑 → 要處理的項目。在套件裡面的(例如 .app 內部檔案)歸到最外層的套件;略過的位置回傳 nil。
    func candidate(for path: String) -> String? {
        let base = root.path + "/"
        guard path.hasPrefix(base) else { return nil }
        if excluded.contains(where: { path == $0 || path.hasPrefix($0 + "/") }) { return nil }
        let parts = path.dropFirst(base.count).split(separator: "/").map(String.init)
        var built = root.path
        for (i, part) in parts.enumerated() {
            built += "/" + part
            if part.hasPrefix(".") { return nil }   // 隱藏的檔案與資料夾
            let isLast = i == parts.count - 1
            if !isLast, Self.skippedFolderNames.contains(part) { return nil }
            let ext = (part as NSString).pathExtension.lowercased()
            if Self.bundleExtensions.contains(ext) { return built }
            if isLast {
                if DownloadWatcher.shouldIgnore(part) { return nil }
                return built
            }
        }
        return nil
    }

    private func settle(_ path: String, last: String?, attempts: Int) {
        queue.asyncAfter(deadline: .now() + settleDelay) { [weak self] in
            guard let self else { return }
            guard let now = Self.snapshot(path) else { self.pending.remove(path); return }
            if now != last, attempts < 600 {   // 還在寫入(最多等約 8 分鐘)
                self.settle(path, last: now, attempts: attempts + 1)
                return
            }
            self.pending.remove(path)
            let url = URL(fileURLWithPath: path)
            guard Self.isFreshDownload(url, window: self.recentWindow) else { return }
            DispatchQueue.main.async { self.onDownload(url) }
        }
    }

    // MARK: - 判斷

    /// 有下載標記、時間夠新、還沒放行過
    public static func isFreshDownload(_ url: URL, window: TimeInterval, now: Date = Date()) -> Bool {
        guard !HoldingPen.isReleased(url),
              let q = FileInspector.xattrString(url.path, "com.apple.quarantine"),
              let when = quarantineDate(q),
              !FileInspector.whereFroms(url.path).isEmpty
        else { return false }
        return now.timeIntervalSince(when) <= window && when.timeIntervalSince(now) < 300
    }

    /// "0083;6712ab34;Chrome;UUID" 的第二欄是十六進位的 Unix 時間
    static func quarantineDate(_ value: String) -> Date? {
        let fields = value.split(separator: ";", omittingEmptySubsequences: false)
        guard fields.count >= 2, let secs = UInt64(fields[1], radix: 16) else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(secs))
    }

    static func snapshot(_ path: String) -> String? {
        var st = stat()
        guard lstat(path, &st) == 0 else { return nil }
        return "\(st.st_ino)|\(st.st_size)|\(st.st_mtimespec.tv_sec).\(st.st_mtimespec.tv_nsec)"
    }
}
