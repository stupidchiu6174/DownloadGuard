import Foundation
import CoreServices

/// 監看一個資料夾最上層的新項目,等它「下載完成」才通知。
///
/// 下載完成的判斷:
/// - 瀏覽器的暫存檔(.crdownload / .download / .part …)不算,改名成正式檔名時會再收到一次事件
/// - 大小和修改時間連續一段時間沒變
/// 同一個項目(路徑 + inode + 大小 + 修改時間)只通知一次。
public final class DownloadWatcher {
    public let directory: URL
    /// 下載完成時呼叫(主執行緒)
    public var onReady: (URL) -> Void
    public var settleDelay: TimeInterval = 2.5

    private var stream: FSEventStreamRef?
    private let queue = DispatchQueue(label: "lirios.downloadguard.watcher")
    private var pending: Set<String> = []
    private var seen: Set<String> = []

    static let temporaryExtensions: Set<String> = ["crdownload", "download", "part", "partial", "opdownload",
                                                   "tmp", "aria2", "!ut", "filepart", "crswap"]

    public init(directory: URL, onReady: @escaping (URL) -> Void) {
        // FSEvents 回報的是實際路徑(例如 /var → /private/var),比對前先解開符號連結。
        // 不能用 URL.resolvingSymlinksInPath():它會把 /private/var 又改回 /var
        self.directory = Self.realURL(directory)
        self.onReady = onReady
    }

    deinit { stop() }

    /// - Parameter includeExisting: 啟動時把資料夾裡現有的項目也當成新項目(小黑屋用:App 沒開時進來的檔案)
    public func start(includeExisting: Bool = false) {
        guard stream == nil else { return }
        var context = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                           retain: nil, release: nil, copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, paths, _, _ in
            guard let info else { return }
            let watcher = Unmanaged<DownloadWatcher>.fromOpaque(info).takeUnretainedValue()
            let list = unsafeBitCast(paths, to: NSArray.self) as? [String] ?? []
            watcher.received(Array(list.prefix(count)))
        }
        let flags = FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes
                                             | kFSEventStreamCreateFlagNoDefer)
        guard let s = FSEventStreamCreate(nil, callback, &context, [directory.path] as CFArray,
                                          FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 0.5, flags)
        else { return }
        FSEventStreamSetDispatchQueue(s, queue)
        FSEventStreamStart(s)
        stream = s

        if includeExisting {
            queue.async {
                let items = (try? FileManager.default.contentsOfDirectory(atPath: self.directory.path)) ?? []
                for name in items { self.schedule(name) }
            }
        }
    }

    public func stop() {
        guard let s = stream else { return }
        FSEventStreamStop(s)
        FSEventStreamInvalidate(s)
        FSEventStreamRelease(s)
        stream = nil
    }

    /// 處理完的項目被搬走後又搬回來(例如從隔離區還原到小黑屋),要能再通知一次
    public func forget(_ url: URL) {
        let path = Self.realURL(url).path
        queue.async { self.seen = self.seen.filter { !$0.hasPrefix(path + "|") } }
    }

    static func realURL(_ url: URL) -> URL {
        guard let resolved = realpath(url.path, nil) else { return url.standardizedFileURL }
        defer { free(resolved) }
        return URL(fileURLWithPath: String(cString: resolved), isDirectory: true)
    }

    // MARK: -

    private func received(_ paths: [String]) {
        let base = directory.path + "/"
        for path in paths where path.hasPrefix(base) {
            // 只看最上層:資料夾裡的變動歸到那個資料夾
            guard let top = path.dropFirst(base.count).split(separator: "/").first else { continue }
            schedule(String(top))
        }
    }

    static func shouldIgnore(_ name: String) -> Bool {
        if name.hasPrefix(".") || name.hasPrefix("Unconfirmed ") || name == "Icon\r" { return true }
        let ext = (name as NSString).pathExtension.lowercased()
        return temporaryExtensions.contains(ext)
    }

    private func schedule(_ name: String) {
        guard !Self.shouldIgnore(name), !pending.contains(name) else { return }
        pending.insert(name)
        let url = directory.appendingPathComponent(name)
        settle(url, name: name, last: snapshot(url), attempts: 0)
    }

    private func settle(_ url: URL, name: String, last: String?, attempts: Int) {
        queue.asyncAfter(deadline: .now() + settleDelay) { [weak self] in
            guard let self else { return }
            guard let now = self.snapshot(url) else { self.pending.remove(name); return }   // 被搬走了
            if now != last, attempts < 240 {   // 還在寫入(最多等約 10 分鐘)
                self.settle(url, name: name, last: now, attempts: attempts + 1)
                return
            }
            self.pending.remove(name)
            let key = url.path + "|" + now
            guard self.seen.insert(key).inserted else { return }
            DispatchQueue.main.async { self.onReady(url) }
        }
    }

    /// inode + 大小 + 修改時間;資料夾用裡面最新的修改時間與項目數
    private func snapshot(_ url: URL) -> String? {
        var st = stat()
        guard lstat(url.path, &st) == 0 else { return nil }
        if (st.st_mode & S_IFMT) == S_IFDIR {
            var newest = st.st_mtimespec.tv_sec, count = 0, bytes: Int64 = 0
            let e = FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey])
            while let f = e?.nextObject() as? URL, count < 20_000 {
                let v = try? f.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
                newest = max(newest, Int(v?.contentModificationDate?.timeIntervalSince1970 ?? 0))
                bytes += Int64(v?.fileSize ?? 0)
                count += 1
            }
            return "\(st.st_ino)|d\(count)|\(bytes)|\(newest)"
        }
        return "\(st.st_ino)|\(st.st_size)|\(st.st_mtimespec.tv_sec).\(st.st_mtimespec.tv_nsec)"
    }
}
