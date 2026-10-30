import AppKit
import Combine
import UserNotifications
import DownloadGuardCore

/// 下載掃描(小黑屋)。
///
/// 流程:任何資料夾裡出現新下載 → 關進 ~/小黑屋(記下原本的資料夾)→ 白名單?直接放行
///      → 否則背景 Claude Code 掃描 → 安全就送回原本的資料夾;可疑留在小黑屋等你決定;惡意移到隔離區。
@MainActor
public final class DownloadGuardController: NSObject, ObservableObject {
    public static let shared = DownloadGuardController()

    // MARK: 設定

    private enum Key {
        static let enabled = "downloadguard.enabled"
        static let model = "downloadguard.model"
        static let notifySafe = "downloadguard.notifySafe"
        static let autoQuarantine = "downloadguard.autoQuarantine"
        static let intercept = "downloadguard.interceptDownloads"
    }
    private let defaults = UserDefaults.standard

    @Published public var enabled: Bool {
        didSet { defaults.set(enabled, forKey: Key.enabled); enabled ? start() : stop() }
    }
    @Published public var model: String { didSet { defaults.set(model, forKey: Key.model) } }
    /// 安全放行時也通知(預設只在可疑 / 惡意時通知)
    @Published public var notifySafe: Bool { didSet { defaults.set(notifySafe, forKey: Key.notifySafe) } }
    /// 判定惡意時自動移到隔離區
    @Published public var autoQuarantine: Bool { didSet { defaults.set(autoQuarantine, forKey: Key.autoQuarantine) } }
    /// 家目錄任何資料夾裡出現新下載時自動關進小黑屋(瀏覽器存到哪裡都有效)
    @Published public var interceptDownloads: Bool { didSet { defaults.set(interceptDownloads, forKey: Key.intercept) } }

    public static let models: [(id: String, label: String)] = [
        ("claude-sonnet-5-5", "Sonnet 5.5(建議)"),
        ("claude-haiku-5-5", "Haiku 5.5(較快、較省)"),
        ("claude-opus-5-5", "Opus 5.5(最仔細)"),
    ]

    // MARK: 狀態

    @Published public private(set) var history: [ScanOutcome] = []
    @Published public private(set) var scanning: String?
    @Published public private(set) var queued: [URL] = []
    @Published public var whitelist: Whitelist = .default
    @Published public private(set) var lastMessage: String?

    private var holdingWatcher: DownloadWatcher?
    private var interceptor: DownloadInterceptor?

    private override init() {
        defaults.register(defaults: [Key.model: ScanRunner.defaultModel, Key.autoQuarantine: true,
                                     Key.intercept: true, Key.notifySafe: false])
        enabled = defaults.bool(forKey: Key.enabled)
        model = defaults.string(forKey: Key.model) ?? ScanRunner.defaultModel
        notifySafe = defaults.bool(forKey: Key.notifySafe)
        autoQuarantine = defaults.bool(forKey: Key.autoQuarantine)
        interceptDownloads = defaults.bool(forKey: Key.intercept)
        super.init()
        whitelist = Whitelist.load(from: GuardPaths.whitelist)
        history = Self.loadHistory()
    }

    /// App 啟動時呼叫:上次開著就恢復
    public func restore() {
        if enabled { start() }
    }

    func start() {
        guard holdingWatcher == nil else { return }
        let fm = FileManager.default
        for dir in [GuardPaths.holding, GuardPaths.quarantine, GuardPaths.scans] {
            try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        if !fm.fileExists(atPath: GuardPaths.whitelist.path) { try? whitelist.save(to: GuardPaths.whitelist) }
        setUpNotifications()

        let holding = DownloadWatcher(directory: GuardPaths.holding) { [weak self] url in self?.enqueue(url) }
        holding.start(includeExisting: true)   // App 沒開的時候進來的也要掃
        holdingWatcher = holding

        let interceptor = DownloadInterceptor(root: FileManager.default.homeDirectoryForCurrentUser,
                                              excluded: DownloadInterceptor.defaultExclusions()) { [weak self] url in
            self?.intercept(url)
        }
        interceptor.start()
        self.interceptor = interceptor
    }

    func stop() {
        holdingWatcher?.stop(); holdingWatcher = nil
        interceptor?.stop(); interceptor = nil
        queued.removeAll()
    }

    // MARK: - 小黑屋

    /// 剛下載完成的項目(DownloadInterceptor 已確認有下載標記、還沒放行過)→ 關進小黑屋
    private func intercept(_ url: URL) {
        guard interceptDownloads else { return }
        do {
            try HoldingPen.admit(url)
        } catch {
            lastMessage = "無法把 \(url.lastPathComponent) 移進小黑屋:\(error.localizedDescription)"
        }
    }

    private func enqueue(_ url: URL) {
        guard enabled, !queued.contains(url) else { return }
        queued.append(url)
        processNext()
    }

    private func processNext() {
        guard scanning == nil, !queued.isEmpty else { return }
        let url = queued.removeFirst()
        guard FileManager.default.fileExists(atPath: url.path) else { processNext(); return }
        guard let claude = ScanRunner.findClaude() else {
            lastMessage = "找不到 claude 指令,請先安裝 Claude Code 並登入。檔案先留在小黑屋。"
            notify(title: "下載掃描無法執行", body: lastMessage!, id: nil, category: nil)
            return
        }
        guard let helper = Self.helperPath() else {
            lastMessage = "找不到 liri-scan 輔助程式(請用 Scripts/build.sh 重新打包)"
            return
        }
        whitelist = Whitelist.load(from: GuardPaths.whitelist)   // 可能被 Claude Code 對話改過
        let runner = ScanRunner(claudePath: claude, helperPath: helper, model: model, whitelist: whitelist)
        scanning = url.lastPathComponent
        Task.detached(priority: .utility) {
            let outcome = runner.scan(url)
            await MainActor.run {
                self.scanning = nil
                self.finish(outcome)
                self.processNext()
            }
        }
    }

    private func finish(_ result: ScanOutcome) {
        var outcome = result
        let url = URL(fileURLWithPath: outcome.path)
        let stillHere = FileManager.default.fileExists(atPath: url.path)

        switch outcome.verdict {
        case .safe where stillHere:
            if let dest = try? HoldingPen.release(url) { outcome.path = dest.path }
            if notifySafe {
                let folder = URL(fileURLWithPath: outcome.path).deletingLastPathComponent().lastPathComponent
                notify(title: "已放行到「\(folder)」:\(outcome.name)", body: outcome.summary, id: outcome.id, category: nil)
            }
        case .malicious where stillHere && autoQuarantine:
            if let dest = try? HoldingPen.quarantine(url) { outcome.quarantinedPath = dest.path }
            notify(title: "⚠️ 已隔離惡意檔案:\(outcome.name)", body: outcome.summary,
                   id: outcome.id, category: Category.quarantined)
        default:
            let title = "\(outcome.verdict == .malicious ? "⚠️ " : "")\(outcome.verdict.label):\(outcome.name) 留在小黑屋"
            let category = outcome.claude?.suggestion != nil ? Category.reviewWithSuggestion : Category.review
            notify(title: title, body: outcome.summary, id: outcome.id, category: category)
        }
        record(outcome)
    }

    // MARK: - 使用者動作

    public func release(_ id: UUID) {
        guard var o = outcome(id) else { return }
        let src = o.quarantinedPath ?? o.path
        do {
            let dest = try HoldingPen.release(URL(fileURLWithPath: src))
            o.path = dest.path
            o.quarantinedPath = nil
            o.summary += "(你手動放行)"
            record(o)
        } catch {
            lastMessage = "放行失敗:\(error.localizedDescription)"
        }
    }

    public func quarantine(_ id: UUID) {
        guard var o = outcome(id) else { return }
        do {
            let dest = try HoldingPen.quarantine(URL(fileURLWithPath: o.path))
            o.quarantinedPath = dest.path
            record(o)
        } catch {
            lastMessage = "隔離失敗:\(error.localizedDescription)"
        }
    }

    public func rescan(_ id: UUID) {
        guard let o = outcome(id) else { return }
        let path = o.quarantinedPath ?? o.path
        enqueue(URL(fileURLWithPath: path))
    }

    /// 接受掃描的 Claude 提出的白名單建議,並放行這個檔案
    public func acceptSuggestion(_ id: UUID) {
        guard let o = outcome(id), let s = o.claude?.suggestion else { return }
        updateWhitelist { $0.add(s.kind, s.value) }
        if FileManager.default.fileExists(atPath: o.path), isInHolding(o.path) { release(id) }
    }

    public func trust(_ kind: WhitelistSuggestion.Kind, from id: UUID) {
        guard let o = outcome(id) else { return }
        let value: String?
        switch kind {
        case .domain: value = o.downloadURL.flatMap { URL(string: $0)?.host }
        case .teamID: value = o.teamID
        case .sha256: value = o.sha256
        }
        guard let value else { return }
        updateWhitelist { $0.add(kind, value) }
    }

    public func updateWhitelist(_ change: (inout Whitelist) -> Void) {
        var list = Whitelist.load(from: GuardPaths.whitelist)
        change(&list)
        do {
            try list.save(to: GuardPaths.whitelist)
            whitelist = list
        } catch {
            lastMessage = "白名單存檔失敗:\(error.localizedDescription)"
        }
    }

    public func reloadWhitelist() { whitelist = Whitelist.load(from: GuardPaths.whitelist) }

    public func isInHolding(_ path: String) -> Bool {
        URL(fileURLWithPath: path).deletingLastPathComponent().standardizedFileURL.path
            == GuardPaths.holding.standardizedFileURL.path
    }

    public func outcome(_ id: UUID) -> ScanOutcome? { history.first { $0.id == id } }

    public func reveal(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    /// 把白名單 MCP 註冊到你的 Claude Code(使用者範圍),之後在任何對話都能請 Claude 改白名單
    public func registerWhitelistMCP() {
        guard let claude = ScanRunner.findClaude(), let helper = Self.helperPath() else {
            lastMessage = "找不到 claude 或 liri-scan"
            return
        }
        let installed = "/Applications/LiriOS.app/Contents/MacOS/liri-scan"
        let path = FileManager.default.isExecutableFile(atPath: installed) ? installed : helper
        Task.detached {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: claude)
            p.arguments = ["mcp", "add", "--scope", "user", "liri-whitelist", "--", path, "whitelist-mcp"]
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = pipe
            try? p.run()
            p.waitUntilExit()
            let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            let ok = p.terminationStatus == 0 || out.contains("already exists")
            await MainActor.run {
                self.lastMessage = ok
                    ? "完成。在 Claude Code 裡說「把 xxx 加進下載白名單」就可以了(新開的對話才會載入)。"
                    : "註冊失敗:\(out.prefix(200))"
            }
        }
    }

    static func helperPath() -> String? {
        if let p = Bundle.main.url(forAuxiliaryExecutable: "liri-scan")?.path,
           FileManager.default.isExecutableFile(atPath: p) { return p }
        // swift run 開發時:和主程式在同一個資料夾
        let sibling = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("liri-scan").path
        return sibling.flatMap { FileManager.default.isExecutableFile(atPath: $0) ? $0 : nil }
    }

    // MARK: - 紀錄(JSON Lines;同一個 id 以最後一筆為準)

    private func record(_ outcome: ScanOutcome) {
        if let i = history.firstIndex(where: { $0.id == outcome.id }) {
            history[i] = outcome
        } else {
            history.insert(outcome, at: 0)
        }
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        guard var line = try? enc.encode(outcome) else { return }
        line.append(0x0A)
        let url = GuardPaths.history
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let h = try? FileHandle(forWritingTo: url) {
            h.seekToEndOfFile(); h.write(line); try? h.close()
        } else {
            try? line.write(to: url)
        }
    }

    static func loadHistory() -> [ScanOutcome] {
        guard let text = try? String(contentsOf: GuardPaths.history, encoding: .utf8) else { return [] }
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        var byID: [UUID: ScanOutcome] = [:]
        for line in text.split(separator: "\n") {
            if let o = try? dec.decode(ScanOutcome.self, from: Data(line.utf8)) { byID[o.id] = o }
        }
        return Array(byID.values.sorted { $0.date > $1.date }.prefix(300))
    }

    // MARK: - 通知

    enum Category {
        static let review = "downloadguard.review"
        static let reviewWithSuggestion = "downloadguard.review.suggest"
        static let quarantined = "downloadguard.quarantined"
    }

    enum Action {
        static let release = "release"
        static let quarantine = "quarantine"
        static let accept = "accept"
        static let restore = "restore"
        static let show = "show"
    }

    private var notificationsReady = false

    private func setUpNotifications() {
        // 系統通知只有在 .app 裡才能用(swift run 的執行檔沒有 bundle id,一呼叫就會閃退)
        guard !notificationsReady, Bundle.main.bundleIdentifier != nil else { return }
        notificationsReady = true
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let release = UNNotificationAction(identifier: Action.release, title: "放行")
        let quarantine = UNNotificationAction(identifier: Action.quarantine, title: "隔離", options: [.destructive])
        let accept = UNNotificationAction(identifier: Action.accept, title: "加入白名單並放行")
        let restore = UNNotificationAction(identifier: Action.restore, title: "還原到原本的資料夾")
        let show = UNNotificationAction(identifier: Action.show, title: "顯示紀錄", options: [.foreground])
        center.setNotificationCategories([
            UNNotificationCategory(identifier: Category.review, actions: [release, quarantine, show], intentIdentifiers: []),
            UNNotificationCategory(identifier: Category.reviewWithSuggestion, actions: [accept, release, quarantine, show],
                                   intentIdentifiers: []),
            UNNotificationCategory(identifier: Category.quarantined, actions: [restore, show], intentIdentifiers: []),
        ])
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    private func notify(title: String, body: String, id: UUID?, category: String?) {
        guard Bundle.main.bundleIdentifier != nil else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        if let category { content.categoryIdentifier = category; content.sound = .default }
        if let id { content.userInfo = ["id": id.uuidString] }
        UNUserNotificationCenter.current().add(
            UNNotificationRequest(identifier: id?.uuidString ?? UUID().uuidString, content: content, trigger: nil))
    }
}

extension DownloadGuardController: UNUserNotificationCenterDelegate {
    // LiriOS 在前景時也要顯示橫幅
    public nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                                   willPresent notification: UNNotification,
                                                   withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }

    public nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                                   didReceive response: UNNotificationResponse,
                                                   withCompletionHandler completionHandler: @escaping () -> Void) {
        let action = response.actionIdentifier
        let idString = response.notification.request.content.userInfo["id"] as? String
        DispatchQueue.main.async {
            MainActor.assumeIsolated {
                let id = idString.flatMap(UUID.init(uuidString:))
                switch action {
                case Action.release, Action.restore: if let id { self.release(id) }
                case Action.quarantine: if let id { self.quarantine(id) }
                case Action.accept: if let id { self.acceptSuggestion(id) }
                default: DownloadGuardWindowController.shared.show()
                }
            }
            completionHandler()
        }
    }
}
