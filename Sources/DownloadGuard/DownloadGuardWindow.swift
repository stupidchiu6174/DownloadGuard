import AppKit
import SwiftUI
import DownloadGuardCore

/// 「下載掃描」視窗:掃描紀錄、白名單、設定
@MainActor
public final class DownloadGuardWindowController {
    public static let shared = DownloadGuardWindowController()
    private var window: NSWindow?

    public func show() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 760, height: 560),
                             styleMask: [.titled, .closable, .miniaturizable, .resizable],
                             backing: .buffered, defer: false)
            w.title = "下載掃描"
            w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: DownloadGuardView(model: .shared))
            w.center()
            window = w
        }
        DownloadGuardController.shared.reloadWhitelist()
        // LiriOS 平常是背景 App:先切成一般 App,下一拍再把視窗叫到最前面,不然會開在別的 App 後面
        NSApp.setActivationPolicy(.regular)
        DispatchQueue.main.async { [window] in
            NSApp.activate()
            window?.makeKeyAndOrderFront(nil)
            window?.orderFrontRegardless()
        }
    }
}

struct DownloadGuardView: View {
    @ObservedObject var model: DownloadGuardController

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            statusBar
            Divider()
            TabView {
                HistoryList(model: model).tabItem { Text("掃描紀錄") }
                WhitelistEditor(model: model).tabItem { Text("白名單") }
                SettingsPane(model: model).tabItem { Text("設定") }
            }
            .padding(12)
        }
        .frame(minWidth: 640, minHeight: 440)
    }

    private var statusBar: some View {
        HStack(spacing: 10) {
            Toggle("下載掃描", isOn: $model.enabled).toggleStyle(.switch)
            if let name = model.scanning {
                ProgressView().controlSize(.small)
                Text("正在掃描 \(name)…").foregroundStyle(.secondary)
                if !model.queued.isEmpty { Text("(還有 \(model.queued.count) 個排隊)").foregroundStyle(.secondary) }
            } else if model.enabled {
                Text("待命中").foregroundStyle(.secondary)
            }
            Spacer()
            Button("打開小黑屋") { NSWorkspace.shared.open(GuardPaths.holding) }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .overlay(alignment: .bottomLeading) {
            if let msg = model.lastMessage {
                Text(msg).font(.caption).foregroundStyle(.orange).padding(.horizontal, 14).offset(y: 14)
            }
        }
    }
}

// MARK: - 掃描紀錄

struct HistoryList: View {
    @ObservedObject var model: DownloadGuardController

    var body: some View {
        if model.history.isEmpty {
            VStack(spacing: 8) {
                Text("還沒有掃描紀錄").font(.headline)
                Text("下載的檔案會先進「小黑屋」,掃描通過才放行到「下載項目」。")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            List(model.history) { o in HistoryRow(model: model, outcome: o) }
        }
    }
}

struct HistoryRow: View {
    @ObservedObject var model: DownloadGuardController
    let outcome: ScanOutcome

    private var color: Color {
        switch outcome.verdict {
        case .safe: return .green
        case .unknown: return .gray
        case .suspicious: return .orange
        case .malicious: return .red
        }
    }

    private var location: String {
        if let q = outcome.quarantinedPath, FileManager.default.fileExists(atPath: q) { return "隔離區" }
        if !FileManager.default.fileExists(atPath: outcome.path) { return "已移走" }
        return model.isInHolding(outcome.path) ? "小黑屋" : "已放行"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle().fill(color).frame(width: 9, height: 9)
                Text(outcome.name).font(.body.weight(.medium)).lineLimit(1)
                Text(outcome.verdict.label).font(.caption).foregroundStyle(color)
                Text(location).font(.caption)
                    .padding(.horizontal, 6).padding(.vertical, 1)
                    .background(.quaternary, in: Capsule())
                Spacer()
                Text(outcome.date, style: .relative).font(.caption).foregroundStyle(.secondary)
            }
            Text(outcome.summary).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let reasons = outcome.claude?.reasons, !reasons.isEmpty, outcome.verdict != .safe {
                ForEach(reasons.prefix(4), id: \.self) { Text("・\($0)").font(.caption).foregroundStyle(.secondary) }
            }
            if let s = outcome.claude?.suggestion {
                Text("Claude 建議加入白名單:\(s.label)\(s.reason.map { "——\($0)" } ?? "")")
                    .font(.caption).foregroundStyle(.blue)
            }
            HStack(spacing: 8) {
                switch location {
                case "小黑屋":
                    Button("放行") { model.release(outcome.id) }
                    Button("隔離") { model.quarantine(outcome.id) }
                    Button("重新掃描") { model.rescan(outcome.id) }
                case "隔離區":
                    Button("還原到下載項目") { model.release(outcome.id) }
                default:
                    EmptyView()
                }
                if outcome.claude?.suggestion != nil {
                    Button("接受白名單建議") { model.acceptSuggestion(outcome.id) }
                }
                Menu("信任…") {
                    if let host = outcome.downloadURL.flatMap({ URL(string: $0)?.host }) {
                        Button("信任網域 \(host)") { model.trust(.domain, from: outcome.id) }
                    }
                    if let team = outcome.teamID { Button("信任開發者 \(team)") { model.trust(.teamID, from: outcome.id) } }
                    if outcome.sha256 != nil { Button("信任這個檔案(SHA-256)") { model.trust(.sha256, from: outcome.id) } }
                }
                .fixedSize()
                if location != "已移走" {
                    Button("在檔案管理中顯示") {
                        model.reveal(location == "隔離區" ? outcome.quarantinedPath! : outcome.path)
                    }
                }
                Spacer()
                if let cost = outcome.costUSD {
                    Text(String(format: "$%.3f・%.0f 秒", cost, outcome.durationSeconds))
                        .font(.caption2).foregroundStyle(.tertiary)
                }
            }
            .controlSize(.small)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - 白名單

struct WhitelistEditor: View {
    @ObservedObject var model: DownloadGuardController

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("命中白名單的下載不經過 Claude,直接從小黑屋放行。")
                    .foregroundStyle(.secondary)
                RuleSection(title: "網域", hint: "例如 apple.com(含子網域;比對下載網址與來源網頁)",
                            items: model.whitelist.domains,
                            add: { v in model.updateWhitelist { $0.add(.domain, v) } },
                            remove: { v in model.updateWhitelist { $0.domains.removeAll { $0 == v } } })
                RuleSection(title: "開發者 Team ID", hint: "簽章有效且經過 Apple 公證的軟體才會比對",
                            items: model.whitelist.teamIDs,
                            add: { v in model.updateWhitelist { $0.add(.teamID, v) } },
                            remove: { v in model.updateWhitelist { $0.teamIDs.removeAll { $0 == v } } })
                RuleSection(title: "副檔名", hint: "只對內容確實是文件或影音的檔案生效",
                            items: model.whitelist.extensions,
                            add: { v in model.updateWhitelist { $0.addExtension(v) } },
                            remove: { v in model.updateWhitelist { $0.extensions.removeAll { $0 == v } } })
                RuleSection(title: "SHA-256", hint: "完全相同的檔案",
                            items: model.whitelist.sha256,
                            add: { v in model.updateWhitelist { $0.add(.sha256, v) } },
                            remove: { v in model.updateWhitelist { $0.sha256.removeAll { $0 == v } } })
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
        }
    }
}

struct RuleSection: View {
    let title: String
    let hint: String
    let items: [String]
    let add: (String) -> Void
    let remove: (String) -> Void
    @State private var draft = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            Text(hint).font(.caption).foregroundStyle(.secondary)
            ForEach(items, id: \.self) { item in
                HStack {
                    Text(item).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    Spacer()
                    Button(role: .destructive) { remove(item) } label: { Image(systemName: "minus.circle") }
                        .buttonStyle(.borderless)
                }
            }
            HStack {
                TextField("新增…", text: $draft).onSubmit(commit)
                Button("加入", action: commit).disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    private func commit() {
        let v = draft.trimmingCharacters(in: .whitespaces)
        guard !v.isEmpty else { return }
        add(v)
        draft = ""
    }
}

// MARK: - 設定

struct SettingsPane: View {
    @ObservedObject var model: DownloadGuardController

    var body: some View {
        Form {
            Picker("掃描模型", selection: $model.model) {
                ForEach(DownloadGuardController.models, id: \.id) { Text($0.label).tag($0.id) }
            }
            Toggle("「下載項目」裡的新下載自動關進小黑屋", isOn: $model.interceptDownloads)
            Text("也可以直接把瀏覽器的下載位置設成 ~/小黑屋。只有帶 macOS 下載標記的檔案會被攔下(瀏覽器、AirDrop、郵件附件);用 curl 等指令下載的不會。")
                .font(.caption).foregroundStyle(.secondary)
            Toggle("判定為惡意時自動移到隔離區", isOn: $model.autoQuarantine)
            Toggle("安全放行時也通知", isOn: $model.notifySafe)
            Section("讓 Claude Code 管理白名單") {
                Text("註冊後,你在 Claude Code 對話裡說「把 github.com 加進下載白名單」,Claude 就能直接修改。背景掃描的 Claude 只能提出建議,要你按一下才會生效。")
                    .font(.caption).foregroundStyle(.secondary)
                Button("註冊到 Claude Code") { model.registerWhitelistMCP() }
            }
            Section("資料夾") {
                Button("打開隔離區") { NSWorkspace.shared.open(GuardPaths.quarantine) }
                Button("打開設定資料夾") { NSWorkspace.shared.open(GuardPaths.support) }
            }
        }
        .formStyle(.grouped)
    }
}
