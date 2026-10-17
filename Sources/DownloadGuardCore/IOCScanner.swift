import Foundation

/// 從檔案裡抽出可印字串,找已知的惡意程式手法(以 macOS 竊密程式 AMOS 一類為主)。
/// 這是給 Claude 的線索,也是 Claude 判斷之外的保險:Claude 說安全但這裡抓到嚴重警訊時,
/// 最終判定至少是「可疑」(檔案內容可能企圖用文字影響 Claude 的判斷)。
public enum IOCScanner {

    public struct Pattern: Sendable {
        let needle: String
        let severity: Signal.Severity
        let meaning: String
    }

    /// 不分大小寫比對
    public static let patterns: [Pattern] = [
        .init(needle: "with administrator privileges", severity: .critical, meaning: "用 AppleScript 要求管理員密碼"),
        .init(needle: "dscl . -authonly", severity: .critical, meaning: "驗證使用者密碼(竊密程式常用來確認騙到的密碼)"),
        .init(needle: "dscl . authonly", severity: .critical, meaning: "驗證使用者密碼(竊密程式常用來確認騙到的密碼)"),
        .init(needle: "security find-generic-password", severity: .critical, meaning: "讀取鑰匙圈密碼"),
        .init(needle: "security dump-keychain", severity: .critical, meaning: "匯出鑰匙圈"),
        .init(needle: "xattr -d com.apple.quarantine", severity: .critical, meaning: "移除下載隔離標記以繞過 Gatekeeper"),
        .init(needle: "xattr -c", severity: .warning, meaning: "清除延伸屬性(可能用來繞過 Gatekeeper)"),
        .init(needle: "xattr -cr", severity: .critical, meaning: "遞迴清除隔離標記以繞過 Gatekeeper"),
        .init(needle: "spctl --master-disable", severity: .critical, meaning: "關閉 Gatekeeper"),
        .init(needle: "spctl --global-disable", severity: .critical, meaning: "關閉 Gatekeeper"),
        .init(needle: "/Library/LaunchDaemons/", severity: .warning, meaning: "寫入開機常駐服務"),
        .init(needle: "Library/LaunchAgents", severity: .warning, meaning: "寫入登入常駐項目"),
        .init(needle: "killall Terminal", severity: .critical, meaning: "關閉終端機以隱藏痕跡(AMOS 手法)"),
        .init(needle: "do shell script", severity: .warning, meaning: "AppleScript 執行殼層指令"),
        .init(needle: "osascript", severity: .warning, meaning: "執行 AppleScript"),
        .init(needle: "base64 -d", severity: .warning, meaning: "解碼隱藏的內容"),
        .init(needle: "base64 --decode", severity: .warning, meaning: "解碼隱藏的內容"),
        .init(needle: "| bash", severity: .warning, meaning: "下載內容直接交給殼層執行"),
        .init(needle: "| sh", severity: .warning, meaning: "下載內容直接交給殼層執行"),
        .init(needle: "| zsh", severity: .warning, meaning: "下載內容直接交給殼層執行"),
        .init(needle: "curl -", severity: .info, meaning: "用 curl 連網"),
        .init(needle: "chmod +x", severity: .info, meaning: "把檔案設成可執行"),
        .init(needle: "/tmp/", severity: .info, meaning: "使用暫存資料夾"),
        .init(needle: "ditto -c", severity: .warning, meaning: "把檔案打包(竊密程式常用來打包要外傳的資料)"),
        .init(needle: "Login Data", severity: .warning, meaning: "瀏覽器存的密碼資料庫"),
        .init(needle: "Cookies.binarycookies", severity: .warning, meaning: "Safari cookie"),
        .init(needle: "login.keychain", severity: .critical, meaning: "鑰匙圈檔案"),
        .init(needle: "nkbihfbeogaeaoehlefnkodbefgpgknn", severity: .critical, meaning: "MetaMask 錢包擴充功能 ID"),
        .init(needle: "Exodus/exodus.wallet", severity: .critical, meaning: "Exodus 錢包資料"),
        .init(needle: "Electrum/wallets", severity: .critical, meaning: "Electrum 錢包資料"),
        .init(needle: "Telegram Desktop/tdata", severity: .critical, meaning: "Telegram 登入資料"),
        .init(needle: "Application Support/Binance", severity: .critical, meaning: "幣安資料"),
        .init(needle: "/.pass", severity: .critical, meaning: "存放騙到的密碼(AMOS 後門手法)"),
        .init(needle: "com.finder.helper", severity: .critical, meaning: "AMOS 後門的常駐服務名稱"),
        .init(needle: "System Preferences needs your password", severity: .critical, meaning: "假的系統密碼視窗"),
        .init(needle: "needs your password to continue", severity: .critical, meaning: "假的密碼視窗文字"),
    ]

    public struct Report: Codable, Sendable {
        public var hits: [String: String]           // needle → 意義
        public var signals: [Signal]
        public var urls: [String]
        public var ips: [String]
        public var bytesScanned: Int
    }

    static let maxBytes = 16 << 20

    public static func scan(data: Data) -> Report {
        let strings = printableStrings(data)
        let lower = strings.lowercased()
        var hits: [String: String] = [:]
        var signals: [Signal] = []
        for p in patterns where lower.contains(p.needle.lowercased()) {
            if hits[p.needle] == nil {
                hits[p.needle] = p.meaning
                signals.append(Signal(severity: p.severity, message: "\(p.meaning)(字串「\(p.needle)」)"))
            }
        }
        return Report(hits: hits, signals: signals, urls: matches(urlRegex, in: strings, limit: 60),
                      ips: matches(ipRegex, in: strings, limit: 40).filter(isInterestingIP),
                      bytesScanned: data.count)
    }

    /// 掃一個路徑:一般檔案直接讀;.app 掃主程式和 Resources 裡的腳本;資料夾掃前幾個可執行內容。
    public static func scan(path: String, facts: FileFacts) -> Report {
        var data = Data()
        for file in filesToScan(path: path, facts: facts) {
            guard let h = FileHandle(forReadingAtPath: file) else { continue }
            let chunk = (try? h.read(upToCount: maxBytes - data.count)) ?? Data()
            try? h.close()
            data.append(chunk)
            data.append(0x0A)
            if data.count >= maxBytes { break }
        }
        return scan(data: data)
    }

    static func filesToScan(path: String, facts: FileFacts) -> [String] {
        switch facts.category {
        case .appBundle:
            var out: [String] = []
            let macos = URL(fileURLWithPath: path).appendingPathComponent("Contents/MacOS")
            if let items = try? FileManager.default.contentsOfDirectory(atPath: macos.path) {
                out += items.prefix(4).map { macos.appendingPathComponent($0).path }
            }
            let res = URL(fileURLWithPath: path).appendingPathComponent("Contents/Resources")
            if let items = try? FileManager.default.contentsOfDirectory(atPath: res.path) {
                out += items.filter { ["sh", "scpt", "command", "py", "applescript"].contains(($0 as NSString).pathExtension) }
                    .prefix(6).map { res.appendingPathComponent($0).path }
            }
            return out
        case .folder:
            return (facts.contents ?? []).filter {
                let ext = ($0 as NSString).pathExtension.lowercased()
                return FileInspector.scriptExts.contains(ext) || ext.isEmpty
            }.prefix(8).map { URL(fileURLWithPath: path).appendingPathComponent($0).path }
        default:
            return [path]
        }
    }

    /// 長度 ≥ 5 的 ASCII 可印字元片段(和 strings(1) 同一個意思),另外保留 UTF-8 中文
    static func printableStrings(_ data: Data) -> String {
        var out = [UInt8]()
        out.reserveCapacity(min(data.count, 4 << 20))
        var run = [UInt8]()
        func flush() {
            if run.count >= 5 { out.append(contentsOf: run); out.append(0x0A) }
            run.removeAll(keepingCapacity: true)
        }
        for b in data {
            if (b >= 0x20 && b < 0x7F) || b == 0x09 || b >= 0x80 { run.append(b) } else { flush() }
        }
        flush()
        return String(decoding: out, as: UTF8.self)
    }

    static let urlRegex = try! NSRegularExpression(pattern: #"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}"#)
    static let ipRegex = try! NSRegularExpression(pattern: #"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"#)

    static func matches(_ re: NSRegularExpression, in text: String, limit: Int) -> [String] {
        var seen = Set<String>(), out: [String] = []
        let ns = text as NSString
        for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let s = ns.substring(with: m.range)
            if seen.insert(s).inserted { out.append(s) }
            if out.count >= limit { break }
        }
        return out
    }

    /// 排除本機位址與看起來像版本號的組合
    static func isInterestingIP(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return false }
        if parts[0] == 0 || parts[0] == 127 || parts[0] == 10 || parts[0] == 255 { return false }
        if parts[0] == 192 && parts[1] == 168 { return false }
        if parts.allSatisfy({ $0 < 10 }) { return false }   // 1.2.3.4 這類版本號
        return true
    }
}
