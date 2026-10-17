import Foundation

/// 不靠 Claude 的固定規則。只會把判定拉高到「可疑」,永遠不會單獨判「惡意」
/// (誤判成惡意會把正常檔案丟進隔離區,這個決定留給 Claude 加上證據)。
public enum LocalRules {

    public static func signals(facts: FileFacts, ioc: IOCScanner.Report?) -> [Signal] {
        var out: [Signal] = []

        if facts.disguised {
            out.append(.init(severity: .critical,
                             message: "副檔名是 .\(facts.ext),內容卻是\(facts.category == .script ? "腳本" : "執行檔")"))
        }

        if let sig = facts.signature, facts.category == .executable || facts.category == .appBundle {
            switch sig.status {
            case .unsigned: out.append(.init(severity: .warning, message: "程式沒有簽章"))
            case .adhoc: out.append(.init(severity: .warning, message: "程式只有臨時簽章(ad-hoc),無法追溯開發者"))
            case .invalid: out.append(.init(severity: .critical, message: "程式簽章無效(可能被竄改)"))
            case .valid:
                if sig.gatekeeperAccepted == false {
                    out.append(.init(severity: .warning, message: "程式沒有經過 Apple 公證,Gatekeeper 不接受"))
                }
            }
        }

        if facts.category == .installerPackage, let sig = facts.signature, sig.status != .valid {
            out.append(.init(severity: .warning, message: "安裝檔沒有有效簽章"))
        }

        // 磁碟映像 / 資料夾 / 壓縮檔裡的內容
        let listing = facts.contents ?? []
        let runnable = listing.filter {
            let ext = ($0 as NSString).pathExtension.lowercased()
            return ["command", "tool", "sh", "terminal", "scpt", "applescript"].contains(ext)
        }
        if !runnable.isEmpty, facts.category == .diskImage || facts.category == .archive || facts.category == .folder {
            out.append(.init(severity: .critical,
                             message: "裡面有可以直接執行的腳本:\(runnable.prefix(3).joined(separator: "、"))"))
        }
        for (path, sig) in facts.nestedSignatures ?? [:] {
            if sig.status != .valid {
                out.append(.init(severity: .warning, message: "裡面的 \(path) 沒有有效簽章"))
            } else if sig.gatekeeperAccepted == false {
                out.append(.init(severity: .warning, message: "裡面的 \(path) 沒有經過 Apple 公證"))
            }
        }

        if let ioc, facts.category.canRunCode || facts.disguised {
            out += ioc.signals
        }
        return out
    }

    /// 本機規則的結論:有嚴重警訊,或可執行內容上累積兩個以上警告 → 可疑
    public static func verdict(for signals: [Signal]) -> Verdict {
        if signals.contains(where: { $0.severity == .critical }) { return .suspicious }
        if signals.filter({ $0.severity == .warning }).count >= 2 { return .suspicious }
        return .safe
    }
}
