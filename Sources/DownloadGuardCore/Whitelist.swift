import Foundation

/// 白名單:命中就直接放行,不呼叫 Claude。
///
/// - 網域:下載網址或來源網頁的網域符合(含子網域)
/// - 開發者 Team ID:程式簽章有效、經過 Apple 公證,且 Team ID 在清單裡
///   (磁碟映像則是裡面每個 App 都符合,而且沒有夾帶腳本)
/// - SHA-256:完全相同的檔案
/// - 副檔名:只對「內容確實是文件或影音」的檔案生效;副檔名是 .jpg 但內容是程式的,不會放行
public struct Whitelist: Codable, Sendable, Equatable {
    public var domains: [String]
    public var teamIDs: [String]
    public var sha256: [String]
    public var extensions: [String]

    public init(domains: [String] = [], teamIDs: [String] = [], sha256: [String] = [], extensions: [String] = []) {
        self.domains = domains
        self.teamIDs = teamIDs
        self.sha256 = sha256
        self.extensions = extensions
    }

    public static let `default` = Whitelist(
        extensions: ["jpg", "jpeg", "png", "gif", "heic", "webp", "mp4", "mov", "mp3", "m4a", "wav"])

    /// 命中的規則說明;沒命中回傳 nil
    public func match(_ facts: FileFacts) -> String? {
        if let hash = facts.sha256?.lowercased(), sha256.contains(where: { $0.lowercased() == hash }) {
            return "SHA-256 \(hash.prefix(12))…"
        }

        if let team = trustedTeam(facts) { return "開發者 \(team)" }

        for host in [facts.downloadHost, facts.referrerHost].compactMap({ $0 }) {
            if let d = domains.first(where: { Self.host(host, matches: $0) }) {
                return "網域 \(d)(\(host))"
            }
        }

        let exts = Set(extensions.map { $0.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ". ")) })
        if exts.contains(facts.ext), !facts.disguised,
           facts.category == .media || facts.category == .document {
            return "副檔名 .\(facts.ext)"
        }
        return nil
    }

    func trustedTeam(_ facts: FileFacts) -> String? {
        let teams = Set(teamIDs.map { $0.uppercased() })
        guard !teams.isEmpty else { return nil }
        func ok(_ s: SignatureInfo?) -> String? {
            guard let s, s.status == .valid, s.gatekeeperAccepted == true,
                  let t = s.teamID?.uppercased(), teams.contains(t) else { return nil }
            return t
        }
        switch facts.category {
        case .executable, .appBundle, .installerPackage:
            return ok(facts.signature)
        case .diskImage, .folder:
            let nested = facts.nestedSignatures ?? [:]
            guard !nested.isEmpty, !LocalRules.signals(facts: facts, ioc: nil)
                    .contains(where: { $0.severity == .critical }) else { return nil }
            let found = nested.values.map(ok)
            guard found.allSatisfy({ $0 != nil }) else { return nil }
            return found.first ?? nil
        default:
            return nil
        }
    }

    public static func host(_ host: String, matches domain: String) -> Bool {
        let d = domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ". "))
        guard !d.isEmpty else { return false }
        return host == d || host.hasSuffix("." + d)
    }

    // MARK: - 修改

    public mutating func add(_ kind: WhitelistSuggestion.Kind, _ raw: String) {
        let value = Self.normalize(kind, raw)
        guard !value.isEmpty else { return }
        switch kind {
        case .domain: if !domains.contains(value) { domains.append(value) }
        case .teamID: if !teamIDs.contains(value) { teamIDs.append(value) }
        case .sha256: if !sha256.contains(value) { sha256.append(value) }
        }
    }

    public mutating func addExtension(_ raw: String) {
        let value = raw.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ". "))
        if !value.isEmpty, !extensions.contains(value) { extensions.append(value) }
    }

    static func normalize(_ kind: WhitelistSuggestion.Kind, _ raw: String) -> String {
        let v = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        switch kind {
        case .domain:
            // 接受貼上整個網址
            let host = URL(string: v)?.host ?? v
            return host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ". "))
        case .teamID: return v.uppercased()
        case .sha256: return v.lowercased()
        }
    }

    /// 掃描的 Claude 給的建議,必須和檔案的真實資料對得上才採用,
    /// 不然就是被檔案內容誤導(例如建議一個跟這次下載無關的網域)
    public static func isConsistent(_ s: WhitelistSuggestion, with facts: FileFacts) -> Bool {
        let value = normalize(s.kind, s.value)
        switch s.kind {
        case .sha256:
            return facts.sha256?.lowercased() == value
        case .domain:
            // 必須是下載網域或來源網頁網域本身(或其上層網域);只有頂級網域(例如 "com")不算
            guard value.contains(".") else { return false }
            return [facts.downloadHost, facts.referrerHost].compactMap { $0 }.contains { host($0, matches: value) }
        case .teamID:
            let sigs = [facts.signature].compactMap { $0 } + Array((facts.nestedSignatures ?? [:]).values)
            return sigs.contains { $0.status == .valid && $0.gatekeeperAccepted == true && $0.teamID?.uppercased() == value }
        }
    }

    // MARK: - 存檔

    public static func load(from url: URL) -> Whitelist {
        guard let data = try? Data(contentsOf: url),
              let list = try? JSONDecoder().decode(Whitelist.self, from: data) else { return .default }
        return list
    }

    public func save(to url: URL) throws {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try enc.encode(self).write(to: url, options: .atomic)
    }
}
